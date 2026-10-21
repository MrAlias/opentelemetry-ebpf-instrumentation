// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

// SessionManager owns one asynchronous EventPipe reader per discovered process.
type SessionManager struct {
	HTTPTraces *msg.Queue[[]request.Span]

	ctx      context.Context
	interval time.Duration
	timeout  time.Duration
	queue    *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot]
	mu       sync.Mutex
	targets  map[app.PID]*collection
	closed   bool
	workers  sync.WaitGroup
}

type collection struct {
	startTime uint64
	cancel    context.CancelFunc
	done      chan struct{}
}

func NewSessionManager(ctx context.Context, interval, timeout time.Duration, queue *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot]) *SessionManager {
	return &SessionManager{ctx: ctx, interval: interval, timeout: timeout, queue: queue, targets: make(map[app.PID]*collection)}
}

// Start captures the discovered process before scheduling attachment. Repeated
// notifications for the same incarnation share one session.
func (c *SessionManager) Start(file *exec.FileInfo) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil {
		return nil
	}
	if c.interval <= 0 || c.timeout <= 0 || (c.queue == nil && c.HTTPTraces == nil) {
		return errors.New(".NET session manager requires a positive sampling interval, timeout, and an output queue")
	}
	pid, startTime := file.Pid(), file.StartTime()
	previous := c.targets[pid]
	if previous != nil && previous.startTime == startTime {
		return nil
	}
	process, err := procs.OpenProcessHandle(pid, startTime)
	if err != nil {
		return err
	}
	if previous != nil {
		previous.cancel()
	}
	if file.RuntimeMetricGeneration(pid) == 0 {
		file.SetRuntimeMetricGeneration(pid, ebpfcommon.NewRuntimeMetricGeneration())
	}
	ctx, cancel := context.WithCancel(c.ctx)
	target := &collection{startTime: startTime, cancel: cancel, done: make(chan struct{})}
	c.targets[pid] = target
	c.workers.Go(func() {
		defer close(target.done)
		defer func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.targets[pid] == target {
				delete(c.targets, pid)
			}
		}()
		defer process.Close()
		defer cancel()
		if previous != nil {
			select {
			case <-previous.done:
			case <-ctx.Done():
				return
			}
		}
		c.run(ctx, process, file)
	})
	return nil
}

// Remove cancels only the process incarnation named by the discovery event.
func (c *SessionManager) Remove(file *exec.FileInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if target := c.targets[file.Pid()]; target != nil && target.startTime == file.StartTime() {
		target.cancel()
	}
}

// Close cancels attachment and readers, then waits for bounded session cleanup.
func (c *SessionManager) Close() {
	c.mu.Lock()
	c.closed = true
	for _, target := range c.targets {
		target.cancel()
	}
	c.mu.Unlock()
	c.workers.Wait()
}

// run retries transient attachment failures while the pinned process is alive.
// Reconnected sessions keep the last published totals as their new baseline.
func (c *SessionManager) run(ctx context.Context, process *procs.ProcessHandle, file *exec.FileInfo) {
	log := slog.With("component", "dotnet.SessionManager", "pid", process.PID())
	service := file.ServiceAttrs()
	collectMetrics := c.queue != nil && (c.HTTPTraces == nil || service.Features.AppRuntime())
	collectHTTP := c.HTTPTraces != nil && service.ExportModes.CanExportTraces()
	if !collectMetrics && !collectHTTP {
		return
	}
	var totals [runtimemetrics.DotnetGCGenerationCount]uint64
	var cumulativeTotals cumulativeSessionTotals
	warned := false
	var httpReadyFrom int64
	generation := file.RuntimeMetricGeneration(process.PID())
	defer func() {
		if !collectMetrics {
			return
		}
		c.queue.SendCtx(c.ctx, []runtimemetrics.RuntimeMetricSnapshot{{
			Service: file.ServiceAttrs(), PID: process.PID(), Generation: generation,
			Time: time.Now(), Removed: true, Dotnet: &runtimemetrics.DotnetRuntimeMetricSnapshot{},
		}})
	}()
	for ctx.Err() == nil {
		if err := process.Alive(); err != nil {
			if !errors.Is(err, unix.ESRCH) {
				log.Warn("unable to check .NET process liveness", "error", err)
			}
			return
		}
		setupCtx, cancel := context.WithTimeout(ctx, c.timeout)
		target, err := resolveDiagnosticTarget(setupCtx, process, file.ServiceAttrs().EnvVars["TMPDIR"])
		var session *eventPipeSession
		if err == nil {
			var providers []eventPipeProvider
			if collectMetrics {
				interval := strconv.FormatFloat(c.interval.Seconds(), 'f', -1, 64)
				providers = append(providers, eventPipeProvider{
					name: "System.Runtime", arguments: "EventCounterIntervalSec=" + interval,
					keywords: systemRuntimeKeywords, level: eventLevelInformational,
				})
			}
			if collectHTTP {
				providers = append(providers, httpActivityProvider())
			}
			var startRequest []byte
			startRequest, err = encodeEventPipeProviders(providers)
			if err == nil {
				session, err = startEventPipeRequest(setupCtx, target.socketPath, startRequest)
			}
		}
		cancel()
		if err == nil {
			log.Debug("started EventPipe GC collection", "session", session.id)
			base := totals
			cumulativeBase := cumulativeTotals
			err = c.readSessionEvents(ctx, session, target.info.PID, func(publishCtx context.Context, snapshot *runtimemetrics.DotnetRuntimeMetricSnapshot) error {
				if !collectMetrics {
					return nil
				}
				for gcGeneration, count := range snapshot.GCCollections {
					if *count > math.MaxInt64-base[gcGeneration] {
						return errors.New(".NET GC collections exceed exporter integer range")
					}
					*count += base[gcGeneration]
				}
				if err := cumulativeTotals.merge(cumulativeBase, snapshot); err != nil {
					return err
				}
				for gcGeneration, count := range snapshot.GCCollections {
					totals[gcGeneration] = *count
				}
				// CPU totals are sampled at publication time, independently of EventPipe intervals.
				user, system, cpuErr := readProcessCPUTimes(process)
				if cpuErr != nil {
					log.Debug("unable to read .NET process CPU times", "error", cpuErr)
				} else {
					snapshot.ProcessCPUTimeUser = &user
					snapshot.ProcessCPUTimeSystem = &system
				}
				c.queue.SendCtx(publishCtx, []runtimemetrics.RuntimeMetricSnapshot{{
					Service: file.ServiceAttrs(), PID: process.PID(), Generation: generation,
					Time: time.Now(), Dotnet: snapshot,
				}})
				return nil
			}, func(publishCtx context.Context, info netTraceInfo, event netTraceEvent) error {
				if !collectHTTP {
					return nil
				}
				if event.Metadata.ProviderName == diagnosticSourceProviderName && event.Metadata.EventName == "NewDiagnosticListener" {
					if name := event.Values["SourceName"]; name == "Microsoft.AspNetCore" || name == "HttpHandlerDiagnosticListener" {
						now := int64(timing.MonoTimeNow())
						if httpReadyFrom == 0 {
							httpReadyFrom = now
							log.Info("started .NET HTTP Activity collection")
						}
					}
				}
				span, err := decodeHTTPActivity(info, event)
				if err != nil {
					log.Warn("unable to decode .NET HTTP Activity", "error", err)
					return nil
				}
				if span == nil || httpReadyFrom == 0 || span.Start < httpReadyFrom {
					return nil
				}
				if span.Type == request.EventTypeHTTP {
					if event.Values["EventName"] != "Microsoft.AspNetCore.Hosting.HttpRequestIn.Start" {
						return nil
					}
					span.Start = event.Header.Timestamp
					span.RequestStart = span.Start
					span.End = span.Start
				}
				span.Service = file.ServiceAttrs()
				span.Pid = request.PidInfo{HostPID: file.Pid(), UserPID: app.PID(target.info.PID), Namespace: file.Ns()}
				request.SetIgnoreMetrics(span)
				span.DotnetHTTPContext = true
				c.HTTPTraces.SendCtx(publishCtx, []request.Span{*span})
				return nil
			})
		}
		if target.directory != nil {
			_ = target.directory.Close()
		}
		if errors.Is(err, errUnsupportedRuntime) {
			log.Warn("skipping unsupported .NET runtime metrics", "error", err)
			return
		}
		if err != nil && ctx.Err() == nil {
			if !warned {
				log.Warn(".NET GC collection interrupted", "error", err)
				warned = true
			} else {
				log.Debug(".NET GC collection interrupted", "error", err)
			}
		}
		timer := time.NewTimer(c.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// readSession drains concurrently with StopTracing. A deadline bounds both
// control IPC and the final stream drain when the process stops responding.
func (c *SessionManager) readSession(ctx context.Context, session *eventPipeSession, pid uint64, publish func(context.Context, *runtimemetrics.DotnetRuntimeMetricSnapshot) error) error {
	return c.readSessionEvents(ctx, session, pid, publish, nil)
}

func (c *SessionManager) readSessionEvents(ctx context.Context, session *eventPipeSession, pid uint64, publish func(context.Context, *runtimemetrics.DotnetRuntimeMetricSnapshot) error, consume func(context.Context, netTraceInfo, netTraceEvent) error) error {
	defer session.stream.Close()
	publishCtx, cancelPublish := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelPublish()
	done := make(chan error, 1)
	go func() {
		var collection runtimeCollection
		err := readNetTraceEvents(session.stream, pid, func(info netTraceInfo, event netTraceEvent) error {
			if consume != nil {
				if err := consume(publishCtx, info, event); err != nil {
					return err
				}
			}
			counter, err := runtimeCounterFromEvent(event)
			if err != nil || counter.Name == "" {
				return err
			}
			snapshot, err := collection.observe(counter)
			if err != nil || snapshot == nil {
				return err
			}
			return publish(publishCtx, snapshot)
		})
		if err == nil {
			if snapshot := collection.finish(); snapshot != nil {
				err = publish(publishCtx, snapshot)
			}
		}
		done <- err
	}()
	var readErr error
	readFinished := false
	select {
	case readErr = <-done:
		readFinished = true
	case <-ctx.Done():
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.timeout)
	defer cancel()
	// Queue delivery and stream draining share the same cleanup deadline.
	stopPublishCancellation := context.AfterFunc(cleanupCtx, cancelPublish)
	defer stopPublishCancellation()
	deadline, _ := cleanupCtx.Deadline()
	_ = session.stream.SetReadDeadline(deadline)
	stopErr := stopEventPipe(cleanupCtx, session)
	if !readFinished {
		readErr = <-done
	}
	if ctx.Err() != nil {
		if err := errors.Join(readErr, stopErr); err != nil {
			slog.Debug(".NET EventPipe session ended during cancellation",
				"session", session.id, "error", err)
		}
		return ctx.Err()
	}
	if stopErr != nil {
		return errors.Join(readErr, fmt.Errorf("stopping EventPipe: %w", stopErr))
	}
	return readErr
}
