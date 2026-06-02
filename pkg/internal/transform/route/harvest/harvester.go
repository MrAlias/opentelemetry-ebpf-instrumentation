// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
)

type RouteHarvester struct {
	log      *slog.Logger
	java     *JavaRoutes
	disabled map[svc.InstrumentableType]struct{}
	cfg      *services.RouteHarvestingConfig
	timeout  time.Duration
	mux      *sync.Mutex

	// Limits blocked Java extraction to one in-flight goroutine when attach cannot be canceled.
	javaHarvestSemaphore chan struct{}

	// testing related
	javaExtractRoutes func(pid app.PID) (*RouteHarvesterResult, error)
	nodeExtractRoutes func(pid app.PID) (*RouteHarvesterResult, error)
}

type routeHarvestResult struct {
	r   *RouteHarvesterResult
	err error
}

type RouteHarvesterResultKind uint8

const (
	CompleteRoutes RouteHarvesterResultKind = iota + 1
	PartialRoutes
)

type RouteHarvesterResult struct {
	Routes []string
	Kind   RouteHarvesterResultKind
}

// HarvestError represents an error that occurred during route harvesting
type HarvestError struct {
	Message string
}

func (e *HarvestError) Error() string {
	return e.Message
}

func NewRouteHarvester(cfg *services.RouteHarvestingConfig, disabled []services.RouteHarvesterLanguage, timeout time.Duration) *RouteHarvester {
	dMap := map[svc.InstrumentableType]struct{}{}
	for _, lang := range disabled {
		if lang == services.RouteHarvesterLanguageJava {
			dMap[svc.InstrumentableJava] = struct{}{}
		}
		if lang == services.RouteHarvesterLanguageNodejs {
			dMap[svc.InstrumentableNodejs] = struct{}{}
		}
	}

	h := &RouteHarvester{
		log:      slog.With("component", "route.harvester"),
		java:     NewJavaRoutesHarvester(),
		disabled: dMap,
		timeout:  timeout,
		cfg:      cfg,
		mux:      &sync.Mutex{},

		javaHarvestSemaphore: make(chan struct{}, 1),
	}

	h.javaExtractRoutes = h.java.ExtractRoutes
	h.nodeExtractRoutes = ExtractNodejsRoutes

	return h
}

func (h *RouteHarvester) HarvestRoutes(fileInfo *exec.FileInfo) (*RouteHarvesterResult, error) {
	// Ensure we harvest one by one
	h.mux.Lock()
	defer h.mux.Unlock()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	resultChan := make(chan routeHarvestResult, 1)

	// Run the harvesting in a goroutine
	switch fileInfo.SDKLanguage() {
	case svc.InstrumentableJava:
		if _, ok := h.disabled[svc.InstrumentableJava]; ok {
			return nil, nil
		}
		if !h.acquireJavaHarvest(ctx) {
			h.log.Warn("route harvesting timed out", "timeout", h.timeout, "pid", fileInfo.Pid())
			return nil, &HarvestError{Message: "route harvesting timed out"}
		}
		go h.harvestJavaRoutes(fileInfo.Pid(), resultChan)
	case svc.InstrumentableNodejs:
		go h.harvestNodejsRoutes(fileInfo.Pid(), resultChan)
	default:
		return nil, nil
	}

	// Wait for either completion or timeout
	select {
	case result := <-resultChan:
		return result.r, result.err
	case <-ctx.Done():
		h.log.Warn("route harvesting timed out", "timeout", h.timeout, "pid", fileInfo.Pid())
		return nil, &HarvestError{Message: "route harvesting timed out"}
	}
}

func (h *RouteHarvester) acquireJavaHarvest(ctx context.Context) bool {
	select {
	case h.javaHarvestSemaphore <- struct{}{}:
		if ctx.Err() != nil {
			h.releaseJavaHarvest()
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}

func (h *RouteHarvester) releaseJavaHarvest() {
	<-h.javaHarvestSemaphore
}

func (h *RouteHarvester) harvestJavaRoutes(pid app.PID, resultChan chan<- routeHarvestResult) {
	defer func() {
		if r := recover(); r != nil {
			h.log.Error("route harvesting failed", "error", r)
			resultChan <- routeHarvestResult{err: &HarvestError{Message: "harvesting failed"}}
		}
	}()
	defer h.releaseJavaHarvest()

	// Keep the attach lifecycle on one OS thread because jvmtools changes thread-local state.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	h.java.Attacher.Init()
	defer h.java.Attacher.Cleanup()

	r, err := h.javaExtractRoutes(pid)
	if err != nil {
		resultChan <- routeHarvestResult{err: err}
		return
	}
	resultChan <- routeHarvestResult{r: r}
}

func (h *RouteHarvester) harvestNodejsRoutes(pid app.PID, resultChan chan<- routeHarvestResult) {
	defer func() {
		if r := recover(); r != nil {
			h.log.Error("route harvesting failed", "error", r)
			resultChan <- routeHarvestResult{err: &HarvestError{Message: "harvesting failed"}}
		}
	}()

	if _, ok := h.disabled[svc.InstrumentableNodejs]; !ok {
		r, err := h.nodeExtractRoutes(pid)
		if err != nil {
			resultChan <- routeHarvestResult{err: err}
			return
		}
		h.log.Debug("found node js application routes", "routes", r.Routes)

		resultChan <- routeHarvestResult{r: r}
	} else {
		resultChan <- routeHarvestResult{r: nil}
	}
}

func RouteMatcherFromResult(r RouteHarvesterResult) route.Matcher {
	switch r.Kind {
	case CompleteRoutes:
		return route.NewMatcher(r.Routes)
	case PartialRoutes:
		return route.NewPartialRouteMatcher(r.Routes)
	}

	return nil
}

func (h *RouteHarvester) HarvestRoutesDelay(fileInfo *exec.FileInfo) (bool, time.Duration) {
	if fileInfo.SDKLanguage() == svc.InstrumentableJava {
		return true, h.cfg.JavaHarvestDelay
	}

	return false, 0
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// for testing purposes
var isDirFunc = isDir

func FindScriptDirectory(root, firstArg, cwd string) string {
	if strings.HasPrefix(firstArg, "/") {
		path := filepath.Join(root, firstArg)
		if isDirFunc(path) {
			return path + string(filepath.Separator)
		}

		lastSlashPos := strings.LastIndex(firstArg, "/")
		if lastSlashPos > 1 {
			path := filepath.Join(root, firstArg[:lastSlashPos])

			if isDirFunc(path) {
				return path + string(filepath.Separator)
			}
		}
	}

	result := filepath.Join(root, cwd)
	if result != "" && result[len(result)-1] != filepath.Separator {
		result += string(filepath.Separator)
	}

	return result
}
