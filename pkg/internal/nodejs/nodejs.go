// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	_ "embed"
	"log/slog"
	"net"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
)

type NodeInjector struct {
	log *slog.Logger
	cfg *obi.Config
}

// PreparedExecutable pins every process-scoped handle needed by Node.js
// injection. The caller owns it and must Close it on every path.
type PreparedExecutable interface {
	NewExecutable() error
	Close() error
}

func NewNodeInjector(cfg *obi.Config) *NodeInjector {
	log := slog.With("component", "nodejs.Injector")

	if !cfg.NodeJS.Enabled && cfg.AppRuntimeMetricsEnabled() {
		log.Warn("application_runtime is enabled but the Node.js injector is disabled " +
			"(nodejs.enabled=false): Node.js runtime metrics will not be collected")
	}

	return &NodeInjector{
		cfg: cfg,
		log: log,
	}
}

// Enabled reports whether the agent should be injected: the injected script
// is both the trace-context propagation vehicle and the only source of the
// nodejs.eventloop.* runtime metrics, so either consumer turns it on —
// unless nodejs.enabled, the global opt-out, is set to false.
func (i *NodeInjector) Enabled() bool {
	return i.cfg.NodeJS.Enabled &&
		(i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() || i.cfg.AppRuntimeMetricsEnabled())
}

// injectionTrigger names what turned the injection on, so the logs explain a
// metrics-only injection.
func (i *NodeInjector) injectionTrigger() string {
	if i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() {
		return "traces"
	}
	return "runtime metrics"
}

func (i *NodeInjector) NewExecutable(ie *ebpf.Instrumentable) {
	prepared, err := i.PrepareExecutable(ie)
	if err != nil {
		i.log.Error("couldn't prepare exact NodeJS injector target", "error", err)
		return
	}
	if prepared == nil {
		return
	}
	defer func() {
		if err := prepared.Close(); err != nil {
			i.log.Warn("couldn't close exact NodeJS injector target", "error", err)
		}
	}()

	if err := prepared.NewExecutable(); err != nil {
		pid := 0
		if ie != nil && ie.PIDOwnerFileInfo() != nil {
			pid = int(ie.PIDOwnerFileInfo().Pid())
		}
		i.log.Error("couldn't attach NodeJS injector", "pid", pid, "error", err)
		i.log.Error("trace-context propagation and nodejs runtime metrics will not work for NodeJS services!")
	}
}

// PrepareExecutable binds injection to the exact discovery-event owner. In
// particular, it never substitutes FileInfo.Pid when discovery selected a
// parent executable for a child Node.js event.
func (i *NodeInjector) PrepareExecutable(ie *ebpf.Instrumentable) (PreparedExecutable, error) {
	if !i.Enabled() {
		i.log.Debug("Node Injector is disabled")
		return nil, nil
	}

	if ie == nil || ie.Type != svc.InstrumentableNodejs {
		i.log.Debug("not a NodeJS executable")
		return nil, nil
	}

	owner := ie.PIDOwnerFileInfo()
	if owner == nil {
		return nil, nil
	}
	i.log.Info("loading NodeJS instrumentation", "pid", owner.Pid(), "trigger", i.injectionTrigger())
	return i.prepareExactExecutable(ie, owner)
}

// isNodeInspector validates that a connection to port 9229 is actually a
// Node.js inspector by requesting /json/version and checking for a valid
// JSON response.
func (i *NodeInjector) isNodeInspector(conn net.Conn) bool {
	resp, err := httpGet(conn, "/json/version")
	if err != nil {
		return false
	}

	// The Node.js inspector responds with a JSON object containing
	// "Browser" and "Protocol-Version" fields.
	return len(resp) > 0 && resp[0] == '{'
}

//go:embed fdextractor.js
var _extractorCode string

//go:embed spanbridge.js
var _spanBridgeCode string

// Substituted at injection time so each injection installs only the
// machinery its configuration asks for (see the OBI_RT_ENABLED and
// OBI_TRACES_ENABLED comments in fdextractor.js).
const (
	rtEnabledPlaceholder     = "= false; /*OBI_RT_ENABLED*/"
	rtEnabledOn              = "= true; /*OBI_RT_ENABLED*/"
	tracesEnabledPlaceholder = "= false; /*OBI_TRACES_ENABLED*/"
	tracesEnabledOn          = "= true; /*OBI_TRACES_ENABLED*/"
)

// agentCode returns the extractor script with the RT gate substituted from
// the same predicate that sets the nodejs_runtime_metrics_enabled BPF
// constant, so the agent and the eBPF side cannot disagree. When manual
// spans are enabled the span bridge is appended as a second script: both are
// self-contained IIFEs, joined with an explicit ';' so the bridge's leading
// '(' is not parsed as a call of the extractor IIFE's return value.
func (i *NodeInjector) agentCode() string {
	code := _extractorCode
	if i.cfg.AppRuntimeMetricsEnabled() {
		code = strings.Replace(code, rtEnabledPlaceholder, rtEnabledOn, 1)
	}
	if i.cfg.Traces.Enabled() || i.cfg.TracePrinter.Enabled() {
		code = strings.Replace(code, tracesEnabledPlaceholder, tracesEnabledOn, 1)
	}
	if i.cfg.NodeJS.ManualSpans {
		code += ";\n" + _spanBridgeCode
	}
	return code
}
