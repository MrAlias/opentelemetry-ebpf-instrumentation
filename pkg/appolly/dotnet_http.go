// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly // import "go.opentelemetry.io/obi/pkg/appolly"

import (
	"container/list"
	"context"
	"net/netip"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const (
	dotnetHTTPEntries      = 8192
	dotnetHTTPObservations = 8
)

type dotnetSpanKey struct {
	namespace uint32
	pid       app.PID
	traceID   trace.TraceID
	spanID    trace.SpanID
}

type dotnetServerKey struct {
	namespace          uint32
	pid                app.PID
	traceID            trace.TraceID
	parent             trace.SpanID
	host               netip.Addr
	peer               netip.Addr
	hostPort, peerPort int
	method, path       string
}

type dotnetServerObservation struct {
	start, end int64
	id         trace.SpanID
}

type dotnetServerPair struct {
	kernel, native []dotnetServerObservation
}

type dotnetHeldSpan struct {
	span      request.Span
	deadline  time.Time
	parent    dotnetSpanKey
	key       dotnetSpanKey
	transport bool
}

type dotnetClientIDs struct {
	traceID trace.TraceID
	spanID  trace.SpanID
	flags   uint8
}

type dotnetHTTPResolver struct {
	output        *msg.Queue[[]request.Span]
	timeout       time.Duration
	recordTimeout time.Duration
	servers       *lru.Cache[dotnetServerKey, *dotnetServerPair]
	aliases       *lru.Cache[dotnetSpanKey, trace.SpanID]
	clients       *lru.Cache[dotnetSpanKey, dotnetClientIDs]
	fallbacks     *lru.Cache[dotnetSpanKey, int64]
	pending       map[dotnetSpanKey]*list.Element
	transports    map[dotnetSpanKey][]*list.Element
	parents       map[dotnetSpanKey]map[dotnetSpanKey]struct{}
	order         *list.List
}

func resolveDotnetHTTPContext(timeout, recordTimeout time.Duration, input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return func(context.Context) (swarm.RunFunc, error) {
		resolver := newDotnetHTTPResolver(timeout, recordTimeout, output)
		in := input.Subscribe(msg.SubscriberName("appolly.DotnetHTTPContext"))
		return func(ctx context.Context) {
			defer output.Close()
			ticker := time.NewTicker(settleTick)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					resolver.expire(ctx, time.Time{})
					return
				case spans, ok := <-in:
					if !ok {
						resolver.expire(ctx, time.Time{})
						return
					}
					resolver.process(ctx, spans)
				case now := <-ticker.C:
					resolver.expire(ctx, now)
				}
			}
		}, nil
	}
}

func newDotnetHTTPResolver(timeout, recordTimeout time.Duration, output *msg.Queue[[]request.Span]) *dotnetHTTPResolver {
	servers, _ := lru.New[dotnetServerKey, *dotnetServerPair](dotnetHTTPEntries)
	aliases, _ := lru.New[dotnetSpanKey, trace.SpanID](dotnetHTTPEntries)
	clients, _ := lru.New[dotnetSpanKey, dotnetClientIDs](dotnetHTTPEntries)
	fallbacks, _ := lru.New[dotnetSpanKey, int64](dotnetHTTPEntries)
	return &dotnetHTTPResolver{
		output: output, timeout: timeout, recordTimeout: recordTimeout, servers: servers, aliases: aliases, clients: clients, fallbacks: fallbacks,
		pending: map[dotnetSpanKey]*list.Element{}, transports: map[dotnetSpanKey][]*list.Element{}, parents: map[dotnetSpanKey]map[dotnetSpanKey]struct{}{}, order: list.New(),
	}
}

func dotnetKey(span *request.Span, id trace.SpanID) dotnetSpanKey {
	return dotnetSpanKey{namespace: span.Pid.Namespace, pid: span.Pid.UserPID, traceID: span.TraceID, spanID: id}
}

func dotnetServerEndpoint(span *request.Span) (dotnetServerKey, bool) {
	host, err := netip.ParseAddr(span.Host)
	if err != nil {
		return dotnetServerKey{}, false
	}
	peer, err := netip.ParseAddr(span.Peer)
	if err != nil {
		return dotnetServerKey{}, false
	}
	return dotnetServerKey{
		namespace: span.Pid.Namespace, pid: span.Pid.UserPID, traceID: span.TraceID, parent: span.ParentSpanID,
		host: host.Unmap(), peer: peer.Unmap(), hostPort: span.HostPort, peerPort: span.PeerPort, method: span.Method, path: span.Path,
	}, true
}

func (r *dotnetHTTPResolver) server(span *request.Span) []request.Span {
	key, ok := dotnetServerEndpoint(span)
	if !ok {
		return nil
	}
	pair, ok := r.servers.Get(key)
	if !ok {
		pair = &dotnetServerPair{}
		r.servers.Add(key, pair)
	}
	observation := dotnetServerObservation{start: span.RequestStart, end: span.End, id: span.SpanID}
	if !span.DotnetHTTPContext && span.ServerSpanID.IsValid() {
		observation.id = span.ServerSpanID
	}
	if observation.start == 0 {
		observation.start = span.Start
	}
	if span.DotnetHTTPContext {
		for index, kernel := range pair.kernel {
			if observation.start >= kernel.start && observation.start <= kernel.end {
				pair.kernel = append(pair.kernel[:index], pair.kernel[index+1:]...)
				native := dotnetKey(span, span.SpanID)
				r.aliases.Add(native, kernel.id)
				return r.releaseParent(native)
			}
		}
		pair.native = append(pair.native, observation)
		if len(pair.native) > dotnetHTTPObservations {
			pair.native = pair.native[1:]
		}
		return nil
	}
	for index, nativeObservation := range pair.native {
		if nativeObservation.start >= observation.start && nativeObservation.start <= observation.end {
			pair.native = append(pair.native[:index], pair.native[index+1:]...)
			native := dotnetKey(span, nativeObservation.id)
			r.aliases.Add(native, observation.id)
			return r.releaseParent(native)
		}
	}
	pair.kernel = append(pair.kernel, observation)
	if len(pair.kernel) > dotnetHTTPObservations {
		pair.kernel = pair.kernel[1:]
	}
	return nil
}

func (r *dotnetHTTPResolver) resolve(span *request.Span, key dotnetSpanKey) (bool, dotnetSpanKey) {
	nativeParent := key
	nativeParent.spanID = span.ParentSpanID
	if span.ParentSpanID.IsValid() {
		exported, ok := r.aliases.Get(nativeParent)
		if !ok {
			return false, nativeParent
		}
		span.ParentSpanID = exported
	}
	span.ParentConditional = false
	return true, dotnetSpanKey{}
}

func (r *dotnetHTTPResolver) process(ctx context.Context, spans []request.Span) {
	out := make([]request.Span, 0, len(spans))
	for i := range spans {
		span := spans[i]
		if span.DotnetHTTPContext {
			if span.Type == request.EventTypeHTTP {
				out = append(out, r.server(&span)...)
			}
			if span.Type == request.EventTypeHTTPClient {
				out = append(out, r.client(span)...)
			}
			continue
		}
		if span.Service.SDKLanguage != svc.InstrumentableDotnet || span.ProtoVersion != request.ProtoVersionHTTP11 {
			out = append(out, span)
			continue
		}
		if span.Type == request.EventTypeHTTP {
			if span.Start > span.RequestStart && !span.ServerSpanID.IsValid() {
				span.ServerSpanID = idgen.RandomSpanID()
			}
			out = append(out, r.server(&span)...)
			out = append(out, span)
			continue
		}
		if span.Type != request.EventTypeHTTPClient || request.HTTPScheme(&span) != "https" || !span.WireTraceContext.IsValid() {
			out = append(out, span)
			continue
		}
		key := dotnetWireKey(&span)
		if ids, ok := r.clients.Get(key); ok {
			out = append(out, dotnetTransportMetrics(span, ids))
			continue
		}
		out = append(out, r.hold(span, key, dotnetSpanKey{}, true)...)
	}
	if len(out) > 0 {
		r.output.SendCtx(ctx, out)
	}
}

func dotnetWireKey(span *request.Span) dotnetSpanKey {
	key := dotnetKey(span, span.WireTraceContext.SpanID())
	key.traceID = span.WireTraceContext.TraceID()
	return key
}

func dotnetTransportMetrics(span request.Span, ids dotnetClientIDs) request.Span {
	request.SetIgnoreTraces(&span)
	if span.WireTraceContext.TraceID() == ids.traceID && span.WireTraceContext.SpanID() == ids.spanID {
		span.TraceID, span.SpanID, span.TraceFlags = ids.traceID, ids.spanID, ids.flags
	}
	span.ParentConditional = false
	return span
}

func (r *dotnetHTTPResolver) client(span request.Span) []request.Span {
	if !span.WireTraceContext.IsValid() {
		return nil
	}
	wire := dotnetWireKey(&span)
	ids := dotnetClientIDs{traceID: span.TraceID, spanID: span.SpanID, flags: span.TraceFlags}
	r.clients.Add(wire, ids)
	var out []request.Span
	for _, element := range append([]*list.Element(nil), r.transports[wire]...) {
		out = append(out, dotnetTransportMetrics(r.remove(wire, element), ids))
	}
	if end, ok := r.fallbacks.Get(wire); ok && span.Start <= end {
		return out
	}
	span.DotnetHTTPContext = false
	request.SetIgnoreMetrics(&span)
	key := dotnetKey(&span, span.SpanID)
	resolved, parent := r.resolve(&span, key)
	if resolved {
		return append(out, span)
	}
	return append(out, r.hold(span, key, parent, false)...)
}

func (r *dotnetHTTPResolver) hold(span request.Span, key, parent dotnetSpanKey, transport bool) []request.Span {
	var out []request.Span
	if r.order.Len() >= dotnetHTTPEntries {
		oldest := r.order.Front()
		out = append(out, r.fallback(oldest.Value.(*dotnetHeldSpan).key, oldest))
	}
	timeout := r.timeout
	if transport {
		timeout = r.recordTimeout
	}
	held := &dotnetHeldSpan{span: span, key: key, transport: transport, deadline: time.Now().Add(timeout)}
	element := r.order.PushBack(held)
	if transport {
		r.transports[key] = append(r.transports[key], element)
	} else {
		if old := r.pending[key]; old != nil {
			out = append(out, r.fallback(key, old))
		}
		r.pending[key] = element
		r.waitForParent(key, held, parent)
	}
	return out
}

func (r *dotnetHTTPResolver) waitForParent(key dotnetSpanKey, held *dotnetHeldSpan, parent dotnetSpanKey) {
	if !parent.spanID.IsValid() || held.parent == parent {
		return
	}
	if held.parent.spanID.IsValid() {
		delete(r.parents[held.parent], key)
		if len(r.parents[held.parent]) == 0 {
			delete(r.parents, held.parent)
		}
	}
	held.parent = parent
	if r.parents[parent] == nil {
		r.parents[parent] = map[dotnetSpanKey]struct{}{}
	}
	r.parents[parent][key] = struct{}{}
}

func (r *dotnetHTTPResolver) release(key dotnetSpanKey, element *list.Element) []request.Span {
	held := element.Value.(*dotnetHeldSpan)
	resolved, parent := r.resolve(&held.span, key)
	if !resolved {
		r.waitForParent(key, held, parent)
		return nil
	}
	return []request.Span{r.remove(key, element)}
}

func (r *dotnetHTTPResolver) releaseParent(parent dotnetSpanKey) []request.Span {
	var out []request.Span
	for key := range r.parents[parent] {
		if element := r.pending[key]; element != nil {
			out = append(out, r.release(key, element)...)
		}
	}
	delete(r.parents, parent)
	return out
}

func (r *dotnetHTTPResolver) remove(key dotnetSpanKey, element *list.Element) request.Span {
	held := element.Value.(*dotnetHeldSpan)
	if held.transport {
		for index, candidate := range r.transports[key] {
			if candidate == element {
				r.transports[key] = append(r.transports[key][:index], r.transports[key][index+1:]...)
				break
			}
		}
		if len(r.transports[key]) == 0 {
			delete(r.transports, key)
		}
	} else {
		delete(r.pending, key)
	}
	r.order.Remove(element)
	if held.parent.spanID.IsValid() {
		delete(r.parents[held.parent], key)
		if len(r.parents[held.parent]) == 0 {
			delete(r.parents, held.parent)
		}
	}
	return held.span
}

func (r *dotnetHTTPResolver) expire(ctx context.Context, now time.Time) {
	var out []request.Span
	for element := r.order.Front(); element != nil; {
		next := element.Next()
		held := element.Value.(*dotnetHeldSpan)
		if !now.IsZero() && held.deadline.After(now) {
			element = next
			continue
		}
		out = append(out, r.fallback(held.key, element))
		element = next
	}
	if len(out) > 0 {
		r.output.SendCtx(ctx, out)
	}
}

func (r *dotnetHTTPResolver) fallback(key dotnetSpanKey, element *list.Element) request.Span {
	held := element.Value.(*dotnetHeldSpan)
	span := r.remove(key, element)
	if held.transport {
		r.fallbacks.Add(key, span.End)
	} else {
		span = detachParent(span)
		span.ParentConditional = false
	}
	return span
}
