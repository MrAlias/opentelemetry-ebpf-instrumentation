/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.api.baggage.propagation.W3CBaggagePropagator;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.TraceFlags;
import io.opentelemetry.api.trace.TraceState;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ObiRemoteParentPropagatorTest {
  private static final String OBI_TRACE_ID = "000102030405060708090a0b0c0d0e0f";
  private static final String OBI_PARENT_ID = "1011121314151617";
  private static final String W3C_TRACE_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  private static final String W3C_PARENT_ID = "bbbbbbbbbbbbbbbb";

  @Test
  void installsExactRemoteParent() {
    ObiRemoteParentPropagator propagator = new ObiRemoteParentPropagator(true, new OneShotBridge());

    Context extracted = propagator.extract(Context.root(), null, null);
    SpanContext parent = Span.fromContext(extracted).getSpanContext();

    assertTrue(parent.isValid());
    assertTrue(parent.isRemote());
    assertTrue(parent.isSampled());
    assertEquals(OBI_TRACE_ID, parent.getTraceId());
    assertEquals(OBI_PARENT_ID, parent.getSpanId());
  }

  @Test
  void validW3cParentWinsAfterObiCandidateInConfiguredOrder() {
    RecordingBridge bridge = new RecordingBridge();
    TextMapPropagator composite =
        new ObiSelectionRecordingPropagator(
            TextMapPropagator.composite(
                new ObiRemoteParentPropagator(true, bridge),
                W3CTraceContextPropagator.getInstance(),
                W3CBaggagePropagator.getInstance()));
    Map<String, String> carrier = new HashMap<>();
    carrier.put("traceparent", "00-" + W3C_TRACE_ID + "-" + W3C_PARENT_ID + "-00");

    Context extracted = composite.extract(Context.root(), carrier, MapGetter.INSTANCE);
    SpanContext parent = Span.fromContext(extracted).getSpanContext();

    assertEquals(W3C_TRACE_ID, parent.getTraceId());
    assertEquals(W3C_PARENT_ID, parent.getSpanId());
    assertFalse(parent.isSampled());
    assertEquals(1, bridge.takeCalls.get());
    assertEquals(0, bridge.discardCalls.get());
    assertEquals(1, bridge.standardParentCalls.get());
  }

  @Test
  void matchingW3cParentStillWinsAndConsumesObiCandidate() {
    RecordingBridge bridge = new RecordingBridge(1, W3C_TRACE_ID, W3C_PARENT_ID);
    TextMapPropagator composite =
        new ObiSelectionRecordingPropagator(
            TextMapPropagator.composite(
                new ObiRemoteParentPropagator(true, bridge),
                W3CTraceContextPropagator.getInstance()));
    Map<String, String> carrier =
        Collections.singletonMap("traceparent", "00-" + W3C_TRACE_ID + "-" + W3C_PARENT_ID + "-01");

    SpanContext parent =
        Span.fromContext(composite.extract(Context.root(), carrier, MapGetter.INSTANCE))
            .getSpanContext();

    assertEquals(W3C_TRACE_ID, parent.getTraceId());
    assertEquals(W3C_PARENT_ID, parent.getSpanId());
    assertTrue(parent.isSampled());
    assertEquals(1, bridge.takeCalls.get());
    assertEquals(0, bridge.discardCalls.get());
    assertEquals(1, bridge.standardParentCalls.get());
  }

  @Test
  void invalidW3cParentLeavesObiCandidate() {
    RecordingBridge bridge = new RecordingBridge();
    TextMapPropagator composite =
        new ObiSelectionRecordingPropagator(
            TextMapPropagator.composite(
                new ObiRemoteParentPropagator(true, bridge),
                W3CTraceContextPropagator.getInstance()));
    Map<String, String> carrier = Collections.singletonMap("traceparent", "invalid");

    Context extracted = composite.extract(Context.root(), carrier, MapGetter.INSTANCE);
    SpanContext parent = Span.fromContext(extracted).getSpanContext();

    assertEquals(OBI_TRACE_ID, parent.getTraceId());
    assertEquals(OBI_PARENT_ID, parent.getSpanId());
    assertEquals(1, bridge.takeCalls.get());
    assertEquals(0, bridge.discardCalls.get());
    assertEquals(0, bridge.standardParentCalls.get());
  }

  @Test
  void existingValidParentDiscardsBridgeEntry() {
    RecordingBridge bridge = new RecordingBridge();
    ObiRemoteParentPropagator propagator = new ObiRemoteParentPropagator(true, bridge);
    SpanContext existingParent =
        SpanContext.createFromRemoteParent(
            W3C_TRACE_ID, W3C_PARENT_ID, TraceFlags.getDefault(), TraceState.getDefault());
    Context input = Context.root().with(Span.wrap(existingParent));

    Context extracted = propagator.extract(input, null, null);

    assertSame(input, extracted);
    assertEquals(0, bridge.takeCalls.get());
    assertEquals(1, bridge.discardCalls.get());
    assertEquals(BridgeAccess.DISCARD_STANDARD_PARENT, bridge.discardReason.get());
    assertEquals(existingParent, Span.fromContext(extracted).getSpanContext());
  }

  @Test
  void preservesFutureTraceFlagBits() {
    ObiRemoteParentPropagator propagator =
        new ObiRemoteParentPropagator(
            true,
            () -> new BridgeResult(BridgeResult.STATUS_VALID, 0x81, OBI_TRACE_ID, OBI_PARENT_ID));

    SpanContext parent =
        Span.fromContext(propagator.extract(Context.root(), null, null)).getSpanContext();

    assertEquals((byte) 0x81, parent.getTraceFlags().asByte());
    assertTrue(parent.isSampled());
  }

  @Test
  void preservesSampledAndUnsampledObiDecisions() {
    ObiRemoteParentPropagator unsampled =
        new ObiRemoteParentPropagator(
            true,
            () -> new BridgeResult(BridgeResult.STATUS_VALID, 0, OBI_TRACE_ID, OBI_PARENT_ID));
    ObiRemoteParentPropagator sampled =
        new ObiRemoteParentPropagator(
            true,
            () -> new BridgeResult(BridgeResult.STATUS_VALID, 1, OBI_TRACE_ID, OBI_PARENT_ID));

    SpanContext unsampledParent =
        Span.fromContext(unsampled.extract(Context.root(), null, null)).getSpanContext();
    SpanContext sampledParent =
        Span.fromContext(sampled.extract(Context.root(), null, null)).getSpanContext();

    assertFalse(unsampledParent.isSampled());
    assertTrue(sampledParent.isSampled());
    assertEquals((byte) 0, unsampledParent.getTraceFlags().asByte());
    assertEquals((byte) 1, sampledParent.getTraceFlags().asByte());
  }

  @Test
  void repeatedExtractionTakesCandidateOnlyOnce() {
    RecordingBridge bridge = new RecordingBridge();
    ObiRemoteParentPropagator propagator = new ObiRemoteParentPropagator(true, bridge);

    Context first = propagator.extract(Context.root(), null, null);
    Context repeated = propagator.extract(first, null, null);

    assertSame(first, repeated);
    assertEquals(1, bridge.takeCalls.get());
    assertEquals(1, bridge.discardCalls.get());
  }

  @Test
  void missingMalformedAndRepeatedTakeLeaveInputUnchanged() {
    OneShotBridge bridge = new OneShotBridge();
    ObiRemoteParentPropagator propagator = new ObiRemoteParentPropagator(true, bridge);
    Context first = propagator.extract(Context.root(), null, null);

    Context input = first.with(Span.wrap(Span.fromContext(first).getSpanContext()));
    assertSame(input, propagator.extract(input, null, null));

    AtomicInteger extractionFailures = new AtomicInteger();
    ObiRemoteParentPropagator malformed =
        new ObiRemoteParentPropagator(
            true,
            new BridgeAccess() {
              @Override
              public BridgeResult takeRemoteParent() {
                return new BridgeResult(
                    BridgeResult.STATUS_VALID, 0, "00000000000000000000000000000000", "0");
              }

              @Override
              public void recordExtractionFailure(int reason) {
                extractionFailures.incrementAndGet();
                assertEquals(BridgeAccess.EXTRACTION_INVALID_CONTEXT, reason);
              }
            });
    Context empty = Context.root();
    assertSame(empty, malformed.extract(empty, null, null));
    assertEquals(1, extractionFailures.get());
  }

  @Test
  void disabledPropagatorDoesNotCallBridgeOrAdvertiseFields() {
    AtomicInteger calls = new AtomicInteger();
    ObiRemoteParentPropagator propagator =
        new ObiRemoteParentPropagator(
            false,
            () -> {
              calls.incrementAndGet();
              return BridgeResult.status(BridgeResult.STATUS_VALID);
            });
    Context input = Context.root();

    assertSame(input, propagator.extract(input, null, null));
    assertEquals(0, calls.get());
    assertTrue(propagator.fields().isEmpty());
    propagator.inject(input, new HashMap<String, String>(), Map::put);
    assertEquals(0, calls.get());
  }

  private static final class OneShotBridge implements BridgeAccess {
    private final AtomicInteger calls = new AtomicInteger();

    @Override
    public BridgeResult takeRemoteParent() {
      if (calls.getAndIncrement() > 0) {
        return BridgeResult.status(BridgeResult.STATUS_MISSING);
      }
      return new BridgeResult(BridgeResult.STATUS_VALID, 1, OBI_TRACE_ID, OBI_PARENT_ID);
    }
  }

  private static final class RecordingBridge implements BridgeAccess {
    private final AtomicInteger takeCalls = new AtomicInteger();
    private final AtomicInteger discardCalls = new AtomicInteger();
    private final AtomicInteger discardReason = new AtomicInteger();
    private final AtomicInteger standardParentCalls = new AtomicInteger();
    private final int traceFlags;
    private final String traceId;
    private final String parentSpanId;

    private RecordingBridge() {
      this(1, OBI_TRACE_ID, OBI_PARENT_ID);
    }

    private RecordingBridge(int traceFlags, String traceId, String parentSpanId) {
      this.traceFlags = traceFlags;
      this.traceId = traceId;
      this.parentSpanId = parentSpanId;
    }

    @Override
    public BridgeResult takeRemoteParent() {
      takeCalls.incrementAndGet();
      return new BridgeResult(BridgeResult.STATUS_VALID, traceFlags, traceId, parentSpanId);
    }

    @Override
    public void discardRemoteParent(int reason) {
      discardCalls.incrementAndGet();
      discardReason.set(reason);
    }

    @Override
    public void recordStandardParentWon() {
      standardParentCalls.incrementAndGet();
    }
  }

  private enum MapGetter implements TextMapGetter<Map<String, String>> {
    INSTANCE;

    @Override
    public Iterable<String> keys(Map<String, String> carrier) {
      return carrier.keySet();
    }

    @Override
    public String get(Map<String, String> carrier, String key) {
      return carrier == null ? null : carrier.get(key);
    }
  }
}
