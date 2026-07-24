/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.api.baggage.Baggage;
import io.opentelemetry.api.baggage.propagation.W3CBaggagePropagator;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.TraceFlags;
import io.opentelemetry.api.trace.TraceState;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import io.opentelemetry.context.propagation.TextMapSetter;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ObiRemoteParentPropagatorTest {
  private static final String OBI_TRACE_ID = "000102030405060708090a0b0c0d0e0f";
  private static final String OBI_PARENT_ID = "1011121314151617";
  private static final String W3C_TRACE_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  private static final String W3C_PARENT_ID = "bbbbbbbbbbbbbbbb";
  private static final String ALTERNATE_TRACE_ID = "cccccccccccccccccccccccccccccccc";
  private static final String ALTERNATE_PARENT_ID = "dddddddddddddddd";

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
        TextMapPropagator.composite(
            new ObiSelectionRecordingPropagator(new ObiRemoteParentPropagator(true, bridge)),
            new ObiSelectionRecordingPropagator(W3CTraceContextPropagator.getInstance()),
            new ObiSelectionRecordingPropagator(W3CBaggagePropagator.getInstance()));
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
  void matchingW3cParentWinsOnlyOnceAcrossRepeatedExtraction() {
    RecordingBridge bridge = new RecordingBridge(1, W3C_TRACE_ID, W3C_PARENT_ID);
    TextMapPropagator composite =
        TextMapPropagator.composite(
            new ObiSelectionRecordingPropagator(new ObiRemoteParentPropagator(true, bridge)),
            new ObiSelectionRecordingPropagator(W3CTraceContextPropagator.getInstance()));
    Map<String, String> carrier =
        Collections.singletonMap("traceparent", "00-" + W3C_TRACE_ID + "-" + W3C_PARENT_ID + "-01");

    Context extracted = composite.extract(Context.root(), carrier, MapGetter.INSTANCE);
    Context repeated = composite.extract(extracted, carrier, MapGetter.INSTANCE);
    Context repeatedAgain = composite.extract(repeated, carrier, MapGetter.INSTANCE);
    SpanContext parent = Span.fromContext(repeatedAgain).getSpanContext();

    assertEquals(W3C_TRACE_ID, parent.getTraceId());
    assertEquals(W3C_PARENT_ID, parent.getSpanId());
    assertTrue(parent.isSampled());
    assertEquals(1, bridge.takeCalls.get());
    assertEquals(0, bridge.discardCalls.get());
    assertEquals(1, bridge.standardParentCalls.get());
  }

  @Test
  void concurrentConflictingW3cSelectionsRemainBranchLocal() throws Exception {
    RecordingBridge bridge = new RecordingBridge();
    TextMapPropagator obi =
        new ObiSelectionRecordingPropagator(new ObiRemoteParentPropagator(true, bridge));
    TextMapPropagator w3c =
        new ObiSelectionRecordingPropagator(
            new ExtractionBarrierPropagator(
                W3CTraceContextPropagator.getInstance(), new CountDownLatch(2)));
    Map<String, String> firstCarrier =
        Collections.singletonMap("traceparent", "00-" + W3C_TRACE_ID + "-" + W3C_PARENT_ID + "-01");
    Map<String, String> secondCarrier =
        Collections.singletonMap(
            "traceparent", "00-" + ALTERNATE_TRACE_ID + "-" + ALTERNATE_PARENT_ID + "-01");
    Context candidate = obi.extract(Context.root(), Collections.emptyMap(), MapGetter.INSTANCE);
    ExecutorService executor = Executors.newFixedThreadPool(2);

    try {
      Future<Context> first =
          executor.submit(() -> w3c.extract(candidate, firstCarrier, MapGetter.INSTANCE));
      Future<Context> second =
          executor.submit(() -> w3c.extract(candidate, secondCarrier, MapGetter.INSTANCE));
      Context firstSelected = first.get(5, TimeUnit.SECONDS);
      Context secondSelected = second.get(5, TimeUnit.SECONDS);

      assertNotSame(Span.fromContext(firstSelected), Span.fromContext(secondSelected));
      assertFalse(
          Span.fromContext(firstSelected)
              .getSpanContext()
              .equals(Span.fromContext(secondSelected).getSpanContext()));

      obi.extract(firstSelected, firstCarrier, MapGetter.INSTANCE);
      obi.extract(secondSelected, secondCarrier, MapGetter.INSTANCE);
      obi.extract(secondSelected, secondCarrier, MapGetter.INSTANCE);
      obi.extract(firstSelected, firstCarrier, MapGetter.INSTANCE);
    } finally {
      executor.shutdownNow();
      assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    assertEquals(1, bridge.takeCalls.get());
    assertEquals(0, bridge.discardCalls.get());
    assertEquals(1, bridge.standardParentCalls.get());
  }

  @Test
  void invalidW3cParentLeavesObiCandidate() {
    RecordingBridge bridge = new RecordingBridge();
    TextMapPropagator composite =
        TextMapPropagator.composite(
            new ObiSelectionRecordingPropagator(new ObiRemoteParentPropagator(true, bridge)),
            new ObiSelectionRecordingPropagator(W3CTraceContextPropagator.getInstance()));
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
  void unchangedIntermediatePropagatorDoesNotHideLaterW3cParent() {
    RecordingBridge bridge = new RecordingBridge();
    TextMapPropagator composite =
        TextMapPropagator.composite(
            new ObiSelectionRecordingPropagator(new ObiRemoteParentPropagator(true, bridge)),
            new ObiSelectionRecordingPropagator(W3CBaggagePropagator.getInstance()),
            new ObiSelectionRecordingPropagator(W3CTraceContextPropagator.getInstance()));
    Map<String, String> carrier = new HashMap<>();
    carrier.put("traceparent", "00-" + W3C_TRACE_ID + "-" + W3C_PARENT_ID + "-01");

    SpanContext parent =
        Span.fromContext(composite.extract(Context.root(), carrier, MapGetter.INSTANCE))
            .getSpanContext();

    assertEquals(W3C_TRACE_ID, parent.getTraceId());
    assertEquals(W3C_PARENT_ID, parent.getSpanId());
    assertEquals(1, bridge.standardParentCalls.get());
  }

  @Test
  void contextChangingIntermediatePropagatorDoesNotHideLaterW3cParent() {
    RecordingBridge bridge = new RecordingBridge();
    TextMapPropagator obi =
        new ObiSelectionRecordingPropagator(new ObiRemoteParentPropagator(true, bridge));
    TextMapPropagator baggage =
        new ObiSelectionRecordingPropagator(W3CBaggagePropagator.getInstance());
    TextMapPropagator w3c =
        new ObiSelectionRecordingPropagator(W3CTraceContextPropagator.getInstance());
    Map<String, String> carrier = new HashMap<>();
    carrier.put("baggage", "key=value");
    carrier.put("traceparent", "00-" + W3C_TRACE_ID + "-" + W3C_PARENT_ID + "-01");

    Context candidate = obi.extract(Context.root(), carrier, MapGetter.INSTANCE);
    Context withBaggage = baggage.extract(candidate, carrier, MapGetter.INSTANCE);

    assertNotSame(candidate, withBaggage);
    assertEquals("value", Baggage.fromContext(withBaggage).getEntryValue("key"));
    assertEquals(0, bridge.standardParentCalls.get());

    Context extracted = w3c.extract(withBaggage, carrier, MapGetter.INSTANCE);
    SpanContext parent = Span.fromContext(extracted).getSpanContext();

    assertEquals(W3C_TRACE_ID, parent.getTraceId());
    assertEquals(W3C_PARENT_ID, parent.getSpanId());
    assertEquals(1, bridge.standardParentCalls.get());
  }

  @Test
  void inheritedCandidateRetiresOnceForAnUnchangedServerParent() {
    RecordingBridge bridge = new RecordingBridge();
    TextMapPropagator composite =
        TextMapPropagator.composite(
            new ObiSelectionRecordingPropagator(new ObiRemoteParentPropagator(true, bridge)),
            new ObiSelectionRecordingPropagator(W3CTraceContextPropagator.getInstance()));
    Context candidate =
        composite.extract(Context.root(), Collections.emptyMap(), MapGetter.INSTANCE);
    SpanContext serverSpanContext =
        SpanContext.create(
            ALTERNATE_TRACE_ID,
            ALTERNATE_PARENT_ID,
            TraceFlags.getSampled(),
            TraceState.getDefault());
    Context serverContext = candidate.with(Span.wrap(serverSpanContext));

    Context extracted =
        composite.extract(serverContext, Collections.emptyMap(), MapGetter.INSTANCE);
    Context repeated = composite.extract(extracted, Collections.emptyMap(), MapGetter.INSTANCE);
    Map<String, String> carrier =
        Collections.singletonMap("traceparent", "00-" + W3C_TRACE_ID + "-" + W3C_PARENT_ID + "-01");
    Context laterW3c = composite.extract(repeated, carrier, MapGetter.INSTANCE);

    assertNotSame(serverContext, extracted);
    assertSame(Span.fromContext(serverContext), Span.fromContext(extracted));
    assertSame(extracted, repeated);
    assertNotSame(Span.fromContext(repeated), Span.fromContext(laterW3c));
    assertEquals(W3C_TRACE_ID, Span.fromContext(laterW3c).getSpanContext().getTraceId());
    assertEquals(W3C_PARENT_ID, Span.fromContext(laterW3c).getSpanContext().getSpanId());
    assertEquals(1, bridge.takeCalls.get());
    assertEquals(1, bridge.discardCalls.get());
    assertEquals(0, bridge.standardParentCalls.get());
    assertEquals(1, bridge.standardDiscardDiagnostics());
  }

  @Test
  void concurrentInheritedCandidatesDiscardEachExecutionTransport() throws Exception {
    CountDownLatch discardEntered = new CountDownLatch(2);
    CountDownLatch releaseDiscard = new CountDownLatch(1);
    RecordingBridge bridge = new BlockingDiscardBridge(discardEntered, releaseDiscard);
    TextMapPropagator composite =
        TextMapPropagator.composite(
            new ObiSelectionRecordingPropagator(new ObiRemoteParentPropagator(true, bridge)),
            new ObiSelectionRecordingPropagator(W3CTraceContextPropagator.getInstance()));
    Context candidate =
        composite.extract(Context.root(), Collections.emptyMap(), MapGetter.INSTANCE);
    SpanContext serverSpanContext =
        SpanContext.create(
            W3C_TRACE_ID, W3C_PARENT_ID, TraceFlags.getSampled(), TraceState.getDefault());
    Context serverContext = candidate.with(Span.wrap(serverSpanContext));
    ExecutorService executor = Executors.newFixedThreadPool(2);

    try {
      Future<Context> first =
          executor.submit(
              () -> composite.extract(serverContext, Collections.emptyMap(), MapGetter.INSTANCE));
      Future<Context> second =
          executor.submit(
              () -> composite.extract(serverContext, Collections.emptyMap(), MapGetter.INSTANCE));
      assertTrue(discardEntered.await(5, TimeUnit.SECONDS));

      releaseDiscard.countDown();
      Context firstExtracted = first.get(5, TimeUnit.SECONDS);
      Context secondExtracted = second.get(5, TimeUnit.SECONDS);
      assertNotSame(serverContext, firstExtracted);
      assertSame(Span.fromContext(serverContext), Span.fromContext(firstExtracted));
      assertNotSame(serverContext, secondExtracted);
      assertSame(Span.fromContext(serverContext), Span.fromContext(secondExtracted));
    } finally {
      releaseDiscard.countDown();
      executor.shutdownNow();
      assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    assertEquals(1, bridge.takeCalls.get());
    assertEquals(2, bridge.discardCalls.get());
    assertEquals(0, bridge.standardParentCalls.get());
    assertEquals(2, bridge.standardDiscardDiagnostics());
  }

  @Test
  void concurrentRetirementAndSelectionAccountIndependently() throws Exception {
    CountDownLatch discardEntered = new CountDownLatch(1);
    CountDownLatch releaseDiscard = new CountDownLatch(1);
    RecordingBridge bridge = new BlockingDiscardBridge(discardEntered, releaseDiscard);
    TextMapPropagator obi =
        new ObiSelectionRecordingPropagator(new ObiRemoteParentPropagator(true, bridge));
    TextMapPropagator w3c =
        new ObiSelectionRecordingPropagator(W3CTraceContextPropagator.getInstance());
    Context candidate = obi.extract(Context.root(), Collections.emptyMap(), MapGetter.INSTANCE);
    SpanContext serverSpanContext =
        SpanContext.create(
            ALTERNATE_TRACE_ID,
            ALTERNATE_PARENT_ID,
            TraceFlags.getSampled(),
            TraceState.getDefault());
    Context serverContext = candidate.with(Span.wrap(serverSpanContext));
    Map<String, String> carrier =
        Collections.singletonMap("traceparent", "00-" + W3C_TRACE_ID + "-" + W3C_PARENT_ID + "-01");
    ExecutorService executor = Executors.newSingleThreadExecutor();

    try {
      Future<Context> retirement =
          executor.submit(() -> obi.extract(serverContext, carrier, MapGetter.INSTANCE));
      assertTrue(discardEntered.await(5, TimeUnit.SECONDS));

      Context selected = w3c.extract(candidate, carrier, MapGetter.INSTANCE);
      assertEquals(W3C_TRACE_ID, Span.fromContext(selected).getSpanContext().getTraceId());

      releaseDiscard.countDown();
      retirement.get(5, TimeUnit.SECONDS);
    } finally {
      releaseDiscard.countDown();
      executor.shutdownNow();
      assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    assertEquals(1, bridge.takeCalls.get());
    assertEquals(1, bridge.discardCalls.get());
    assertEquals(1, bridge.standardParentCalls.get());
    assertEquals(2, bridge.standardDiscardDiagnostics());
  }

  @Test
  void selectionDoesNotSuppressConcurrentRetirement() throws Exception {
    CountDownLatch selectionEntered = new CountDownLatch(1);
    CountDownLatch releaseSelection = new CountDownLatch(1);
    RecordingBridge bridge = new BlockingSelectionBridge(selectionEntered, releaseSelection);
    TextMapPropagator obi =
        new ObiSelectionRecordingPropagator(new ObiRemoteParentPropagator(true, bridge));
    TextMapPropagator w3c =
        new ObiSelectionRecordingPropagator(W3CTraceContextPropagator.getInstance());
    Context candidate = obi.extract(Context.root(), Collections.emptyMap(), MapGetter.INSTANCE);
    SpanContext serverSpanContext =
        SpanContext.create(
            ALTERNATE_TRACE_ID,
            ALTERNATE_PARENT_ID,
            TraceFlags.getSampled(),
            TraceState.getDefault());
    Context serverContext = candidate.with(Span.wrap(serverSpanContext));
    Map<String, String> carrier =
        Collections.singletonMap("traceparent", "00-" + W3C_TRACE_ID + "-" + W3C_PARENT_ID + "-01");
    ExecutorService executor = Executors.newSingleThreadExecutor();

    try {
      Future<Context> selection =
          executor.submit(() -> w3c.extract(candidate, carrier, MapGetter.INSTANCE));
      assertTrue(selectionEntered.await(5, TimeUnit.SECONDS));

      Context retired = obi.extract(serverContext, carrier, MapGetter.INSTANCE);
      assertSame(Span.fromContext(serverContext), Span.fromContext(retired));

      releaseSelection.countDown();
      selection.get(5, TimeUnit.SECONDS);
    } finally {
      releaseSelection.countDown();
      executor.shutdownNow();
      assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
    }

    assertEquals(1, bridge.takeCalls.get());
    assertEquals(1, bridge.discardCalls.get());
    assertEquals(1, bridge.standardParentCalls.get());
    assertEquals(2, bridge.standardDiscardDiagnostics());
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
  void repeatedExtractionDoesNotDiscardOwnCandidate() {
    RecordingBridge bridge = new RecordingBridge();
    ObiRemoteParentPropagator propagator = new ObiRemoteParentPropagator(true, bridge);

    Context first = propagator.extract(Context.root(), null, null);
    Context repeated = propagator.extract(first, null, null);

    assertSame(first, repeated);
    assertEquals(1, bridge.takeCalls.get());
    assertEquals(0, bridge.discardCalls.get());
  }

  @Test
  void missingMalformedAndRepeatedTakeLeaveInputUnchanged() {
    OneShotBridge bridge = new OneShotBridge();
    ObiRemoteParentPropagator propagator = new ObiRemoteParentPropagator(true, bridge);
    Context first = propagator.extract(Context.root(), null, null);

    Context input = first.with(Span.wrap(Span.fromContext(first).getSpanContext()));
    assertSame(input, propagator.extract(input, null, null));
    assertEquals(1, bridge.calls.get());

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

  private static class RecordingBridge implements BridgeAccess {
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

    private int standardDiscardDiagnostics() {
      return discardCalls.get() + standardParentCalls.get();
    }
  }

  private static final class BlockingDiscardBridge extends RecordingBridge {
    private final CountDownLatch entered;
    private final CountDownLatch release;

    private BlockingDiscardBridge(CountDownLatch entered, CountDownLatch release) {
      this.entered = entered;
      this.release = release;
    }

    @Override
    public void discardRemoteParent(int reason) {
      super.discardRemoteParent(reason);
      entered.countDown();
      await(release);
    }
  }

  private static final class BlockingSelectionBridge extends RecordingBridge {
    private final CountDownLatch entered;
    private final CountDownLatch release;

    private BlockingSelectionBridge(CountDownLatch entered, CountDownLatch release) {
      this.entered = entered;
      this.release = release;
    }

    @Override
    public void recordStandardParentWon() {
      super.recordStandardParentWon();
      entered.countDown();
      await(release);
    }
  }

  private static final class ExtractionBarrierPropagator implements TextMapPropagator {
    private final TextMapPropagator delegate;
    private final CountDownLatch extracted;

    private ExtractionBarrierPropagator(TextMapPropagator delegate, CountDownLatch extracted) {
      this.delegate = delegate;
      this.extracted = extracted;
    }

    @Override
    public Collection<String> fields() {
      return delegate.fields();
    }

    @Override
    public <C> void inject(Context context, C carrier, TextMapSetter<C> setter) {
      delegate.inject(context, carrier, setter);
    }

    @Override
    public <C> Context extract(Context context, C carrier, TextMapGetter<C> getter) {
      Context result = delegate.extract(context, carrier, getter);
      extracted.countDown();
      await(extracted);
      return result;
    }
  }

  private static void await(CountDownLatch latch) {
    try {
      if (!latch.await(5, TimeUnit.SECONDS)) {
        throw new AssertionError("timed out waiting for concurrent extraction");
      }
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      throw new AssertionError(error);
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
