/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension.probe;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.ContextKey;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import io.opentelemetry.context.propagation.TextMapSetter;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizer;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.trace.ReadWriteSpan;
import io.opentelemetry.sdk.trace.ReadableSpan;
import io.opentelemetry.sdk.trace.SpanProcessor;
import io.opentelemetry.sdk.trace.data.SpanData;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Test-only official-agent extension for the isolated server runtime probes. */
public final class OfficialAgentProbeExtension implements AutoConfigurationCustomizerProvider {
  private static final String OUTPUT_PROPERTY = "obi.test.official.agent.probe.output";
  private static final String MODE_PROPERTY = "obi.test.official.agent.probe.mode";
  private static final String FRAMEWORK_PROPERTY = "obi.test.official.agent.probe.framework";
  private static final String INSTALL_PROVIDER_PROPERTY =
      "obi.test.official.agent.probe.install-provider";
  private static final String REEXTRACT_ID_PROPERTY = "obi.test.official.agent.probe.reextract.id";
  private static final String FRAMEWORK_JETTY = "jetty";
  private static final String FRAMEWORK_NETTY = "netty";
  private static final String FRAMEWORK_JAVA21_CONCURRENCY = "java21-concurrency";
  private static final String MODE_AUTO_UNAVAILABLE = "auto-unavailable";
  private static final String RAW_OBI_PROPAGATOR =
      "io.opentelemetry.obi.java.extension.ObiRemoteParentPropagator";
  private static final int STATUS_VALID = 1;
  private static final int STATUS_MISSING = 2;
  private static final int STATUS_STALE = 3;
  private static final int STATUS_MALFORMED = 5;
  private static final int STATUS_ALREADY_CONSUMED = 9;
  private static final long DISABLED_TRANSPORT_CONFIGURATION = 0x4f0200000003030dL;

  private static final String TRACE_A = "11111111111111111111111111111111";
  private static final String PARENT_A = "2222222222222222";
  private static final String TRACE_B = "33333333333333333333333333333333";
  private static final String PARENT_B = "4444444444444444";
  private static final String TRACE_W3C_ONLY = "12121212121212121212121212121212";
  private static final String TRACE_MATCHING = "34343434343434343434343434343434";
  private static final String PARENT_MATCHING = "5656565656565656";
  private static final String TRACE_CONFLICT = "77777777777777777777777777777777";
  private static final String PARENT_CONFLICT = "8888888888888888";
  private static final String TRACE_MALFORMED_W3C = "90909090909090909090909090909090";
  private static final String PARENT_MALFORMED_W3C = "9191919191919191";
  private static final String TRACE_P = "99999999999999999999999999999999";
  private static final String PARENT_P = "aaaaaaaaaaaaaaaa";
  private static final String TRACE_Q = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  private static final String PARENT_Q = "cccccccccccccccc";
  private static final String TRACE_D_OBI = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";
  private static final String PARENT_D_OBI = "abababababababab";
  private static final String TRACE_T = "20202020202020202020202020202020";
  private static final String PARENT_T = "2121212121212121";

  private static final ContextKey<String> PROBE_ID_CONTEXT =
      ContextKey.named("obi-official-agent-probe-id");
  private static final ConcurrentHashMap<String, AtomicInteger> EXTRACTION_CALLS =
      new ConcurrentHashMap<>();
  private static final AtomicInteger OBI_WRAPS = new AtomicInteger();
  private static final AtomicInteger AUTO_UNAVAILABLE_WRAPS = new AtomicInteger();
  private static final AtomicInteger HELPER_ABSENT_WRAPS = new AtomicInteger();

  @Override
  public int order() {
    // Wrap the raw OBI propagator before the production extension adds selection recording.
    return Integer.MIN_VALUE;
  }

  @Override
  public void customize(AutoConfigurationCustomizer customizer) {
    ProbeOutput output = new ProbeOutput(requiredProperty(OUTPUT_PROPERTY));
    output.append("EXTENSION\tready");
    String framework = System.getProperty(FRAMEWORK_PROPERTY);
    boolean jetty = FRAMEWORK_JETTY.equals(framework);
    boolean netty = FRAMEWORK_NETTY.equals(framework);
    boolean java21Concurrency = FRAMEWORK_JAVA21_CONCURRENCY.equals(framework);
    boolean installProvider =
        !"false".equalsIgnoreCase(System.getProperty(INSTALL_PROVIDER_PROPERTY));
    boolean autoUnavailable = MODE_AUTO_UNAVAILABLE.equals(System.getProperty(MODE_PROPERTY));
    if (autoUnavailable && installProvider) {
      throw new IllegalStateException("auto-unavailable mode must retain the native provider");
    }
    ProviderState provider =
        installProvider ? ProviderState.install(output, jetty, netty, java21Concurrency) : null;
    if (provider == null) {
      if (autoUnavailable) {
        output.append("PROVIDER\tretained\tbootstrap");
        customizer.addPropagatorCustomizer(
            (propagator, config) -> wrapAutoUnavailableObiPropagator(propagator, output));
      } else {
        output.append("PROVIDER\tabsent");
        customizer.addPropagatorCustomizer(
            (propagator, config) -> wrapHelperAbsentObiPropagator(propagator, output));
      }
    } else {
      customizer.addPropagatorCustomizer(
          (propagator, config) ->
              wrapObiPropagator(propagator, output, provider, netty, java21Concurrency));
    }
    customizer.addTracerProviderCustomizer(
        (builder, config) ->
            builder.addSpanProcessor(
                new CapturingSpanProcessor(output, netty, !installProvider, java21Concurrency)));
  }

  private static TextMapPropagator wrapObiPropagator(
      TextMapPropagator propagator,
      ProbeOutput output,
      ProviderState provider,
      boolean netty,
      boolean java21Concurrency) {
    if (!RAW_OBI_PROPAGATOR.equals(propagator.getClass().getName())) {
      return propagator;
    }
    int wraps = OBI_WRAPS.incrementAndGet();
    output.append("WRAP\tobi\t" + wraps);
    if (wraps != 1) {
      output.append("ERROR\tmultiple-obi-propagators");
    }
    return new RecordingObiPropagator(
        propagator,
        output,
        provider,
        System.getProperty(REEXTRACT_ID_PROPERTY),
        netty,
        java21Concurrency);
  }

  private static TextMapPropagator wrapHelperAbsentObiPropagator(
      TextMapPropagator propagator, ProbeOutput output) {
    if (!RAW_OBI_PROPAGATOR.equals(propagator.getClass().getName())) {
      return propagator;
    }
    int wraps = HELPER_ABSENT_WRAPS.incrementAndGet();
    output.append("WRAP\thelper-absent\t" + wraps);
    if (wraps != 1) {
      output.append("ERROR\tmultiple-helper-absent-obi-propagators");
    }
    return new HelperAbsentObiPropagator(propagator, output);
  }

  private static TextMapPropagator wrapAutoUnavailableObiPropagator(
      TextMapPropagator propagator, ProbeOutput output) {
    if (!RAW_OBI_PROPAGATOR.equals(propagator.getClass().getName())) {
      return propagator;
    }
    int wraps = AUTO_UNAVAILABLE_WRAPS.incrementAndGet();
    output.append("WRAP\tauto-unavailable\t" + wraps);
    if (wraps != 1) {
      output.append("ERROR\tmultiple-auto-unavailable-obi-propagators");
    }
    return new AutoUnavailableObiPropagator(propagator, output);
  }

  private static final class AutoUnavailableObiPropagator implements TextMapPropagator {
    private static final String ID_HEADER = "x-obi-probe-id";
    private static final String BRIDGE_CLASS =
        "io.opentelemetry.obi.java.bridge.RemoteParentBridge";
    private static final String PROVIDER_CLASS =
        "io.opentelemetry.obi.java.bridge.NativeRemoteParentProvider";
    private static final String THREAD_INFO_CLASS = "io.opentelemetry.obi.java.ebpf.ThreadInfo";
    private static final int CALLS_PER_PHASE = 8;
    private static final long DEADLINE_MARGIN_NANOS = TimeUnit.MILLISECONDS.toNanos(250L);

    private final TextMapPropagator delegate;
    private final ProbeOutput output;
    private final AtomicBoolean exercised = new AtomicBoolean();

    private AutoUnavailableObiPropagator(TextMapPropagator delegate, ProbeOutput output) {
      this.delegate = delegate;
      this.output = output;
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
      Context input = context == null ? Context.root() : context;
      if (!"H".equals(getter.get(carrier, ID_HEADER)) || !exercised.compareAndSet(false, true)) {
        return delegate.extract(input, carrier, getter);
      }

      try {
        markDirectLookup();
        Object provider = productionProvider();
        long initialDeadline = nextConfigurationAttemptNanos(provider);
        if (initialDeadline == 0L) {
          throw new IllegalStateException("unavailable provider has no retry deadline");
        }
        recordBaseline();
        waitUntil(initialDeadline + DEADLINE_MARGIN_NANOS);

        System.out.println("OBI_AUTO_UNAVAILABLE\tBURST_START");
        long phaseStart = System.nanoTime();
        Context result = delegate.extract(input, carrier, getter);
        requireInputContext(input, result);
        long deadline = nextConfigurationAttemptNanos(provider);
        result = extractBurst(input, carrier, getter, CALLS_PER_PHASE - 1);
        recordPhase("BURST", provider, deadline, phaseStart);
        System.out.println("OBI_AUTO_UNAVAILABLE\tBURST_END");

        waitUntil(deadline - DEADLINE_MARGIN_NANOS);
        System.out.println("OBI_AUTO_UNAVAILABLE\tMID_START");
        phaseStart = System.nanoTime();
        result = extractBurst(input, carrier, getter, CALLS_PER_PHASE);
        recordPhase("MID", provider, deadline, phaseStart);
        System.out.println("OBI_AUTO_UNAVAILABLE\tMID_END");

        waitUntil(deadline + DEADLINE_MARGIN_NANOS);
        System.out.println("OBI_AUTO_UNAVAILABLE\tRETRY_START");
        phaseStart = System.nanoTime();
        result = extractBurst(input, carrier, getter, CALLS_PER_PHASE);
        recordPhase("RETRY", provider, deadline, phaseStart);
        long retryDeadline = nextConfigurationAttemptNanos(provider);
        System.out.println("OBI_AUTO_UNAVAILABLE\tRETRY_END");

        waitUntil(retryDeadline + DEADLINE_MARGIN_NANOS);
        System.out.println("OBI_AUTO_UNAVAILABLE\tLIFETIME_START");
        phaseStart = System.nanoTime();
        result = extractBurst(input, carrier, getter, CALLS_PER_PHASE);
        recordPhase("LIFETIME", provider, retryDeadline, phaseStart);
        System.out.println("OBI_AUTO_UNAVAILABLE\tLIFETIME_END");
        return result;
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        output.append("ERROR\tauto-unavailable-exercise\tinterrupted");
        return delegate.extract(input, carrier, getter);
      } catch (Exception failure) {
        output.append("ERROR\tauto-unavailable-exercise\t" + token(failure.getClass().getName()));
        return delegate.extract(input, carrier, getter);
      } finally {
        restoreBlockedLookup(output);
      }
    }

    private <C> Context extractBurst(Context input, C carrier, TextMapGetter<C> getter, int calls) {
      Context result = input;
      for (int call = 0; call < calls; call++) {
        result = delegate.extract(input, carrier, getter);
        requireInputContext(input, result);
      }
      return result;
    }

    private static void requireInputContext(Context input, Context result) {
      if (result != input) {
        throw new IllegalStateException("unavailable native provider changed the input context");
      }
    }

    private static Object productionProvider() throws Exception {
      Class<?> bridge = Class.forName(BRIDGE_CLASS, true, null);
      ProviderState.requireBootstrap(bridge, "bridge");
      Field field = bridge.getDeclaredField("provider");
      field.setAccessible(true);
      Object reference = field.get(null);
      Object provider = reference.getClass().getMethod("get").invoke(reference);
      if (provider == null || !PROVIDER_CLASS.equals(provider.getClass().getName())) {
        throw new IllegalStateException("native remote-parent provider is not installed");
      }
      ProviderState.requireBootstrap(provider.getClass(), "native provider");
      return provider;
    }

    private static void markDirectLookup() throws Exception {
      Class<?> threadInfo = Class.forName(THREAD_INFO_CLASS, true, null);
      ProviderState.requireBootstrap(threadInfo, "thread lookup authority");
      int previous =
          ((Integer) threadInfo.getMethod("remoteParentLookupSource").invoke(null)).intValue();
      if (previous != 3) {
        throw new IllegalStateException("auto-unavailable lookup did not begin blocked");
      }
      threadInfo.getMethod("markRemoteParentDirectLookup").invoke(null);
      int source =
          ((Integer) threadInfo.getMethod("remoteParentLookupSource").invoke(null)).intValue();
      if (source != 1) {
        throw new IllegalStateException(
            "direct remote-parent lookup authority was not established");
      }
    }

    private static void restoreBlockedLookup(ProbeOutput output) {
      try {
        Class<?> threadInfo = Class.forName(THREAD_INFO_CLASS, true, null);
        threadInfo.getMethod("blockRemoteParentLookup").invoke(null);
        int source =
            ((Integer) threadInfo.getMethod("remoteParentLookupSource").invoke(null)).intValue();
        if (source != 3) {
          throw new IllegalStateException(
              "blocked remote-parent lookup authority was not restored");
        }
        output.append("AUTO_CLEANUP\tBLOCKED");
      } catch (Exception failure) {
        output.append("ERROR\tauto-unavailable-cleanup\t" + token(failure.getClass().getName()));
      }
    }

    private static long nextConfigurationAttemptNanos(Object provider) throws Exception {
      Field field = provider.getClass().getDeclaredField("nextConfigurationAttemptNanos");
      field.setAccessible(true);
      return field.getLong(provider);
    }

    private static long retryNanos(Object provider) throws Exception {
      Field field = provider.getClass().getDeclaredField("RETRY_NANOS");
      field.setAccessible(true);
      return field.getLong(null);
    }

    private void recordBaseline() throws Exception {
      Class<?> bridge = Class.forName(BRIDGE_CLASS, true, null);
      output.append(
          "AUTO_BASELINE\t"
              + bridge.getMethod("transportConfigurationSnapshot").invoke(null)
              + "\t"
              + bridge.getMethod("diagnosticsSnapshot").invoke(null));
    }

    private void recordPhase(
        String phase, Object provider, long previousDeadline, long phaseStartNanos)
        throws Exception {
      long now = System.nanoTime();
      long currentDeadline = nextConfigurationAttemptNanos(provider);
      Class<?> bridge = Class.forName(BRIDGE_CLASS, true, null);
      String transport = (String) bridge.getMethod("transportConfigurationSnapshot").invoke(null);
      String diagnostics = (String) bridge.getMethod("diagnosticsSnapshot").invoke(null);
      output.append(
          "AUTO\t"
              + phase
              + "\t"
              + (now - previousDeadline)
              + "\t"
              + (currentDeadline - previousDeadline)
              + "\t"
              + retryNanos(provider)
              + "\t"
              + CALLS_PER_PHASE
              + "\t"
              + (now - phaseStartNanos)
              + "\t"
              + transport
              + "\t"
              + diagnostics);
    }

    private static void waitUntil(long deadlineNanos) throws InterruptedException {
      while (true) {
        long remaining = deadlineNanos - System.nanoTime();
        if (remaining <= 0L) {
          return;
        }
        TimeUnit.NANOSECONDS.sleep(remaining);
      }
    }
  }

  private static final class HelperAbsentObiPropagator implements TextMapPropagator {
    private static final String ID_HEADER = "x-obi-probe-id";
    private static final String BRIDGE_ACCESS_CLASS =
        "io.opentelemetry.obi.java.extension.BootstrapBridgeAccess";
    private static final int CALLS_PER_PHASE = 8;
    private static final long DEADLINE_MARGIN_NANOS = TimeUnit.MILLISECONDS.toNanos(500L);

    private final TextMapPropagator delegate;
    private final ProbeOutput output;
    private final AtomicBoolean exercised = new AtomicBoolean();

    private HelperAbsentObiPropagator(TextMapPropagator delegate, ProbeOutput output) {
      this.delegate = delegate;
      this.output = output;
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
      Context input = context == null ? Context.root() : context;
      if (!"H".equals(getter.get(carrier, ID_HEADER)) || !exercised.compareAndSet(false, true)) {
        return delegate.extract(input, carrier, getter);
      }

      try {
        System.out.println("OBI_HELPER_ABSENT\tBURST_START");
        long lookupBefore = System.nanoTime();
        Context result = delegate.extract(input, carrier, getter);
        long lookupAfter = System.nanoTime();
        requireInputContext(input, result);
        Object bridge = productionBridge();
        long deadline = lookupDeadlineNanos(bridge);
        recordDeadline(bridge, deadline, lookupBefore, lookupAfter);
        result = extractBurst(input, carrier, getter, CALLS_PER_PHASE - 1);
        recordLookup("BURST", bridge, deadline);
        System.out.println("OBI_HELPER_ABSENT\tBURST_END");

        waitUntil(deadline - DEADLINE_MARGIN_NANOS);
        System.out.println("OBI_HELPER_ABSENT\tMID_START");
        result = extractBurst(input, carrier, getter, CALLS_PER_PHASE);
        recordLookup("MID", bridge, deadline);
        System.out.println("OBI_HELPER_ABSENT\tMID_END");

        waitUntil(deadline + DEADLINE_MARGIN_NANOS);
        System.out.println("OBI_HELPER_ABSENT\tRETRY_START");
        result = extractBurst(input, carrier, getter, CALLS_PER_PHASE);
        recordLookup("RETRY", bridge, deadline);
        System.out.println("OBI_HELPER_ABSENT\tRETRY_END");
        return result;
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        output.append("ERROR\thelper-absent-exercise\tinterrupted");
        return delegate.extract(input, carrier, getter);
      } catch (Exception failure) {
        output.append("ERROR\thelper-absent-exercise\t" + token(failure.getClass().getName()));
        return delegate.extract(input, carrier, getter);
      }
    }

    private <C> Context extractBurst(Context input, C carrier, TextMapGetter<C> getter, int calls) {
      Context result = input;
      for (int call = 0; call < calls; call++) {
        result = delegate.extract(input, carrier, getter);
        requireInputContext(input, result);
      }
      return result;
    }

    private static void requireInputContext(Context input, Context result) {
      if (result != input) {
        throw new IllegalStateException("helper-absent OBI propagator changed the input context");
      }
    }

    private Object productionBridge() throws Exception {
      Field field = delegate.getClass().getDeclaredField("bridge");
      field.setAccessible(true);
      Object bridge = field.get(delegate);
      if (bridge == null || !BRIDGE_ACCESS_CLASS.equals(bridge.getClass().getName())) {
        throw new IllegalStateException("raw OBI propagator does not use BootstrapBridgeAccess");
      }
      return bridge;
    }

    private static long lookupDeadlineNanos(Object bridge) throws Exception {
      Field field = bridge.getClass().getDeclaredField("nextLookupNanos");
      field.setAccessible(true);
      return field.getLong(bridge);
    }

    private static long lookupRetryNanos(Object bridge) throws Exception {
      Field field = bridge.getClass().getDeclaredField("LOOKUP_RETRY_NANOS");
      field.setAccessible(true);
      return field.getLong(null);
    }

    private void recordDeadline(
        Object bridge, long deadlineNanos, long lookupBefore, long lookupAfter) throws Exception {
      output.append(
          "DEADLINE\t"
              + (deadlineNanos - lookupBefore)
              + "\t"
              + (deadlineNanos - lookupAfter)
              + "\t"
              + lookupRetryNanos(bridge));
    }

    private void recordLookup(String phase, Object bridge, long deadlineNanos) throws Exception {
      Method snapshot = bridge.getClass().getDeclaredMethod("localDiagnosticsSnapshot");
      snapshot.setAccessible(true);
      output.append(
          "LOOKUP\t"
              + phase
              + "\t"
              + (System.nanoTime() - deadlineNanos)
              + "\t"
              + lookupRetryNanos(bridge)
              + "\t"
              + CALLS_PER_PHASE
              + "\t"
              + snapshot.invoke(null));
    }

    private static void waitUntil(long deadlineNanos) throws InterruptedException {
      while (true) {
        long remaining = deadlineNanos - System.nanoTime();
        if (remaining <= 0) {
          return;
        }
        TimeUnit.NANOSECONDS.sleep(remaining);
      }
    }
  }

  private static String requiredProperty(String name) {
    String value = System.getProperty(name);
    if (value == null || value.isEmpty()) {
      throw new IllegalStateException("missing system property " + name);
    }
    return value;
  }

  private static final class RecordingObiPropagator implements TextMapPropagator {
    private static final String ID_HEADER = "x-obi-probe-id";

    private final TextMapPropagator delegate;
    private final ProbeOutput output;
    private final ProviderState provider;
    private final String reextractId;
    private final boolean netty;
    private final boolean java21Concurrency;
    private final AtomicBoolean reextractionStarted = new AtomicBoolean();
    private final AtomicBoolean syntheticFaultExercised = new AtomicBoolean();
    private final ThreadLocal<Boolean> reextracting = new ThreadLocal<>();

    private RecordingObiPropagator(
        TextMapPropagator delegate,
        ProbeOutput output,
        ProviderState provider,
        String reextractId,
        boolean netty,
        boolean java21Concurrency) {
      this.delegate = delegate;
      this.output = output;
      this.provider = provider;
      this.reextractId = reextractId;
      this.netty = netty;
      this.java21Concurrency = java21Concurrency;
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
      Context input = context == null ? Context.root() : context;
      String id = probeId(carrier, getter);
      if (id == null) {
        return delegate.extract(input, carrier, getter);
      }

      exerciseSyntheticPostMarkFailure(input, carrier, getter, id);

      int invocation =
          EXTRACTION_CALLS.computeIfAbsent(id, ignored -> new AtomicInteger()).incrementAndGet();
      output.append("CALL\t" + id + "\t" + invocation);
      if ("T".equals(id)) {
        output.append("THREAD\tEXTRACT\tT\t" + Thread.currentThread().getId());
      } else if ("B".equals(id) && !netty) {
        output.append(
            "TIMING\tEXTRACT\tB\t" + Thread.currentThread().getId() + "\t" + System.nanoTime());
      }
      boolean reentry = Boolean.TRUE.equals(reextracting.get());
      if (reentry) {
        output.append("REENTRY\t" + id + "\t" + invocation);
      }
      Context first = extractPass(input, carrier, getter, id, invocation, 1);
      output.append(pass(id, invocation, 1, first));
      if (reentry) {
        return first.with(PROBE_ID_CONTEXT, id);
      }
      Context second = extractPass(first, carrier, getter, id, invocation, 2);
      output.append(pass(id, invocation, 2, second));
      Context result = second.with(PROBE_ID_CONTEXT, id);
      reextractRegisteredChain(carrier, getter, id);
      return result;
    }

    private <C> void reextractRegisteredChain(C carrier, TextMapGetter<C> getter, String id) {
      if (!id.equals(reextractId) || !reextractionStarted.compareAndSet(false, true)) {
        return;
      }
      reextracting.set(Boolean.TRUE);
      try {
        GlobalOpenTelemetry.get()
            .getPropagators()
            .getTextMapPropagator()
            .extract(Context.root(), carrier, getter);
      } finally {
        reextracting.remove();
      }
    }

    private <C> Context extractPass(
        Context context, C carrier, TextMapGetter<C> getter, String id, int invocation, int pass) {
      Invocation previous = provider.current.get();
      provider.current.set(new Invocation(id, invocation, pass));
      try {
        SyntheticReceiveScope receiveScope = provider.openSyntheticReceive(id, invocation, pass);
        try {
          return delegate.extract(context, carrier, getter);
        } finally {
          if (receiveScope != null) {
            receiveScope.close();
          }
        }
      } finally {
        if (previous == null) {
          provider.current.remove();
        } else {
          provider.current.set(previous);
        }
      }
    }

    private <C> void exerciseSyntheticPostMarkFailure(
        Context context, C carrier, TextMapGetter<C> getter, String id) {
      if (!provider.armSyntheticPostMarkFailure()
          || !syntheticFaultExercised.compareAndSet(false, true)) {
        return;
      }

      Invocation previous = provider.current.get();
      Object failedLifecycle;
      long failedSequence;
      try {
        extractPass(context, carrier, getter, id, 0, 0);
        throw new IllegalStateException("synthetic post-mark failure was not injected");
      } catch (SyntheticPostMarkFailure expected) {
        failedLifecycle = expected.lifecycle;
        failedSequence = expected.sequence;
      }
      boolean invocationRestored = provider.current.get() == previous;
      provider.verifySyntheticPostMarkFailure(failedLifecycle, failedSequence, invocationRestored);
    }

    private <C> String probeId(C carrier, TextMapGetter<C> getter) {
      String value = getter.get(carrier, ID_HEADER);
      if (java21ConcurrencyId(value)) {
        return value;
      }
      if ("A".equals(value)
          || "B".equals(value)
          || "C".equals(value)
          || "H".equals(value)
          || "M".equals(value)
          || "W".equals(value)
          || "F".equals(value)
          || "R".equals(value)
          || "S".equals(value)
          || "P".equals(value)
          || "Q".equals(value)
          || "D".equals(value)
          || "T".equals(value)) {
        return value;
      }
      return null;
    }

    private boolean java21ConcurrencyId(String value) {
      return java21Concurrency && OfficialAgentProbeExtension.java21ConcurrencyId(value);
    }

    private static String pass(String id, int invocation, int pass, Context context) {
      SpanContext spanContext = Span.fromContext(context).getSpanContext();
      return "PASS\t"
          + id
          + "\t"
          + invocation
          + "\t"
          + pass
          + "\t"
          + spanContext.getTraceId()
          + "\t"
          + spanContext.getSpanId()
          + "\t"
          + spanContext.isRemote()
          + "\t"
          + spanContext.isSampled();
    }
  }

  private static final class ProviderState implements InvocationHandler {
    private final ProbeOutput output;
    private final Map<String, ScenarioState> scenarios;
    private final Object missing;
    private final Object alreadyConsumed;
    private final ThreadLocal<Invocation> current = new ThreadLocal<>();
    private final CountDownLatch parallelTakes = new CountDownLatch(2);
    private final AuthorityVerifier authorityVerifier;
    private final ProviderCallCleanup providerCallCleanup;
    private final SyntheticReceiveFixture syntheticReceiveFixture;

    private ProviderState(
        ProbeOutput output,
        Map<String, ScenarioState> scenarios,
        Object missing,
        Object alreadyConsumed,
        AuthorityVerifier authorityVerifier,
        ProviderCallCleanup providerCallCleanup,
        SyntheticReceiveFixture syntheticReceiveFixture) {
      this.output = output;
      this.scenarios = scenarios;
      this.missing = missing;
      this.alreadyConsumed = alreadyConsumed;
      this.authorityVerifier = authorityVerifier;
      this.providerCallCleanup = providerCallCleanup;
      this.syntheticReceiveFixture = syntheticReceiveFixture;
    }

    private static ProviderState install(
        ProbeOutput output, boolean jetty, boolean netty, boolean java21Concurrency) {
      try {
        Class<?> bridge =
            Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", true, null);
        Class<?> providerType =
            Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentProvider", true, null);
        Class<?> recordType =
            Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentRecord", true, null);
        requireBootstrap(bridge, "bridge");
        requireBootstrap(providerType, "provider ABI");
        requireBootstrap(recordType, "record ABI");

        Method decode = recordType.getMethod("decode", byte[].class);
        Method statusOnly = recordType.getMethod("statusOnly", int.class);
        Object missing = statusOnly.invoke(null, STATUS_MISSING);
        Object stale = statusOnly.invoke(null, STATUS_STALE);
        Object malformed = statusOnly.invoke(null, STATUS_MALFORMED);
        Object alreadyConsumed = statusOnly.invoke(null, STATUS_ALREADY_CONSUMED);
        Map<String, ScenarioState> scenarios = new ConcurrentHashMap<>();
        scenarios.put(
            "A", new ScenarioState(decode.invoke(null, record(TRACE_A, PARENT_A, 1, 1L))));
        scenarios.put(
            "B", new ScenarioState(decode.invoke(null, record(TRACE_B, PARENT_B, 0, 2L))));
        scenarios.put("C", new ScenarioState(null));
        scenarios.put("H", new ScenarioState(null));
        scenarios.put(
            "M",
            new ScenarioState(decode.invoke(null, record(TRACE_MATCHING, PARENT_MATCHING, 1, 3L))));
        scenarios.put(
            "W",
            new ScenarioState(decode.invoke(null, record(TRACE_CONFLICT, PARENT_CONFLICT, 0, 4L))));
        scenarios.put(
            "F",
            new ScenarioState(
                decode.invoke(null, record(TRACE_MALFORMED_W3C, PARENT_MALFORMED_W3C, 1, 5L))));
        scenarios.put("R", ScenarioState.failure(malformed, "MALFORMED"));
        scenarios.put("S", ScenarioState.failure(stale, "STALE"));
        scenarios.put(
            "P", new ScenarioState(decode.invoke(null, record(TRACE_P, PARENT_P, 1, 6L))));
        scenarios.put(
            "Q", new ScenarioState(decode.invoke(null, record(TRACE_Q, PARENT_Q, 0, 7L))));
        scenarios.put(
            "D", new ScenarioState(decode.invoke(null, record(TRACE_D_OBI, PARENT_D_OBI, 1, 8L))));
        scenarios.put(
            "T", new ScenarioState(decode.invoke(null, record(TRACE_T, PARENT_T, 1, 9L))));
        if (java21Concurrency) {
          for (int index = 0; index < 16; index++) {
            addJava21Scenario(decode, scenarios, "V", index);
          }
          for (int index = 0; index < 4; index++) {
            addJava21Scenario(decode, scenarios, "P", index);
          }
        }

        AuthorityVerifier authorityVerifier = null;
        if (netty) {
          authorityVerifier = NettyAuthority.create();
        } else if (java21Concurrency) {
          authorityVerifier = Java21Authority.create();
        }
        ProviderCallCleanup providerCallCleanup = ProviderCallCleanup.create();
        SyntheticReceiveFixture syntheticReceiveFixture =
            jetty ? SyntheticReceiveFixture.create(output, providerCallCleanup) : null;

        ProviderState state =
            new ProviderState(
                output,
                scenarios,
                missing,
                alreadyConsumed,
                authorityVerifier,
                providerCallCleanup,
                syntheticReceiveFixture);
        Object provider = Proxy.newProxyInstance(null, new Class<?>[] {providerType}, state);
        requireBootstrap(provider.getClass(), "test provider");
        boolean installed =
            (Boolean) bridge.getMethod("installProvider", providerType).invoke(null, provider);
        if (!installed) {
          throw new IllegalStateException("bootstrap bridge rejected the test provider");
        }
        output.append("PROVIDER\tready\tbootstrap");
        return state;
      } catch (ReflectiveOperationException error) {
        throw new IllegalStateException("cannot install probe provider", error);
      }
    }

    private SyntheticReceiveScope openSyntheticReceive(String id, int invocation, int pass) {
      return syntheticReceiveFixture == null
          ? null
          : syntheticReceiveFixture.open(id, invocation, pass);
    }

    private boolean armSyntheticPostMarkFailure() {
      return syntheticReceiveFixture != null && syntheticReceiveFixture.armPostMarkFailure();
    }

    private void verifySyntheticPostMarkFailure(
        Object failedLifecycle, long failedSequence, boolean invocationRestored) {
      if (syntheticReceiveFixture != null) {
        syntheticReceiveFixture.verifyPostMarkFailure(
            failedLifecycle, failedSequence, invocationRestored);
      }
    }

    private static void addJava21Scenario(
        Method decode, Map<String, ScenarioState> scenarios, String kind, int index)
        throws ReflectiveOperationException {
      String firstWave = "W1" + kind + twoDigits(index);
      scenarios.put(
          firstWave,
          new ScenarioState(
              decode.invoke(
                  null,
                  record(
                      java21TraceId(firstWave),
                      java21ParentSpanId(firstWave),
                      java21Ordinal(firstWave) & 1,
                      100L + java21Ordinal(firstWave)))));
      scenarios.put("W2" + kind + twoDigits(index), new ScenarioState(null));
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) {
      String name = method.getName();
      if ("abiVersion".equals(name)) {
        return 1;
      }
      if ("transportConfiguration".equals(name)) {
        return DISABLED_TRANSPORT_CONFIGURATION;
      }
      if ("takeRemoteParent".equals(name)) {
        return operation("TAKE", true);
      }
      if ("discardRemoteParent".equals(name)) {
        return operation("DISCARD", false);
      }
      if ("close".equals(name)) {
        output.append("PROVIDER\tclose");
        return null;
      }
      if ("toString".equals(name)) {
        return "OfficialAgentProbeProvider";
      }
      if ("hashCode".equals(name)) {
        return System.identityHashCode(proxy);
      }
      if ("equals".equals(name)) {
        return args != null && args.length == 1 && proxy == args[0];
      }
      output.append("ERROR\tunexpected-provider-method\t" + token(name));
      return missing;
    }

    private Object operation(String operation, boolean take) {
      Object receiveContext;
      try {
        receiveContext = providerCallCleanup.takeReceiveContext();
      } catch (ReflectiveOperationException error) {
        output.append("ERROR\tprovider-receive-take\t" + token(error.getClass().getName()));
        return missing;
      }

      Object result;
      boolean receiveContextValid = false;
      boolean cleanupSucceeded = true;
      try {
        result = scopedOperation(operation, take);
      } finally {
        try {
          receiveContextValid = providerCallCleanup.finishReceiveContext(receiveContext);
        } catch (ReflectiveOperationException error) {
          cleanupSucceeded = false;
          output.append("ERROR\tprovider-receive-finish\t" + token(error.getClass().getName()));
        } finally {
          try {
            providerCallCleanup.clearSocketFileDescriptor();
          } catch (ReflectiveOperationException error) {
            cleanupSucceeded = false;
            output.append("ERROR\tprovider-receive-clear\t" + token(error.getClass().getName()));
          }
        }
      }
      if (!cleanupSucceeded || !receiveContextValid) {
        output.append("ERROR\tprovider-receive-invalid");
        return missing;
      }
      return result;
    }

    private Object scopedOperation(String operation, boolean take) {
      Invocation invocation = current.get();
      if (invocation == null) {
        output.append("ERROR\tunscoped-provider-" + operation.toLowerCase());
        return missing;
      }
      ScenarioState scenario = scenarios.get(invocation.id);
      if (scenario == null) {
        output.append("ERROR\tunknown-provider-scenario\t" + token(invocation.id));
        return missing;
      }
      if (authorityVerifier != null && !authorityVerifier.verify(output, operation, invocation)) {
        return missing;
      }

      ProviderResult result = scenario.claim(missing, alreadyConsumed);
      output.append(
          "PROVIDER\t"
              + operation
              + "\t"
              + invocation.id
              + "\t"
              + invocation.invocation
              + "\t"
              + invocation.pass
              + "\t"
              + result.status);
      if (take && result.valid && ("P".equals(invocation.id) || "Q".equals(invocation.id))) {
        parallelTakes.countDown();
        try {
          if (!parallelTakes.await(5, TimeUnit.SECONDS)) {
            output.append("ERROR\tparallel-provider-timeout\t" + invocation.id);
            return missing;
          }
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
          output.append("ERROR\tparallel-provider-interrupted\t" + invocation.id);
          return missing;
        }
      }
      return result.record;
    }

    private static void requireBootstrap(Class<?> type, String name) {
      if (type.getClassLoader() != null) {
        throw new IllegalStateException(name + " is not bootstrap loaded");
      }
    }
  }

  private interface AuthorityVerifier {
    boolean verify(ProbeOutput output, String operation, Invocation invocation);
  }

  private static final class NettyAuthority implements AuthorityVerifier {
    private static final int LOOKUP_TASK = 2;
    private static final int LOOKUP_BLOCKED = 3;

    private final Method lookupSource;
    private final Method lookupLifecycle;
    private final Method takeSocketFileDescriptor;
    private final Method lifecycleActive;

    private NettyAuthority(
        Method lookupSource,
        Method lookupLifecycle,
        Method takeSocketFileDescriptor,
        Method lifecycleActive) {
      this.lookupSource = lookupSource;
      this.lookupLifecycle = lookupLifecycle;
      this.takeSocketFileDescriptor = takeSocketFileDescriptor;
      this.lifecycleActive = lifecycleActive;
    }

    private static NettyAuthority create() throws ReflectiveOperationException {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      Class<?> lifecycle =
          Class.forName(
              "io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext$Lifecycle",
              true,
              null);
      ProviderState.requireBootstrap(threadInfo, "thread authority");
      ProviderState.requireBootstrap(lifecycle, "socket lifecycle");
      return new NettyAuthority(
          threadInfo.getMethod("remoteParentLookupSource"),
          threadInfo.getMethod("remoteParentLookupLifecycle"),
          threadInfo.getMethod("takeRemoteParentSocketFileDescriptor"),
          lifecycle.getMethod("active"));
    }

    @Override
    public boolean verify(ProbeOutput output, String operation, Invocation invocation) {
      try {
        int source = ((Integer) lookupSource.invoke(null)).intValue();
        Object lifecycle = lookupLifecycle.invoke(null);
        boolean active =
            lifecycle != null && Boolean.TRUE.equals(lifecycleActive.invoke(lifecycle));
        int socketFileDescriptor = ((Integer) takeSocketFileDescriptor.invoke(null)).intValue();
        long threadId = Thread.currentThread().getId();
        output.append(
            "AUTH\t"
                + operation
                + "\t"
                + invocation.id
                + "\t"
                + invocation.invocation
                + "\t"
                + invocation.pass
                + "\t"
                + source
                + "\t"
                + (active ? "LIVE" : "NONE")
                + "\t"
                + (lifecycle == null ? 0 : System.identityHashCode(lifecycle))
                + "\t"
                + socketFileDescriptor
                + "\t"
                + threadId);
        boolean firstPass = invocation.invocation == 1 && invocation.pass == 1;
        boolean valid;
        if (firstPass) {
          valid = source == LOOKUP_TASK && active && threadId > 0 && socketFileDescriptor >= 0;
        } else {
          valid =
              source == LOOKUP_BLOCKED
                  && !active
                  && lifecycle == null
                  && threadId > 0
                  && socketFileDescriptor == -1;
        }
        if (!valid) {
          output.append(
              "ERROR\tnetty-authority\t"
                  + invocation.id
                  + "\t"
                  + invocation.invocation
                  + "\t"
                  + invocation.pass);
        }
        return valid;
      } catch (ReflectiveOperationException error) {
        output.append("ERROR\tnetty-authority-reflection\t" + token(error.getClass().getName()));
        return false;
      }
    }
  }

  /** Mirrors the bootstrap provider's one-shot extraction cleanup around every probe call. */
  private static final class ProviderCallCleanup {
    private final Class<?> threadInfo;
    private final Method takeReceiveContext;
    private final Method finishReceiveContext;
    private final Method clearSocketFileDescriptor;

    private ProviderCallCleanup(
        Class<?> threadInfo,
        Method takeReceiveContext,
        Method finishReceiveContext,
        Method clearSocketFileDescriptor) {
      this.threadInfo = threadInfo;
      this.takeReceiveContext = takeReceiveContext;
      this.finishReceiveContext = finishReceiveContext;
      this.clearSocketFileDescriptor = clearSocketFileDescriptor;
    }

    private static ProviderCallCleanup create() throws ReflectiveOperationException {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      Class<?> receiveContext =
          Class.forName(
              "io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext$ReceiveContext",
              true,
              null);
      ProviderState.requireBootstrap(threadInfo, "provider receive cleanup");
      ProviderState.requireBootstrap(receiveContext, "provider receive context");
      return new ProviderCallCleanup(
          threadInfo,
          threadInfo.getMethod("takeRemoteParentReceiveContext"),
          threadInfo.getMethod("finishRemoteParentExtractionAndValidate", receiveContext),
          threadInfo.getMethod("clearRemoteParentSocketFileDescriptor"));
    }

    private Object takeReceiveContext() throws ReflectiveOperationException {
      return takeReceiveContext.invoke(null);
    }

    private boolean finishReceiveContext(Object receiveContext)
        throws ReflectiveOperationException {
      return ((Boolean) finishReceiveContext.invoke(null, receiveContext)).booleanValue();
    }

    private void clearSocketFileDescriptor() throws ReflectiveOperationException {
      clearSocketFileDescriptor.invoke(null);
    }
  }

  /** Jetty fixture for an exact extraction when the packaged helper transport is disabled. */
  private static final class SyntheticReceiveFixture {
    private final ProbeOutput output;
    private final ProviderCallCleanup providerCallCleanup;
    private final Constructor<?> lifecycleConstructor;
    private final Constructor<?> receiveContextConstructor;
    private final Class<?> observerType;
    private final Method lifecycleId;
    private final Method lifecycleActive;
    private final Method lifecycleInvalidate;
    private final Method bridgeEpoch;
    private final Method enabled;
    private final Method setEnabled;
    private final Method beginReceiveAttempt;
    private final Method markReceiveContext;
    private final Method clearLookup;
    private final Field lookupOverrideState;
    private final Field lookupLifecycleState;
    private final Field lookupBridgeEpochState;
    private final Field receiveContextState;
    private final Field socketContextState;
    private final AtomicLong nextSequence = new AtomicLong();
    private final AtomicBoolean injectPostMarkFailure = new AtomicBoolean();
    private final AtomicBoolean postMarkFailureArmed = new AtomicBoolean();

    private int activeScopes;

    private SyntheticReceiveFixture(
        ProbeOutput output,
        ProviderCallCleanup providerCallCleanup,
        Constructor<?> lifecycleConstructor,
        Constructor<?> receiveContextConstructor,
        Class<?> observerType,
        Method lifecycleId,
        Method lifecycleActive,
        Method lifecycleInvalidate,
        Method bridgeEpoch,
        Method enabled,
        Method setEnabled,
        Method beginReceiveAttempt,
        Method markReceiveContext,
        Method clearLookup,
        Field lookupOverrideState,
        Field lookupLifecycleState,
        Field lookupBridgeEpochState,
        Field receiveContextState,
        Field socketContextState) {
      this.output = output;
      this.providerCallCleanup = providerCallCleanup;
      this.lifecycleConstructor = lifecycleConstructor;
      this.receiveContextConstructor = receiveContextConstructor;
      this.observerType = observerType;
      this.lifecycleId = lifecycleId;
      this.lifecycleActive = lifecycleActive;
      this.lifecycleInvalidate = lifecycleInvalidate;
      this.bridgeEpoch = bridgeEpoch;
      this.enabled = enabled;
      this.setEnabled = setEnabled;
      this.beginReceiveAttempt = beginReceiveAttempt;
      this.markReceiveContext = markReceiveContext;
      this.clearLookup = clearLookup;
      this.lookupOverrideState = lookupOverrideState;
      this.lookupLifecycleState = lookupLifecycleState;
      this.lookupBridgeEpochState = lookupBridgeEpochState;
      this.receiveContextState = receiveContextState;
      this.socketContextState = socketContextState;
    }

    private static SyntheticReceiveFixture create(
        ProbeOutput output, ProviderCallCleanup providerCallCleanup)
        throws ReflectiveOperationException {
      Class<?> threadInfo = providerCallCleanup.threadInfo;
      Class<?> lifecycle =
          Class.forName(
              "io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext$Lifecycle",
              true,
              null);
      Class<?> receiveContext =
          Class.forName(
              "io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext$ReceiveContext",
              true,
              null);
      Class<?> observer =
          Class.forName(
              "io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext$ExtractionObserver",
              true,
              null);
      ProviderState.requireBootstrap(lifecycle, "synthetic Jetty lifecycle");
      ProviderState.requireBootstrap(receiveContext, "synthetic Jetty receive context");
      ProviderState.requireBootstrap(observer, "synthetic Jetty extraction observer");

      Constructor<?> receiveContextConstructor =
          receiveContext.getDeclaredConstructor(lifecycle, long.class, long.class, observer);
      receiveContextConstructor.setAccessible(true);
      if (Boolean.TRUE.equals(threadInfo.getMethod("isRemoteParentEnabled").invoke(null))) {
        throw new IllegalStateException("synthetic Jetty fixture requires disabled transport");
      }
      Field lookupOverrideState = threadLocalField(threadInfo, "remoteParentLookupOverride");
      Field lookupLifecycleState = threadLocalField(threadInfo, "remoteParentLookupLifecycle");
      Field lookupBridgeEpochState = threadLocalField(threadInfo, "remoteParentLookupBridgeEpoch");
      Field receiveContextState = threadLocalField(threadInfo, "remoteParentReceiveContext");
      Field socketContextState = threadLocalField(threadInfo, "remoteParentSocketContext");
      return new SyntheticReceiveFixture(
          output,
          providerCallCleanup,
          lifecycle.getConstructor(),
          receiveContextConstructor,
          observer,
          lifecycle.getMethod("id"),
          lifecycle.getMethod("active"),
          lifecycle.getMethod("invalidate"),
          threadInfo.getMethod("remoteParentBridgeEpoch"),
          threadInfo.getMethod("isRemoteParentEnabled"),
          threadInfo.getMethod("setRemoteParentEnabled", boolean.class),
          threadInfo.getMethod("beginRemoteParentReceiveAttempt"),
          threadInfo.getMethod("markRemoteParentDirectReceiveContext", receiveContext),
          threadInfo.getMethod("clearRemoteParentLookupSource"),
          lookupOverrideState,
          lookupLifecycleState,
          lookupBridgeEpochState,
          receiveContextState,
          socketContextState);
    }

    private SyntheticReceiveScope open(String id, int invocation, int pass) {
      Object lifecycle = null;
      boolean enabledScopeAcquired = false;
      boolean lookupStateMutated = false;
      boolean ownershipTransferred = false;
      try {
        long sequence = nextSequence.incrementAndGet();
        if (sequence <= 0L) {
          throw new IllegalStateException("synthetic receive sequence exhausted");
        }
        lifecycle = lifecycleConstructor.newInstance();
        SyntheticReceiveObserver observer = new SyntheticReceiveObserver();
        Object observerProxy =
            Proxy.newProxyInstance(null, new Class<?>[] {observerType}, observer);
        long epoch = ((Long) bridgeEpoch.invoke(null)).longValue();
        Object receiveContext =
            receiveContextConstructor.newInstance(lifecycle, sequence, epoch, observerProxy);
        observer.bind(receiveContext);

        acquireEnabledScope();
        enabledScopeAcquired = true;
        lookupStateMutated = true;
        beginReceiveAttempt.invoke(null);
        if (!Boolean.TRUE.equals(markReceiveContext.invoke(null, receiveContext))) {
          throw new IllegalStateException("cannot stage synthetic Jetty receive context");
        }
        if (injectPostMarkFailure.compareAndSet(true, false)) {
          throw new SyntheticPostMarkFailure(lifecycle, sequence);
        }
        long lifecycleIdentifier = ((Long) lifecycleId.invoke(lifecycle)).longValue();
        SyntheticReceiveScope scope =
            new SyntheticReceiveScope(
                this, id, invocation, pass, sequence, lifecycleIdentifier, lifecycle, observer);
        ownershipTransferred = true;
        return scope;
      } catch (ReflectiveOperationException error) {
        throw new IllegalStateException("cannot open synthetic Jetty receive", error);
      } finally {
        if (!ownershipTransferred) {
          cleanupFailedOpen(lifecycle, lookupStateMutated, enabledScopeAcquired);
        }
      }
    }

    private boolean armPostMarkFailure() {
      if (!postMarkFailureArmed.compareAndSet(false, true)) {
        return false;
      }
      injectPostMarkFailure.set(true);
      return true;
    }

    private void cleanupFailedOpen(
        Object lifecycle, boolean lookupStateMutated, boolean enabledScopeAcquired) {
      if (lookupStateMutated) {
        invokeCleanup(providerCallCleanup.clearSocketFileDescriptor, null, "socket");
        invokeCleanup(clearLookup, null, "lookup");
      }
      if (lifecycle != null) {
        invokeCleanup(lifecycleInvalidate, lifecycle, "lifecycle");
      }
      if (enabledScopeAcquired) {
        try {
          releaseEnabledScope();
        } catch (ReflectiveOperationException error) {
          output.append(
              "ERROR\tsynthetic-receive-open-cleanup-enabled\t"
                  + token(error.getClass().getName()));
        }
      }
    }

    private void invokeCleanup(Method method, Object target, String state) {
      try {
        method.invoke(target);
      } catch (ReflectiveOperationException error) {
        output.append(
            "ERROR\tsynthetic-receive-open-cleanup-"
                + state
                + "\t"
                + token(error.getClass().getName()));
      }
    }

    private void verifyPostMarkFailure(
        Object failedLifecycle, long failedSequence, boolean invocationRestored) {
      try {
        boolean enabledValue = Boolean.TRUE.equals(enabled.invoke(null));
        boolean lookupOverridePresent = threadLocalValue(lookupOverrideState) != null;
        boolean lookupLifecyclePresent = threadLocalValue(lookupLifecycleState) != null;
        boolean lookupBridgeEpochPresent = threadLocalValue(lookupBridgeEpochState) != null;
        boolean receiveContextPresent = threadLocalValue(receiveContextState) != null;
        boolean socketContextPresent = threadLocalValue(socketContextState) != null;
        boolean failedLifecycleActive =
            failedLifecycle != null && Boolean.TRUE.equals(lifecycleActive.invoke(failedLifecycle));
        boolean cleared =
            !enabledValue
                && !lookupOverridePresent
                && !lookupLifecyclePresent
                && !lookupBridgeEpochPresent
                && !receiveContextPresent
                && !socketContextPresent
                && !failedLifecycleActive
                && activeScopes == 0
                && failedSequence == 1L
                && invocationRestored;
        if (!cleared) {
          output.append("ERROR\tsynthetic-post-mark-failure-not-cleared");
          throw new IllegalStateException("synthetic post-mark failure leaked state");
        }
        output.append(
            "SYNTHETIC_FAULT\tJETTY\tenabled=false,lookup=false,lifecycle=false,epoch=false,"
                + "receive=false,socket=false,failed_lifecycle=false,active_scopes=0,"
                + "invocation_restored=true,failed_sequence=1");
      } catch (ReflectiveOperationException error) {
        throw new IllegalStateException("cannot verify synthetic post-mark cleanup", error);
      }
    }

    private static Field threadLocalField(Class<?> owner, String name)
        throws ReflectiveOperationException {
      Field field = owner.getDeclaredField(name);
      field.setAccessible(true);
      return field;
    }

    private static Object threadLocalValue(Field field) throws IllegalAccessException {
      return ((ThreadLocal<?>) field.get(null)).get();
    }

    private synchronized void acquireEnabledScope() throws ReflectiveOperationException {
      if (activeScopes == 0) {
        if (Boolean.TRUE.equals(enabled.invoke(null))) {
          throw new IllegalStateException("synthetic Jetty transport became enabled");
        }
        setEnabled.invoke(null, Boolean.TRUE);
      }
      activeScopes++;
    }

    private synchronized void releaseEnabledScope() throws ReflectiveOperationException {
      if (activeScopes <= 0) {
        throw new IllegalStateException("synthetic Jetty scope underflow");
      }
      activeScopes--;
      if (activeScopes == 0) {
        setEnabled.invoke(null, Boolean.FALSE);
      }
    }

    private void close(SyntheticReceiveScope scope) {
      boolean lifecycleStillActive = true;
      try {
        providerCallCleanup.clearSocketFileDescriptor();
        clearLookup.invoke(null);
        lifecycleInvalidate.invoke(scope.lifecycle);
        lifecycleStillActive = Boolean.TRUE.equals(lifecycleActive.invoke(scope.lifecycle));
      } catch (ReflectiveOperationException error) {
        output.append("ERROR\tsynthetic-receive-close\t" + token(error.getClass().getName()));
      } finally {
        try {
          releaseEnabledScope();
        } catch (ReflectiveOperationException error) {
          output.append("ERROR\tsynthetic-receive-disable\t" + token(error.getClass().getName()));
        }
      }
      int observations = scope.observer.observations.get();
      if (observations < 0 || observations > 1 || lifecycleStillActive) {
        output.append(
            "ERROR\tsynthetic-receive-lifecycle\t"
                + scope.id
                + "\t"
                + scope.invocation
                + "\t"
                + scope.pass);
      }
      output.append(
          "SYNTHETIC\tJETTY\t"
              + scope.id
              + "\t"
              + scope.invocation
              + "\t"
              + scope.pass
              + "\t"
              + scope.sequence
              + "\t"
              + scope.lifecycleId
              + "\t"
              + observations
              + "\t"
              + lifecycleStillActive);
    }
  }

  private static final class SyntheticPostMarkFailure extends RuntimeException {
    private final Object lifecycle;
    private final long sequence;

    private SyntheticPostMarkFailure(Object lifecycle, long sequence) {
      super("injected synthetic post-mark failure");
      this.lifecycle = lifecycle;
      this.sequence = sequence;
    }
  }

  private static final class SyntheticReceiveScope implements AutoCloseable {
    private final SyntheticReceiveFixture fixture;
    private final String id;
    private final int invocation;
    private final int pass;
    private final long sequence;
    private final long lifecycleId;
    private final Object lifecycle;
    private final SyntheticReceiveObserver observer;
    private final AtomicBoolean closed = new AtomicBoolean();

    private SyntheticReceiveScope(
        SyntheticReceiveFixture fixture,
        String id,
        int invocation,
        int pass,
        long sequence,
        long lifecycleId,
        Object lifecycle,
        SyntheticReceiveObserver observer) {
      this.fixture = fixture;
      this.id = id;
      this.invocation = invocation;
      this.pass = pass;
      this.sequence = sequence;
      this.lifecycleId = lifecycleId;
      this.lifecycle = lifecycle;
      this.observer = observer;
    }

    @Override
    public void close() {
      if (closed.compareAndSet(false, true)) {
        fixture.close(this);
      }
    }
  }

  private static final class SyntheticReceiveObserver implements InvocationHandler {
    private final AtomicBoolean consumed = new AtomicBoolean();
    private final AtomicInteger observations = new AtomicInteger();
    private Object receiveContext;

    private void bind(Object receiveContext) {
      this.receiveContext = receiveContext;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) {
      String name = method.getName();
      if ("extractionObserved".equals(name)) {
        observations.incrementAndGet();
        return args != null
            && args.length == 1
            && args[0] == receiveContext
            && consumed.compareAndSet(false, true);
      }
      if ("toString".equals(name)) {
        return "SyntheticJettyReceiveObserver";
      }
      if ("hashCode".equals(name)) {
        return System.identityHashCode(proxy);
      }
      if ("equals".equals(name)) {
        return args != null && args.length == 1 && proxy == args[0];
      }
      throw new IllegalStateException("unexpected synthetic observer method " + token(name));
    }
  }

  private static final class Java21Authority implements AuthorityVerifier {
    private static final int LOOKUP_TASK = 2;
    private static final int LOOKUP_BLOCKED = 3;

    private final Method lookupSource;
    private final Method directAuthority;
    private final Method lookupLifecycle;
    private final Method takeSocketFileDescriptor;
    private final Method lifecycleActive;
    private final Method nativeThreadId;
    private final Field taskRelayState;
    private final Field socketContext;

    private Java21Authority(
        Method lookupSource,
        Method directAuthority,
        Method lookupLifecycle,
        Method takeSocketFileDescriptor,
        Method lifecycleActive,
        Method nativeThreadId,
        Field taskRelayState,
        Field socketContext) {
      this.lookupSource = lookupSource;
      this.directAuthority = directAuthority;
      this.lookupLifecycle = lookupLifecycle;
      this.takeSocketFileDescriptor = takeSocketFileDescriptor;
      this.lifecycleActive = lifecycleActive;
      this.nativeThreadId = nativeThreadId;
      this.taskRelayState = taskRelayState;
      this.socketContext = socketContext;
    }

    private static Java21Authority create() throws ReflectiveOperationException {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      Class<?> storage =
          Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
      Class<?> lifecycle =
          Class.forName(
              "io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext$Lifecycle",
              true,
              null);
      ProviderState.requireBootstrap(threadInfo, "Java 21 thread authority");
      ProviderState.requireBootstrap(storage, "Java 21 task storage");
      ProviderState.requireBootstrap(lifecycle, "Java 21 socket lifecycle");
      Field taskRelayState = threadInfo.getDeclaredField("taskRelayState");
      taskRelayState.setAccessible(true);
      Field socketContext = threadInfo.getDeclaredField("remoteParentSocketContext");
      socketContext.setAccessible(true);
      return new Java21Authority(
          threadInfo.getMethod("remoteParentLookupSource"),
          threadInfo.getMethod("hasRemoteParentDirectReceiveAuthority"),
          threadInfo.getMethod("remoteParentLookupLifecycle"),
          threadInfo.getMethod("takeRemoteParentSocketFileDescriptor"),
          lifecycle.getMethod("active"),
          storage.getMethod("currentThreadId"),
          taskRelayState,
          socketContext);
    }

    @Override
    public boolean verify(ProbeOutput output, String operation, Invocation invocation) {
      try {
        int source = ((Integer) lookupSource.invoke(null)).intValue();
        boolean direct = ((Boolean) directAuthority.invoke(null)).booleanValue();
        Object lifecycle = lookupLifecycle.invoke(null);
        boolean active =
            lifecycle != null && Boolean.TRUE.equals(lifecycleActive.invoke(lifecycle));
        boolean socketContextPresent = ((ThreadLocal<?>) socketContext.get(null)).get() != null;
        int socketFileDescriptor = ((Integer) takeSocketFileDescriptor.invoke(null)).intValue();
        long javaThreadId = Thread.currentThread().getId();
        long nativeThread = ((Long) nativeThreadId.invoke(null)).longValue();
        Object relay = ((ThreadLocal<?>) taskRelayState.get(null)).get();
        boolean exact = relay != null && booleanField(relay, "currentExact");
        int lifecycleIdentity = lifecycle == null ? 0 : System.identityHashCode(lifecycle);
        output.append(
            "AUTH\tJAVA21\t"
                + operation
                + "\t"
                + invocation.id
                + "\t"
                + invocation.invocation
                + "\t"
                + invocation.pass
                + "\t"
                + source
                + "\t"
                + direct
                + "\t"
                + (active ? "LIVE" : "NONE")
                + "\t"
                + lifecycleIdentity
                + "\t"
                + socketFileDescriptor
                + "\t"
                + exact
                + "\t"
                + socketContextPresent
                + "\t"
                + javaThreadId
                + "\t"
                + nativeThread);

        boolean firstWave = invocation.id.startsWith("W1");
        boolean firstPass = invocation.invocation == 1 && invocation.pass == 1;
        boolean valid;
        if (firstWave) {
          valid =
              source == LOOKUP_TASK
                  && !direct
                  && active
                  && lifecycleIdentity != 0
                  && exact
                  && javaThreadId > 0
                  && nativeThread > 0
                  && (firstPass
                      ? socketContextPresent
                          && socketFileDescriptor == 200 + java21Ordinal(invocation.id)
                      : !socketContextPresent && socketFileDescriptor == -1);
        } else {
          valid =
              source == LOOKUP_BLOCKED
                  && !direct
                  && !active
                  && lifecycleIdentity == 0
                  && socketFileDescriptor == -1
                  && !exact
                  && !socketContextPresent
                  && javaThreadId > 0
                  && nativeThread > 0;
        }
        if (!valid) {
          output.append(
              "ERROR\tjava21-authority\t"
                  + invocation.id
                  + "\t"
                  + invocation.invocation
                  + "\t"
                  + invocation.pass);
        }
        return valid;
      } catch (ReflectiveOperationException error) {
        output.append("ERROR\tjava21-authority-reflection\t" + token(error.getClass().getName()));
        return false;
      }
    }

    private static boolean booleanField(Object target, String name)
        throws ReflectiveOperationException {
      Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      return field.getBoolean(target);
    }
  }

  private static final class Invocation {
    private final String id;
    private final int invocation;
    private final int pass;

    private Invocation(String id, int invocation, int pass) {
      this.id = id;
      this.invocation = invocation;
      this.pass = pass;
    }
  }

  private static final class ScenarioState {
    private final Object valid;
    private final Object failure;
    private final String failureStatus;
    private final AtomicBoolean claimed = new AtomicBoolean();

    private ScenarioState(Object valid) {
      this.valid = valid;
      this.failure = null;
      this.failureStatus = null;
    }

    private ScenarioState(Object failure, String failureStatus) {
      this.valid = null;
      this.failure = failure;
      this.failureStatus = failureStatus;
    }

    private static ScenarioState failure(Object record, String status) {
      return new ScenarioState(record, status);
    }

    private ProviderResult claim(Object missing, Object alreadyConsumed) {
      if (valid == null) {
        if (failure != null) {
          return new ProviderResult(failure, failureStatus, false);
        }
        return new ProviderResult(missing, "MISSING", false);
      }
      if (claimed.compareAndSet(false, true)) {
        return new ProviderResult(valid, "VALID", true);
      }
      return new ProviderResult(alreadyConsumed, "ALREADY_CONSUMED", false);
    }
  }

  private static final class ProviderResult {
    private final Object record;
    private final String status;
    private final boolean valid;

    private ProviderResult(Object record, String status, boolean valid) {
      this.record = record;
      this.status = status;
      this.valid = valid;
    }
  }

  private static boolean java21ConcurrencyId(String value) {
    if (value == null || value.length() != 5 || value.charAt(0) != 'W') {
      return false;
    }
    char wave = value.charAt(1);
    char kind = value.charAt(2);
    char tens = value.charAt(3);
    char ones = value.charAt(4);
    if ((wave != '1' && wave != '2')
        || (kind != 'V' && kind != 'P')
        || tens < '0'
        || tens > '9'
        || ones < '0'
        || ones > '9') {
      return false;
    }
    int index = (tens - '0') * 10 + (ones - '0');
    return kind == 'V' ? index < 16 : index < 4;
  }

  private static int java21Ordinal(String id) {
    if (!java21ConcurrencyId(id)) {
      throw new IllegalArgumentException("invalid Java 21 concurrency id " + token(id));
    }
    int index = (id.charAt(3) - '0') * 10 + (id.charAt(4) - '0');
    return id.charAt(2) == 'V' ? index : 16 + index;
  }

  private static String java21TraceId(String id) {
    return paddedHex(java21Ordinal(id) + 1L, 32);
  }

  private static String java21ParentSpanId(String id) {
    return paddedHex(java21Ordinal(id) + 1L, 16);
  }

  private static String twoDigits(int value) {
    if (value < 0 || value > 99) {
      throw new IllegalArgumentException("two-digit value out of range");
    }
    return value < 10 ? "0" + value : Integer.toString(value);
  }

  private static String paddedHex(long value, int width) {
    String hex = Long.toHexString(value);
    if (hex.length() > width) {
      throw new IllegalArgumentException("hex value exceeds width");
    }
    StringBuilder result = new StringBuilder(width);
    for (int index = hex.length(); index < width; index++) {
      result.append('0');
    }
    return result.append(hex).toString();
  }

  private static byte[] record(String traceId, String parentSpanId, int flags, long generation) {
    byte[] bytes = new byte[64];
    bytes[0] = 'O';
    bytes[1] = 'B';
    bytes[2] = 'I';
    bytes[3] = 'J';
    littleEndianShort(bytes, 4, 1);
    littleEndianShort(bytes, 6, bytes.length);
    bytes[8] = STATUS_VALID;
    bytes[9] = (byte) flags;
    decodeHex(traceId, bytes, 16);
    decodeHex(parentSpanId, bytes, 32);
    littleEndianLong(bytes, 40, generation);
    littleEndianLong(bytes, 48, generation + 10L);
    return bytes;
  }

  private static void littleEndianShort(byte[] bytes, int offset, int value) {
    bytes[offset] = (byte) value;
    bytes[offset + 1] = (byte) (value >>> 8);
  }

  private static void littleEndianLong(byte[] bytes, int offset, long value) {
    for (int index = 0; index < Long.BYTES; index++) {
      bytes[offset + index] = (byte) (value >>> (index * Byte.SIZE));
    }
  }

  private static void decodeHex(String value, byte[] destination, int offset) {
    if ((value.length() & 1) != 0) {
      throw new IllegalArgumentException("odd-length test identifier");
    }
    for (int index = 0; index < value.length() / 2; index++) {
      int high = Character.digit(value.charAt(index * 2), 16);
      int low = Character.digit(value.charAt(index * 2 + 1), 16);
      if (high < 0 || low < 0) {
        throw new IllegalArgumentException("non-hex test identifier");
      }
      destination[offset + index] = (byte) ((high << 4) | low);
    }
  }

  private static final class CapturingSpanProcessor implements SpanProcessor {
    private static final AttributeKey<String> PROBE_ID = AttributeKey.stringKey("obi.probe.id");
    private static final AttributeKey<String> HTTP_ROUTE = AttributeKey.stringKey("http.route");
    private static final AttributeKey<String> HTTP_METHOD =
        AttributeKey.stringKey("http.request.method");
    private static final AttributeKey<String> URL_SCHEME = AttributeKey.stringKey("url.scheme");
    private static final AttributeKey<String> URL_PATH = AttributeKey.stringKey("url.path");
    private static final AttributeKey<Long> HTTP_STATUS =
        AttributeKey.longKey("http.response.status_code");
    private static final AttributeKey<String> PROTOCOL_VERSION =
        AttributeKey.stringKey("network.protocol.version");

    private final ProbeOutput output;
    private final boolean captureHttp;
    private final boolean captureHelperAbsent;
    private final boolean captureJava21Concurrency;

    private CapturingSpanProcessor(
        ProbeOutput output,
        boolean captureHttp,
        boolean captureHelperAbsent,
        boolean captureJava21Concurrency) {
      this.output = output;
      this.captureHttp = captureHttp;
      this.captureHelperAbsent = captureHelperAbsent;
      this.captureJava21Concurrency = captureJava21Concurrency;
    }

    @Override
    public void onStart(Context parentContext, ReadWriteSpan span) {
      String id = parentContext.get(PROBE_ID_CONTEXT);
      if (id != null && span.getKind() == SpanKind.SERVER) {
        span.setAttribute(PROBE_ID, id);
        if (captureHttp || captureJava21Concurrency) {
          output.append("THREAD\tSPAN_START\t" + id + "\t" + Thread.currentThread().getId());
        } else if ("T".equals(id)) {
          output.append("THREAD\tSPAN_START\tT\t" + Thread.currentThread().getId());
        } else if ("B".equals(id)) {
          output.append(
              "TIMING\tSPAN_START\tB\t"
                  + Thread.currentThread().getId()
                  + "\t"
                  + System.nanoTime());
        }
      }
    }

    @Override
    public boolean isStartRequired() {
      return true;
    }

    @Override
    public void onEnd(ReadableSpan readableSpan) {
      if (readableSpan.getKind() != SpanKind.SERVER) {
        return;
      }
      SpanData span = readableSpan.toSpanData();
      String id = span.getAttributes().get(PROBE_ID);
      if (id == null && captureHelperAbsent) {
        if (TRACE_W3C_ONLY.equals(span.getTraceId())) {
          id = "H";
        }
      }
      SpanContext parent = span.getParentSpanContext();
      String route = span.getAttributes().get(HTTP_ROUTE);
      boolean routePresent = span.getAttributes().asMap().containsKey(HTTP_ROUTE);
      output.append(
          "SPAN\t"
              + token(id)
              + "\t"
              + span.getTraceId()
              + "\t"
              + span.getSpanId()
              + "\t"
              + span.getParentSpanId()
              + "\t"
              + parent.isRemote()
              + "\t"
              + parent.isSampled()
              + "\t"
              + span.getSpanContext().isSampled()
              + "\t"
              + token(span.getInstrumentationScopeInfo().getName())
              + "\t"
              + (captureHttp ? Boolean.toString(routePresent) : token(route)));
      if (captureHttp) {
        Long status = span.getAttributes().get(HTTP_STATUS);
        output.append(
            "HTTP\t"
                + token(id)
                + "\t"
                + token(span.getAttributes().get(HTTP_METHOD))
                + "\t"
                + token(span.getAttributes().get(URL_SCHEME))
                + "\t"
                + reversibleToken(span.getAttributes().get(URL_PATH))
                + "\t"
                + (status == null ? "-" : status.toString())
                + "\t"
                + token(span.getAttributes().get(PROTOCOL_VERSION)));
      }
    }

    @Override
    public boolean isEndRequired() {
      return true;
    }

    @Override
    public CompletableResultCode shutdown() {
      output.append("PROCESSOR\tshutdown");
      return CompletableResultCode.ofSuccess();
    }

    @Override
    public CompletableResultCode forceFlush() {
      return CompletableResultCode.ofSuccess();
    }
  }

  private static String token(String value) {
    if (value == null || value.isEmpty()) {
      return "-";
    }
    StringBuilder result = new StringBuilder(value.length());
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      if ((character >= 'a' && character <= 'z')
          || (character >= 'A' && character <= 'Z')
          || (character >= '0' && character <= '9')
          || character == '.'
          || character == '_'
          || character == '-') {
        result.append(character);
      } else {
        result.append('_');
      }
    }
    return result.toString();
  }

  private static String reversibleToken(String value) {
    if (value == null) {
      return "-";
    }
    return Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private static final class ProbeOutput {
    private final Path path;

    private ProbeOutput(String value) {
      path = Paths.get(value).toAbsolutePath().normalize();
      try {
        Path parent = path.getParent();
        if (parent != null) {
          Files.createDirectories(parent);
        }
        Files.deleteIfExists(path);
        Files.createFile(path);
      } catch (IOException error) {
        throw new IllegalStateException("cannot initialize probe output", error);
      }
    }

    private synchronized void append(String line) {
      try {
        Files.write(
            path, (line + "\n").getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);
      } catch (IOException error) {
        throw new IllegalStateException("cannot write probe output", error);
      }
    }
  }
}
