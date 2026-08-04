/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension.probe;

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
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Test-only official-agent extension for the isolated Jetty runtime probe. */
public final class OfficialAgentProbeExtension implements AutoConfigurationCustomizerProvider {
  private static final String OUTPUT_PROPERTY = "obi.test.official.agent.probe.output";
  private static final String RAW_OBI_PROPAGATOR =
      "io.opentelemetry.obi.java.extension.ObiRemoteParentPropagator";
  private static final int STATUS_VALID = 1;
  private static final int STATUS_MISSING = 2;
  private static final int STATUS_ALREADY_CONSUMED = 9;
  private static final long DISABLED_TRANSPORT_CONFIGURATION = 0x4f0200000003030dL;

  private static final String TRACE_A = "11111111111111111111111111111111";
  private static final String PARENT_A = "2222222222222222";
  private static final String TRACE_B = "33333333333333333333333333333333";
  private static final String PARENT_B = "4444444444444444";
  private static final String TRACE_CONFLICT = "77777777777777777777777777777777";
  private static final String PARENT_CONFLICT = "8888888888888888";
  private static final String TRACE_P = "99999999999999999999999999999999";
  private static final String PARENT_P = "aaaaaaaaaaaaaaaa";
  private static final String TRACE_Q = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  private static final String PARENT_Q = "cccccccccccccccc";
  private static final String TRACE_D_OBI = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";
  private static final String PARENT_D_OBI = "abababababababab";

  private static final ContextKey<String> PROBE_ID_CONTEXT =
      ContextKey.named("obi-official-agent-probe-id");
  private static final ConcurrentHashMap<String, AtomicInteger> EXTRACTION_CALLS =
      new ConcurrentHashMap<>();
  private static final AtomicInteger OBI_WRAPS = new AtomicInteger();

  @Override
  public int order() {
    // Wrap the raw OBI propagator before the production extension adds selection recording.
    return Integer.MIN_VALUE;
  }

  @Override
  public void customize(AutoConfigurationCustomizer customizer) {
    ProbeOutput output = new ProbeOutput(requiredProperty(OUTPUT_PROPERTY));
    output.append("EXTENSION\tready");
    ProviderState provider = ProviderState.install(output);
    customizer.addPropagatorCustomizer(
        (propagator, config) -> wrapObiPropagator(propagator, output, provider));
    customizer.addTracerProviderCustomizer(
        (builder, config) -> builder.addSpanProcessor(new CapturingSpanProcessor(output)));
  }

  private static TextMapPropagator wrapObiPropagator(
      TextMapPropagator propagator, ProbeOutput output, ProviderState provider) {
    if (!RAW_OBI_PROPAGATOR.equals(propagator.getClass().getName())) {
      return propagator;
    }
    int wraps = OBI_WRAPS.incrementAndGet();
    output.append("WRAP\tobi\t" + wraps);
    if (wraps != 1) {
      output.append("ERROR\tmultiple-obi-propagators");
    }
    return new RecordingObiPropagator(propagator, output, provider);
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

    private RecordingObiPropagator(
        TextMapPropagator delegate, ProbeOutput output, ProviderState provider) {
      this.delegate = delegate;
      this.output = output;
      this.provider = provider;
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

      int invocation =
          EXTRACTION_CALLS.computeIfAbsent(id, ignored -> new AtomicInteger()).incrementAndGet();
      output.append("CALL\t" + id + "\t" + invocation);
      Context first = extractPass(input, carrier, getter, id, invocation, 1);
      output.append(pass(id, invocation, 1, first));
      Context second = extractPass(first, carrier, getter, id, invocation, 2);
      output.append(pass(id, invocation, 2, second));
      return second.with(PROBE_ID_CONTEXT, id);
    }

    private <C> Context extractPass(
        Context context, C carrier, TextMapGetter<C> getter, String id, int invocation, int pass) {
      Invocation previous = provider.current.get();
      provider.current.set(new Invocation(id, invocation, pass));
      try {
        return delegate.extract(context, carrier, getter);
      } finally {
        if (previous == null) {
          provider.current.remove();
        } else {
          provider.current.set(previous);
        }
      }
    }

    private static <C> String probeId(C carrier, TextMapGetter<C> getter) {
      String value = getter.get(carrier, ID_HEADER);
      if ("A".equals(value)
          || "B".equals(value)
          || "C".equals(value)
          || "W".equals(value)
          || "P".equals(value)
          || "Q".equals(value)
          || "D".equals(value)) {
        return value;
      }
      return null;
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

    private ProviderState(
        ProbeOutput output,
        Map<String, ScenarioState> scenarios,
        Object missing,
        Object alreadyConsumed) {
      this.output = output;
      this.scenarios = scenarios;
      this.missing = missing;
      this.alreadyConsumed = alreadyConsumed;
    }

    private static ProviderState install(ProbeOutput output) {
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
        Object alreadyConsumed = statusOnly.invoke(null, STATUS_ALREADY_CONSUMED);
        Map<String, ScenarioState> scenarios = new ConcurrentHashMap<>();
        scenarios.put(
            "A", new ScenarioState(decode.invoke(null, record(TRACE_A, PARENT_A, 1, 1L))));
        scenarios.put(
            "B", new ScenarioState(decode.invoke(null, record(TRACE_B, PARENT_B, 0, 2L))));
        scenarios.put("C", new ScenarioState(null));
        scenarios.put(
            "W",
            new ScenarioState(decode.invoke(null, record(TRACE_CONFLICT, PARENT_CONFLICT, 0, 3L))));
        scenarios.put(
            "P", new ScenarioState(decode.invoke(null, record(TRACE_P, PARENT_P, 1, 4L))));
        scenarios.put(
            "Q", new ScenarioState(decode.invoke(null, record(TRACE_Q, PARENT_Q, 0, 5L))));
        scenarios.put(
            "D", new ScenarioState(decode.invoke(null, record(TRACE_D_OBI, PARENT_D_OBI, 1, 6L))));

        ProviderState state = new ProviderState(output, scenarios, missing, alreadyConsumed);
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
        return "OfficialAgentJettyProbeProvider";
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
    private final AtomicBoolean claimed = new AtomicBoolean();

    private ScenarioState(Object valid) {
      this.valid = valid;
    }

    private ProviderResult claim(Object missing, Object alreadyConsumed) {
      if (valid == null) {
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

    private final ProbeOutput output;

    private CapturingSpanProcessor(ProbeOutput output) {
      this.output = output;
    }

    @Override
    public void onStart(Context parentContext, ReadWriteSpan span) {
      String id = parentContext.get(PROBE_ID_CONTEXT);
      if (id != null && span.getKind() == SpanKind.SERVER) {
        span.setAttribute(PROBE_ID, id);
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
      SpanContext parent = span.getParentSpanContext();
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
              + token(span.getInstrumentationScopeInfo().getName()));
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
