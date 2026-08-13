/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.examples;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/** Deterministic application-side half of the real numeric PID/TID reuse fixture. */
final class PidReuseProbe {
  private static final Duration CONTROL_TIMEOUT = Duration.ofSeconds(120);
  private static final Duration POLL_INTERVAL = Duration.ofMillis(10);
  private static final int RECORD_SIZE = 64;
  private static final int STATUS_VALID = 1;
  private static final int STATUS_UNSUPPORTED = 4;
  private static final int STATUS_AMBIGUOUS = 7;
  private static final String RECOVERY_TRACE_ID = "22222222222222222222222222222222";
  private static final String RECOVERY_SPAN_ID = "bbbbbbbbbbbbbbbb";
  private static final String W3C_TRACE_ID = "33333333333333333333333333333333";
  private static final String W3C_SPAN_ID = "cccccccccccccccc";
  private static final Set<PosixFilePermission> DIRECTORY_PERMISSIONS =
      EnumSet.of(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE,
          PosixFilePermission.OWNER_EXECUTE);
  private static final Set<PosixFilePermission> FILE_PERMISSIONS =
      EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
  private static final AtomicLong NEXT_TEMPORARY = new AtomicLong();

  private PidReuseProbe() {}

  static boolean runIfConfigured() throws Exception {
    Config config = parseConfig(System.getenv());
    if (config == null) {
      return false;
    }
    validateControlDirectory(config.controlDirectory());
    awaitBridgeInitialization();
    config = config.withTransport(selectedForcedTransport());
    RuntimePrivilegeAttestation attestation = readRuntimePrivilegeAttestation();
    publish(
        config.controlDirectory(),
        config.phase().equals("A") ? "jvm-a-attestation" : "jvm-b-attestation",
        attestation.payload());
    if (config.phase().equals("A")) {
      runPhaseA(config);
      return true;
    }
    runPhaseB(config);
    return false;
  }

  private static void runPhaseA(Config config) throws Exception {
    publish(config.controlDirectory(), "java-a-ready", "java-a-ready-v1\n");
    await(config.controlDirectory(), "a-stage", "a-stage-v1\n");
    if (config.transport().equals("getsockopt")) {
      int emit = emit(config.socketFileDescriptor());
      if (emit != 1) {
        throw new IllegalStateException("phase A primary acknowledgement failed");
      }
    }
    publish(config.controlDirectory(), "a-armed", "a-armed-v1\n");
    await(config.controlDirectory(), "a-exit", "a-exit-v1\n");
  }

  private static void runPhaseB(Config config) throws Exception {
    publish(config.controlDirectory(), "java-b-ready", "java-b-ready-v1\n");
    await(config.controlDirectory(), "b-negative", "b-negative-v1\n");

    byte[] response = new byte[RECORD_SIZE];
    int negativeStatus = take(config.socketFileDescriptor(), response);
    int expectedStatus = expectedNegativeStatus(config.transport());
    if (negativeStatus != expectedStatus) {
      throw new IllegalStateException("stale-residue probe returned an unexpected status");
    }
    if (!extractsExactW3CParent(config.socketFileDescriptor())) {
      throw new IllegalStateException("stale-residue probe did not fail open to W3C");
    }
    publish(
        config.controlDirectory(),
        "b-negative-result",
        negativeResultPayload(config.transport(), negativeStatus, true));

    await(config.controlDirectory(), "b-recovery", "b-recovery-v1\n");
    if (config.transport().equals("getsockopt")) {
      int emit = emit(config.socketFileDescriptor());
      if (emit != 1) {
        throw new IllegalStateException("phase B primary acknowledgement failed");
      }
    }
    response = new byte[RECORD_SIZE];
    int recoveryStatus = take(config.socketFileDescriptor(), response);
    Record recovery = decodeRecord(recoveryStatus, response);
    if (!recovery.valid()
        || !RECOVERY_TRACE_ID.equals(recovery.traceId())
        || !RECOVERY_SPAN_ID.equals(recovery.spanId())) {
      throw new IllegalStateException("phase B recovery did not return the exact staged parent");
    }
    clearFixtureLookupState();
    awaitProviderReadyWithoutParent(config.socketFileDescriptor());
    publish(
        config.controlDirectory(),
        "b-recovery-result",
        "schema=obi-pid-reuse-java-result-v1\n"
            + "status=valid\n"
            + "parent_exact=true\n");
  }

  static Config parseConfig(Map<String, String> environment) {
    Set<String> fixtureKeys =
        Set.of(
            "OBI_PID_REUSE_PHASE",
            "OBI_PID_REUSE_CONTROL_DIR",
            "OBI_PID_REUSE_SOCKET_FD");
    for (String key : environment.keySet()) {
      if (key.startsWith("OBI_PID_REUSE_") && !fixtureKeys.contains(key)) {
        throw new IllegalArgumentException("PID reuse probe environment has an unknown field");
      }
    }
    String phase = environment.get("OBI_PID_REUSE_PHASE");
    String directory = environment.get("OBI_PID_REUSE_CONTROL_DIR");
    String descriptor = environment.get("OBI_PID_REUSE_SOCKET_FD");
    boolean any = phase != null || directory != null || descriptor != null;
    if (!any) {
      return null;
    }
    if (!(phase != null
        && (phase.equals("A") || phase.equals("B"))
        && directory != null
        && descriptor != null)) {
      throw new IllegalArgumentException("PID reuse probe environment is incomplete or invalid");
    }
    Path path = Path.of(directory);
    if (!path.isAbsolute() || !path.normalize().equals(path) || directory.endsWith("/")) {
      throw new IllegalArgumentException("PID reuse control directory must be an absolute clean path");
    }
    int fd;
    try {
      fd = Integer.parseUnsignedInt(descriptor);
    } catch (NumberFormatException failure) {
      throw new IllegalArgumentException("PID reuse socket descriptor is invalid", failure);
    }
    if (fd < 3) {
      throw new IllegalArgumentException("PID reuse socket descriptor must be at least 3");
    }
    return new Config(phase, path, "", fd);
  }

  private static void validateControlDirectory(Path directory) throws IOException {
    Path real = directory.toRealPath(LinkOption.NOFOLLOW_LINKS);
    BasicFileAttributes attributes =
        Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    Object owner = Files.getAttribute(directory, "unix:uid", LinkOption.NOFOLLOW_LINKS);
    if (!directory.equals(real)
        || !attributes.isDirectory()
        || attributes.isSymbolicLink()
        || !(owner instanceof Number)
        || ((Number) owner).longValue() != 0L
        || !Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS)
            .equals(DIRECTORY_PERMISSIONS)) {
      throw new IOException("PID reuse control directory metadata is unsafe");
    }
  }

  private static void awaitBridgeInitialization() throws Exception {
    Class<?> threadInfo =
        Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
    Method enabled = threadInfo.getMethod("isRemoteParentEnabled");
    Method incarnation = threadInfo.getMethod("processIncarnation");
    long deadline = System.nanoTime() + CONTROL_TIMEOUT.toNanos();
    do {
      boolean bridgeEnabled = Boolean.TRUE.equals(enabled.invoke(null));
      long capability = ((Number) incarnation.invoke(null)).longValue();
      if (bridgeEnabled && capability != 0L) {
        return;
      }
      Thread.sleep(POLL_INTERVAL.toMillis());
    } while (System.nanoTime() < deadline);
    throw new IllegalStateException("timed out waiting for the OBI remote-parent bridge");
  }

  private static String selectedForcedTransport() throws Exception {
    Class<?> bridge =
        Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", true, null);
    String snapshot =
        (String) bridge.getMethod("transportConfigurationSnapshot").invoke(null);
    return forcedTransportFromSnapshot(snapshot);
  }

  static String forcedTransportFromSnapshot(String snapshot) {
    if ("version=2,status=1,requested=1,selected=1,attempted=1,getsockopt=1,unix=0"
        .equals(snapshot)) {
      return "getsockopt";
    }
    if ("version=2,status=1,requested=2,selected=2,attempted=2,getsockopt=0,unix=1"
        .equals(snapshot)) {
      return "unix";
    }
    throw new IllegalStateException("PID reuse fixture requires one exact forced transport");
  }

  private static RuntimePrivilegeAttestation readRuntimePrivilegeAttestation() throws IOException {
    return runtimePrivilegeAttestation(
        Files.readString(Path.of("/proc/self/status"), StandardCharsets.US_ASCII),
        Files.readString(Path.of("/proc/self/stat"), StandardCharsets.US_ASCII),
        ProcessHandle.current().pid());
  }

  static RuntimePrivilegeAttestation runtimePrivilegeAttestation(
      String status, String stat, long expectedPid) {
    Map<String, String> required = new HashMap<>();
    Set<String> names = Set.of("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs");
    for (String line : status.split("\\n", -1)) {
      int separator = line.indexOf(':');
      if (separator <= 0) {
        continue;
      }
      String name = line.substring(0, separator);
      if (names.contains(name)
          && required.putIfAbsent(name, line.substring(separator + 1).trim()) != null) {
        throw new IllegalStateException("duplicate JVM privilege status field");
      }
    }
    if (!required.keySet().equals(names)) {
      throw new IllegalStateException("JVM privilege status fields are incomplete");
    }
    for (String name : Set.of("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")) {
      if (!required.get(name).matches("0+")) {
        throw new IllegalStateException("controlled JVM retained runtime capabilities");
      }
    }
    if (!required.get("NoNewPrivs").equals("1")) {
      throw new IllegalStateException("controlled JVM lacks no-new-privileges");
    }

    int close = stat.lastIndexOf(')');
    if (close < 0 || close + 2 >= stat.length()) {
      throw new IllegalStateException("controlled JVM stat is malformed");
    }
    String[] fieldsAfterName = stat.substring(close + 2).trim().split("\\s+");
    if (fieldsAfterName.length < 20) {
      throw new IllegalStateException("controlled JVM stat lacks start time");
    }
    long actualPid;
    long startTimeTicks;
    try {
      actualPid = Long.parseLong(stat.substring(0, stat.indexOf(' ')));
      startTimeTicks = Long.parseUnsignedLong(fieldsAfterName[19]);
    } catch (NumberFormatException failure) {
      throw new IllegalStateException("controlled JVM identity is malformed", failure);
    }
    if (actualPid <= 0 || actualPid != expectedPid || startTimeTicks == 0) {
      throw new IllegalStateException("controlled JVM identity does not match its runtime");
    }
    return new RuntimePrivilegeAttestation(actualPid, startTimeTicks);
  }

  private static int emit(int socketFileDescriptor) throws Exception {
    Class<?> nativeMemory =
        Class.forName("io.opentelemetry.obi.java.ebpf.NativeMemory", true, null);
    Object packet = nativeMemory.getConstructor(int.class).newInstance(RECORD_SIZE);
    long address = ((Number) nativeMemory.getMethod("getAddress").invoke(packet)).longValue();
    Class<?> nativeBridge =
        Class.forName("io.opentelemetry.obi.java.BootstrapNative", true, null);
    return ((Number)
            nativeBridge
                .getMethod("emitData", int.class, long.class, boolean.class)
                .invoke(null, socketFileDescriptor, address, true))
        .intValue();
  }

  private static int take(int socketFileDescriptor, byte[] response) throws Exception {
    Class<?> nativeBridge =
        Class.forName("io.opentelemetry.obi.java.BootstrapNative", true, null);
    return ((Number)
            nativeBridge
                .getMethod("takeRemoteParent", int.class, byte[].class)
                .invoke(null, socketFileDescriptor, response))
        .intValue();
  }

  private static void clearFixtureLookupState() throws Exception {
    Class<?> threadInfo =
        Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
    threadInfo.getMethod("clearRemoteParentSocketFileDescriptor").invoke(null);
    threadInfo.getMethod("clearRemoteParentLookupSource").invoke(null);
  }

  private static void awaitProviderReadyWithoutParent(int socketFileDescriptor) throws Exception {
    Class<?> bridge =
        Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", true, null);
    Method take = bridge.getMethod("takeRemoteParent");
    long deadline = System.nanoTime() + CONTROL_TIMEOUT.toNanos();
    do {
      Class<?> threadInfo =
          Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      threadInfo
          .getMethod("setRemoteParentSocketFileDescriptor", int.class)
          .invoke(null, socketFileDescriptor);
      Object record = take.invoke(null);
      int status = ((Number) record.getClass().getMethod("getStatus").invoke(record)).intValue();
      clearFixtureLookupState();
      if (status == 2) {
        return;
      }
      Thread.sleep(POLL_INTERVAL.toMillis());
    } while (System.nanoTime() < deadline);
    throw new IllegalStateException("timed out waiting for phase B provider recovery");
  }

  private static boolean extractsExactW3CParent(int socketFileDescriptor) throws Exception {
    Class<?> threadInfo =
        Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
    threadInfo
        .getMethod("setRemoteParentSocketFileDescriptor", int.class)
        .invoke(null, socketFileDescriptor);
    try {
      Class<?> global = Class.forName("io.opentelemetry.api.GlobalOpenTelemetry");
      Object telemetry = global.getMethod("get").invoke(null);
      Class<?> openTelemetryClass = Class.forName("io.opentelemetry.api.OpenTelemetry");
      Object propagators = openTelemetryClass.getMethod("getPropagators").invoke(telemetry);
      Class<?> propagatorsClass =
          Class.forName("io.opentelemetry.context.propagation.ContextPropagators");
      Object propagator =
          propagatorsClass.getMethod("getTextMapPropagator").invoke(propagators);
      Class<?> contextClass = Class.forName("io.opentelemetry.context.Context");
      Class<?> getterClass = Class.forName("io.opentelemetry.context.propagation.TextMapGetter");
      Class<?> propagatorClass =
          Class.forName("io.opentelemetry.context.propagation.TextMapPropagator");
      Object root = contextClass.getMethod("root").invoke(null);
      Map<String, String> carrier =
          Collections.singletonMap(
              "traceparent", "00-" + W3C_TRACE_ID + "-" + W3C_SPAN_ID + "-01");
      InvocationHandler handler =
          (proxy, method, arguments) -> {
            if (method.getName().equals("keys")) {
              return carrier.keySet();
            }
            if (method.getName().equals("get")) {
              return carrier.get(arguments[1]);
            }
            if (method.getName().equals("toString")) {
              return "PidReuseTextMapGetter";
            }
            throw new UnsupportedOperationException("unexpected TextMapGetter method");
          };
      Object getter =
          Proxy.newProxyInstance(getterClass.getClassLoader(), new Class<?>[] {getterClass}, handler);
      Object extracted =
          propagatorClass
              .getMethod("extract", contextClass, Object.class, getterClass)
              .invoke(propagator, root, carrier, getter);
      Class<?> spanClass = Class.forName("io.opentelemetry.api.trace.Span");
      Object span = spanClass.getMethod("fromContext", contextClass).invoke(null, extracted);
      Object spanContext = spanClass.getMethod("getSpanContext").invoke(span);
      Class<?> spanContextClass = Class.forName("io.opentelemetry.api.trace.SpanContext");
      int remainingDescriptor =
          ((Number) threadInfo.getMethod("remoteParentSocketFileDescriptor").invoke(null))
              .intValue();
      return remainingDescriptor == -1
          && Boolean.TRUE.equals(spanContextClass.getMethod("isValid").invoke(spanContext))
          && Boolean.TRUE.equals(spanContextClass.getMethod("isRemote").invoke(spanContext))
          && W3C_TRACE_ID.equals(spanContextClass.getMethod("getTraceId").invoke(spanContext))
          && W3C_SPAN_ID.equals(spanContextClass.getMethod("getSpanId").invoke(spanContext));
    } finally {
      clearFixtureLookupState();
    }
  }

  private static int expectedNegativeStatus(String transport) {
    return transport.equals("getsockopt") ? STATUS_UNSUPPORTED : STATUS_AMBIGUOUS;
  }

  static String statusName(int status) {
    if (status == STATUS_VALID) {
      return "valid";
    }
    if (status == STATUS_UNSUPPORTED) {
      return "unsupported";
    }
    if (status == STATUS_AMBIGUOUS) {
      return "ambiguous";
    }
    return "unexpected";
  }

  static String negativeResultPayload(String transport, int status, boolean w3cFailOpen) {
    if (status != expectedNegativeStatus(transport) || !w3cFailOpen) {
      throw new IllegalArgumentException("negative PID reuse result is not a passing result");
    }
    return "schema=obi-pid-reuse-java-result-v1\n"
        + "status="
        + statusName(status)
        + "\n"
        + "w3c_fail_open=true\n";
  }

  static Record decodeRecord(int status, byte[] response) {
    if (response.length != RECORD_SIZE || status != STATUS_VALID) {
      return new Record(false, "", "");
    }
    ByteBuffer buffer = ByteBuffer.wrap(response).order(ByteOrder.LITTLE_ENDIAN);
    if (response[0] != 'O'
        || response[1] != 'B'
        || response[2] != 'I'
        || response[3] != 'J'
        || Short.toUnsignedInt(buffer.getShort(4)) != 1
        || Short.toUnsignedInt(buffer.getShort(6)) != RECORD_SIZE
        || Byte.toUnsignedInt(response[8]) != STATUS_VALID
        || response[9] > 1
        || !allZero(response, 10, 16)
        || !allZero(response, 56, 64)
        || buffer.getLong(40) == 0L
        || buffer.getLong(48) == 0L) {
      return new Record(false, "", "");
    }
    String traceId = hex(response, 16, 32);
    String spanId = hex(response, 32, 40);
    if (allZero(response, 16, 32) || allZero(response, 32, 40)) {
      return new Record(false, "", "");
    }
    return new Record(true, traceId, spanId);
  }

  private static boolean allZero(byte[] value, int start, int end) {
    for (int index = start; index < end; index++) {
      if (value[index] != 0) {
        return false;
      }
    }
    return true;
  }

  private static String hex(byte[] value, int start, int end) {
    StringBuilder result = new StringBuilder((end - start) * 2);
    for (int index = start; index < end; index++) {
      result.append(Character.forDigit((value[index] >>> 4) & 0xf, 16));
      result.append(Character.forDigit(value[index] & 0xf, 16));
    }
    return result.toString();
  }

  private static void await(Path directory, String name, String expected) throws Exception {
    long deadline = System.nanoTime() + CONTROL_TIMEOUT.toNanos();
    do {
      Path command = directory.resolve(name);
      if (Files.exists(command, LinkOption.NOFOLLOW_LINKS)) {
        validateControlFile(command, expected.getBytes(StandardCharsets.US_ASCII).length);
        String actual = Files.readString(command, StandardCharsets.US_ASCII);
        if (!actual.equals(expected)) {
          throw new IOException("PID reuse control command has unexpected contents");
        }
        return;
      }
      Thread.sleep(POLL_INTERVAL.toMillis());
    } while (System.nanoTime() < deadline);
    throw new IllegalStateException("timed out waiting for PID reuse control command");
  }

  private static void validateControlFile(Path file, int expectedLength) throws IOException {
    BasicFileAttributes attributes =
        Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    Object owner = Files.getAttribute(file, "unix:uid", LinkOption.NOFOLLOW_LINKS);
    Object links = Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS);
    if (!attributes.isRegularFile()
        || attributes.isSymbolicLink()
        || attributes.size() != expectedLength
        || !(owner instanceof Number)
        || ((Number) owner).longValue() != 0L
        || !(links instanceof Number)
        || ((Number) links).longValue() != 1L
        || !Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS).equals(FILE_PERMISSIONS)) {
      throw new IOException("PID reuse control file metadata is unsafe");
    }
  }

  private static void publish(Path directory, String name, String contents) throws IOException {
    if (!name.matches("[a-z0-9-]{1,64}")
        || !contents.matches("[a-z0-9_=\\-\\n]{1,512}")) {
      throw new IllegalArgumentException("PID reuse publication is outside the safe schema");
    }
    Path destination = directory.resolve(name);
    Path temporary =
        directory.resolve(
            ".java-tmp-"
                + ProcessHandle.current().pid()
                + "-"
                + NEXT_TEMPORARY.incrementAndGet());
    OpenOption[] options = {
      StandardOpenOption.CREATE_NEW,
      StandardOpenOption.WRITE,
      LinkOption.NOFOLLOW_LINKS
    };
    try {
      try (FileChannel channel = FileChannel.open(temporary, options)) {
        Files.setPosixFilePermissions(temporary, FILE_PERMISSIONS);
        ByteBuffer bytes = ByteBuffer.wrap(contents.getBytes(StandardCharsets.US_ASCII));
        while (bytes.hasRemaining()) {
          channel.write(bytes);
        }
        channel.force(true);
      }
      Files.createLink(destination, temporary);
      Files.delete(temporary);
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  record Config(String phase, Path controlDirectory, String transport, int socketFileDescriptor) {
    Config withTransport(String selectedTransport) {
      if (!transport.isEmpty()
          || !(selectedTransport.equals("getsockopt") || selectedTransport.equals("unix"))) {
        throw new IllegalStateException("PID reuse fixture transport transition is invalid");
      }
      return new Config(phase, controlDirectory, selectedTransport, socketFileDescriptor);
    }
  }

  record RuntimePrivilegeAttestation(long pid, long startTimeTicks) {
    String payload() {
      return "schema=obi-pid-reuse-jvm-attestation-v1\n"
          + "pid="
          + pid
          + "\nstart_time_ticks="
          + startTimeTicks
          + "\ncap_inh_zero=true\n"
          + "cap_prm_zero=true\n"
          + "cap_eff_zero=true\n"
          + "cap_bnd_zero=true\n"
          + "cap_amb_zero=true\n"
          + "no_new_privs=true\n";
    }
  }

  record Record(boolean valid, String traceId, String spanId) {}
}
