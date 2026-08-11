/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class OfficialAgentJava21ConcurrencyRuntimeTest {
  private static final String INVALID_TRACE = "00000000000000000000000000000000";
  private static final String INVALID_SPAN = "0000000000000000";
  private static final String DIAGNOSTICS_LOGGER_INITIALIZED =
      "OBI remote-parent diagnostics logger initialized";
  private static final String SUCCESS_MARKER =
      "OBI_JAVA21_PROBE\tpassed\tvirtual=34\tplatform=10\tcaptures=24\tlinks=24"
          + "\trelays=4\tcarriers=4\tworkers=4";

  @Test
  void unmodifiedOpenTelemetryAgentPreservesConcurrentJava21Parents() throws Exception {
    verifyAgent(
        "OBI_TEST_OTEL_AGENT",
        "faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",
        "distribution=opentelemetry",
        "agent_version=2.28.1");
  }

  @Test
  void unmodifiedSplunkAgentPreservesConcurrentJava21Parents() throws Exception {
    verifyAgent(
        "OBI_TEST_SPLUNK_AGENT",
        "70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351",
        "distribution=splunk",
        "agent_version=splunk-2.28.0-otel-2.28.1");
  }

  private static void verifyAgent(
      String environmentName, String expectedSha256, String distribution, String version)
      throws Exception {
    Assumptions.assumeTrue(javaMajorVersion() == 21, "Java 21 concurrency probe requires Java 21");
    String agentPath = System.getenv(environmentName);
    Assumptions.assumeTrue(
        agentPath != null && !agentPath.isEmpty(), environmentName + " is unset");

    File officialAgent = new File(agentPath);
    File helper = new File(requiredProperty("obi.test.packaged.agent"));
    File extension = new File(requiredProperty("obi.test.extension.jar"));
    File probeExtension = new File(requiredProperty("obi.test.official.agent.probe.extension.jar"));
    String probeClasspath = requiredProperty("obi.test.official.agent.java21.probe.app.classpath");

    assertTrue(officialAgent.isFile() && officialAgent.length() > 0, officialAgent.toString());
    assertEquals(expectedSha256, sha256(officialAgent.toPath()));
    assertTrue(helper.isFile() && helper.length() > 0, helper.toString());
    assertTrue(extension.isFile() && extension.length() > 0, extension.toString());
    assertTrue(probeExtension.isFile() && probeExtension.length() > 0, probeExtension.toString());
    assertProbeClasspath(probeClasspath);
    assertNoAgentProvidedClasses(extension);
    assertNoAgentProvidedClasses(probeExtension);

    runProbe(
        officialAgent,
        expectedSha256,
        helper,
        extension,
        probeExtension,
        probeClasspath,
        distribution,
        version,
        null);
    runProbe(
        officialAgent,
        expectedSha256,
        helper,
        extension,
        probeExtension,
        probeClasspath,
        distribution,
        version,
        "WARNING");
    assertEquals(expectedSha256, sha256(officialAgent.toPath()));
  }

  private static void runProbe(
      File officialAgent,
      String expectedSha256,
      File helper,
      File extension,
      File probeExtension,
      String probeClasspath,
      String distribution,
      String version,
      String diagnosticsLogLevel)
      throws Exception {
    Path directory = Files.createTempDirectory("obi-official-agent-java21-");
    Path result = directory.resolve("spans.tsv");
    Path loggingConfiguration = directory.resolve("logging.properties");
    try {
      List<String> command = new ArrayList<>();
      command.add(new File(System.getProperty("java.home"), "bin/java").getAbsolutePath());
      command.add("--add-opens=java.base/java.lang=ALL-UNNAMED");
      if (diagnosticsLogLevel != null) {
        Files.write(
            loggingConfiguration,
            java.util.Arrays.asList(
                "handlers=java.util.logging.ConsoleHandler",
                ".level=INFO",
                "java.util.logging.ConsoleHandler.level=ALL",
                "java.util.logging.ConsoleHandler.formatter=java.util.logging.SimpleFormatter",
                "io.opentelemetry.obi.java.bridge.RemoteParentDiagnostics.level="
                    + diagnosticsLogLevel),
            StandardCharsets.UTF_8);
        command.add("-Djava.util.logging.config.file=" + loggingConfiguration);
      }
      command.add("-javaagent:" + helper.getAbsolutePath() + "=remoteParentTransport=disabled");
      command.add("-javaagent:" + officialAgent.getAbsolutePath());
      command.add(
          "-Dotel.javaagent.extensions="
              + extension.getAbsolutePath()
              + ","
              + probeExtension.getAbsolutePath());
      command.add("-Dotel.propagators=obi,tracecontext,baggage");
      command.add("-Dotel.obi.remote.parent.enabled=true");
      command.add("-Dotel.traces.sampler=always_on");
      command.add("-Dotel.traces.exporter=none");
      command.add("-Dotel.metrics.exporter=none");
      command.add("-Dotel.logs.exporter=none");
      command.add("-Dotel.service.name=obi-official-agent-java21-concurrency-probe");
      command.add("-Dobi.test.official.agent.probe.output=" + result);
      command.add("-Dobi.test.official.agent.probe.framework=java21-concurrency");
      command.add("-cp");
      command.add(probeClasspath);
      command.add("org.example.obi.java21.probe.OfficialAgentJava21ConcurrencyProbe");

      String output;
      try {
        output = run(command, 90, "official-agent Java 21 concurrency probe");
      } catch (Throwable failure) {
        String partialResult =
            Files.isRegularFile(result)
                ? new String(Files.readAllBytes(result), StandardCharsets.UTF_8)
                : "<missing>";
        throw new AssertionError("official-agent Java 21 probe result:\n" + partialResult, failure);
      }
      List<String> resultLines = Files.readAllLines(result, StandardCharsets.UTF_8);
      try {
        assertOutput(output, distribution, version);
        assertResult(resultLines, output);
        assertEquals(expectedSha256, sha256(officialAgent.toPath()));
      } catch (Throwable failure) {
        throw new AssertionError(
            "official-agent Java 21 output:\n"
                + output
                + "\nofficial-agent Java 21 probe result:\n"
                + resultLines,
            failure);
      }
    } finally {
      Files.deleteIfExists(result);
      Files.deleteIfExists(loggingConfiguration);
      Files.deleteIfExists(directory);
    }
  }

  private static void assertOutput(String output, String distribution, String version) {
    List<String> lines = outputLines(output);
    assertEquals(1, count(lines, SUCCESS_MARKER), output);
    List<String> loggerInitialization = containing(lines, DIAGNOSTICS_LOGGER_INITIALIZED);
    assertEquals(1, loggerInitialization.size(), output);
    int initialization = lines.indexOf(loggerInitialization.get(0));
    int firstBaseline = firstIndexWithPrefix(lines, "OBI_JAVA21_BASELINE\t");
    int firstWave = lines.indexOf("OBI_JAVA21_WAVE\t1\tSTART");
    assertTrue(
        initialization >= 0 && initialization < firstBaseline && firstBaseline < firstWave, output);
    assertTrue(output.contains("OBI remote-parent compatibility"), output);
    assertTrue(output.contains(distribution), output);
    assertTrue(output.contains(version), output);
    assertTrue(output.contains("provider=obi,supported=true,reason=compatible"), output);
    assertFalse(output.contains("LinkageError"), output);
    assertFalse(output.contains("ClassNotFoundException"), output);
    assertFalse(output.contains("AssertionError"), output);
  }

  private static void assertResult(List<String> lines, String output) {
    List<String> outputLines = outputLines(output);
    ProbeRecords probe = ProbeRecords.parse(outputLines);
    Map<String, Long> diagnostics = diagnostics(outputLines);
    assertEquals(20L, counter(diagnostics, "t_valid"), output);
    assertEquals(40L, counter(diagnostics, "t_missing"), output);
    assertEquals(10L, counter(diagnostics, "take_sampled"), output);
    assertEquals(10L, counter(diagnostics, "take_unsampled"), output);
    assertEquals(0L, counter(diagnostics, "framework_depth"), output);
    assertEquals(0L, counter(diagnostics, "framework_cycle"), output);
    assertEquals(20L, counter(diagnostics, "framework_late"), output);
    assertEquals(20L, counter(diagnostics, "transport_missing"), output);
    assertEquals(1, count(lines, "EXTENSION\tready"), lines.toString());
    assertEquals(1, count(lines, "PROVIDER\tready\tbootstrap"), lines.toString());
    assertEquals(1, count(lines, "WRAP\tobi\t1"), lines.toString());
    assertEquals(0, prefix(lines, "WRAP\tobi\t2").size(), lines.toString());
    assertEquals(0, prefix(lines, "ERROR\t").size(), lines.toString());
    assertExactRecordKeys(lines);

    Map<String, SpanResult> spans = new HashMap<>();
    for (String line : prefix(lines, "SPAN\t")) {
      SpanResult span = SpanResult.parse(line);
      assertTrue(java21Id(span.id), line);
      assertFalse(spans.containsKey(span.id), "duplicate span for " + span.id);
      spans.put(span.id, span);
    }
    assertEquals(40, spans.size(), lines.toString());

    Set<String> firstWaveTraces = new HashSet<>();
    Set<String> rootTraces = new HashSet<>();
    Set<String> firstWaveParents = new HashSet<>();
    Set<Integer> lifecycleIdentities = new HashSet<>();
    Set<String> childSpanIds = new HashSet<>();
    for (String id : ids()) {
      boolean firstWave = id.startsWith("W1");
      assertEquals(1, count(lines, "CALL\t" + id + "\t1"), lines.toString());
      assertEquals(0, prefix(lines, "CALL\t" + id + "\t2").size(), lines.toString());

      List<String> passLines = prefix(lines, "PASS\t" + id + "\t1\t");
      assertEquals(2, passLines.size(), lines.toString());
      PassResult first = PassResult.parse(passLines.get(0));
      PassResult second = PassResult.parse(passLines.get(1));
      assertEquals(1, first.pass, passLines.toString());
      assertEquals(2, second.pass, passLines.toString());
      assertEquals(first.traceId, second.traceId, passLines.toString());
      assertEquals(first.spanId, second.spanId, passLines.toString());
      assertEquals(first.remote, second.remote, passLines.toString());
      assertEquals(first.sampled, second.sampled, passLines.toString());

      List<String> providerLines = prefix(lines, "PROVIDER\tTAKE\t" + id + "\t1\t");
      assertEquals(1, providerLines.size(), lines.toString());
      ProviderResult providerResult = ProviderResult.parse(providerLines.get(0));
      assertEquals(firstWave ? 1 : 2, providerResult.pass, providerLines.toString());
      assertEquals(
          firstWave ? "VALID" : "MISSING", providerResult.status, providerLines.toString());

      List<String> authorityLines = prefix(lines, "AUTH\tJAVA21\tTAKE\t" + id + "\t1\t");
      assertEquals(1, authorityLines.size(), lines.toString());
      AuthorityResult lookupAuthority = AuthorityResult.parse(authorityLines.get(0));
      assertEquals(firstWave ? 1 : 2, lookupAuthority.pass, authorityLines.toString());
      assertTrue(lookupAuthority.javaThreadId > 0L, authorityLines.toString());
      assertTrue(lookupAuthority.nativeThreadId > 0L, authorityLines.toString());

      String spanStart = only(lines, "THREAD\tSPAN_START\t" + id + "\t");
      long spanStartThread = Long.parseLong(spanStart.split("\\t", -1)[3]);
      assertEquals(lookupAuthority.javaThreadId, spanStartThread, lines.toString());

      SpanResult span = required(spans, id);
      probe.assertOwner(id, lookupAuthority, span);
      assertEquals("io.opentelemetry.obi.java21-concurrency-probe", span.scope, span.line);
      assertEquals("-", span.route, span.line);
      assertTrue(span.spanSampled, span.line);
      assertTrue(lowerHex(span.traceId, 32), span.line);
      assertTrue(lowerHex(span.spanId, 16), span.line);
      assertNotEquals(INVALID_TRACE, span.traceId, span.line);
      assertNotEquals(INVALID_SPAN, span.spanId, span.line);
      assertTrue(childSpanIds.add(span.spanId), "duplicate child span id " + span.spanId);
      assertNotEquals(span.spanId, span.parentSpanId, span.line);
      if (firstWave) {
        String expectedTrace = expectedTraceId(id);
        String expectedParent = expectedParentSpanId(id);
        boolean expectedSampled = (ordinal(id) & 1) != 0;
        assertEquals(expectedTrace, first.traceId, passLines.toString());
        assertEquals(expectedParent, first.spanId, passLines.toString());
        assertTrue(first.remote, passLines.toString());
        assertEquals(expectedSampled, first.sampled, passLines.toString());
        assertEquals(2, lookupAuthority.source, authorityLines.toString());
        assertFalse(lookupAuthority.direct, authorityLines.toString());
        assertTrue(lookupAuthority.lifecycleActive, authorityLines.toString());
        assertNotEquals(0, lookupAuthority.lifecycleIdentity, authorityLines.toString());
        assertTrue(
            lifecycleIdentities.add(lookupAuthority.lifecycleIdentity),
            "duplicate lifecycle identity " + lookupAuthority.lifecycleIdentity);
        assertEquals(
            200 + ordinal(id), lookupAuthority.socketFileDescriptor, authorityLines.toString());
        assertTrue(lookupAuthority.exact, authorityLines.toString());
        assertTrue(lookupAuthority.socketContextPresent, authorityLines.toString());
        assertEquals(expectedTrace, span.traceId, span.line);
        assertEquals(expectedParent, span.parentSpanId, span.line);
        assertTrue(span.parentRemote, span.line);
        assertEquals(expectedSampled, span.parentSampled, span.line);
        assertTrue(firstWaveTraces.add(span.traceId), "duplicate first-wave trace " + span.traceId);
        assertTrue(
            firstWaveParents.add(span.parentSpanId),
            "duplicate first-wave parent " + span.parentSpanId);
      } else {
        assertEquals(INVALID_TRACE, first.traceId, passLines.toString());
        assertEquals(INVALID_SPAN, first.spanId, passLines.toString());
        assertFalse(first.remote, passLines.toString());
        assertFalse(first.sampled, passLines.toString());
        assertEquals(3, lookupAuthority.source, authorityLines.toString());
        assertFalse(lookupAuthority.direct, authorityLines.toString());
        assertFalse(lookupAuthority.lifecycleActive, authorityLines.toString());
        assertEquals(0, lookupAuthority.lifecycleIdentity, authorityLines.toString());
        assertEquals(-1, lookupAuthority.socketFileDescriptor, authorityLines.toString());
        assertFalse(lookupAuthority.exact, authorityLines.toString());
        assertFalse(lookupAuthority.socketContextPresent, authorityLines.toString());
        assertEquals(INVALID_SPAN, span.parentSpanId, span.line);
        assertFalse(span.parentRemote, span.line);
        assertFalse(span.parentSampled, span.line);
        assertFalse(firstWaveTraces.contains(span.traceId), span.line);
        assertTrue(rootTraces.add(span.traceId), "duplicate second-wave root " + span.traceId);
      }
    }
    assertEquals(20, firstWaveTraces.size(), output);
    assertEquals(20, firstWaveParents.size(), output);
    assertEquals(20, lifecycleIdentities.size(), output);
    assertEquals(20, rootTraces.size(), output);
    assertEquals(40, childSpanIds.size(), output);
  }

  private static boolean lowerHex(String value, int length) {
    if (value == null || value.length() != length) {
      return false;
    }
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'))) {
        return false;
      }
    }
    return true;
  }

  private static void assertExactRecordKeys(List<String> lines) {
    Set<String> expectedIds = new HashSet<>(ids());
    Set<String> expectedPasses = new HashSet<>();
    Set<String> expectedProviderPasses = new HashSet<>();
    for (String id : expectedIds) {
      expectedPasses.add(id + "/1");
      expectedPasses.add(id + "/2");
      expectedProviderPasses.add(id + (id.startsWith("W1") ? "/1" : "/2"));
    }

    Set<String> calls = new HashSet<>();
    for (String line : prefix(lines, "CALL\t")) {
      String[] fields = line.split("\\t", -1);
      assertEquals(3, fields.length, line);
      assertTrue(expectedIds.contains(fields[1]), line);
      assertEquals(1, Integer.parseInt(fields[2]), line);
      assertTrue(calls.add(fields[1]), "duplicate CALL record " + line);
    }
    assertEquals(expectedIds, calls, lines.toString());

    Set<String> passes = new HashSet<>();
    for (String line : prefix(lines, "PASS\t")) {
      String[] fields = line.split("\\t", -1);
      assertEquals(8, fields.length, line);
      assertTrue(expectedIds.contains(fields[1]), line);
      assertEquals(1, Integer.parseInt(fields[2]), line);
      String key = fields[1] + "/" + Integer.parseInt(fields[3]);
      assertTrue(passes.add(key), "duplicate PASS record " + line);
    }
    assertEquals(expectedPasses, passes, lines.toString());

    Set<String> providers = new HashSet<>();
    assertEquals(0, prefix(lines, "PROVIDER\tDISCARD\t").size(), lines.toString());
    for (String line : prefix(lines, "PROVIDER\tTAKE\t")) {
      String[] fields = line.split("\\t", -1);
      assertEquals(6, fields.length, line);
      assertTrue(expectedIds.contains(fields[2]), line);
      assertEquals(1, Integer.parseInt(fields[3]), line);
      String key = fields[2] + "/" + Integer.parseInt(fields[4]);
      assertTrue(providers.add(key), "duplicate provider record " + line);
    }
    assertEquals(expectedProviderPasses, providers, lines.toString());

    Set<String> authorities = new HashSet<>();
    assertEquals(expectedProviderPasses.size(), prefix(lines, "AUTH\t").size(), lines.toString());
    for (String line : prefix(lines, "AUTH\tJAVA21\t")) {
      String[] fields = line.split("\\t", -1);
      assertEquals(15, fields.length, line);
      assertEquals("TAKE", fields[2], line);
      assertTrue(expectedIds.contains(fields[3]), line);
      assertEquals(1, Integer.parseInt(fields[4]), line);
      String key = fields[3] + "/" + Integer.parseInt(fields[5]);
      assertTrue(authorities.add(key), "duplicate authority record " + line);
    }
    assertEquals(expectedProviderPasses, authorities, lines.toString());

    int providerClose = count(lines, "PROVIDER\tclose");
    assertTrue(providerClose == 0 || providerClose == 1, lines.toString());
    assertEquals(
        1 + expectedProviderPasses.size() + providerClose,
        prefix(lines, "PROVIDER\t").size(),
        lines.toString());

    Set<String> spanStarts = new HashSet<>();
    for (String line : prefix(lines, "THREAD\tSPAN_START\t")) {
      String[] fields = line.split("\\t", -1);
      assertEquals(4, fields.length, line);
      assertTrue(expectedIds.contains(fields[2]), line);
      assertTrue(Long.parseLong(fields[3]) > 0L, line);
      assertTrue(spanStarts.add(fields[2]), "duplicate span-start record " + line);
    }
    assertEquals(expectedIds, spanStarts, lines.toString());
  }

  private static List<String> ids() {
    List<String> ids = new ArrayList<>();
    for (int wave = 1; wave <= 2; wave++) {
      for (int index = 0; index < 16; index++) {
        ids.add("W" + wave + "V" + twoDigits(index));
      }
      for (int index = 0; index < 4; index++) {
        ids.add("W" + wave + "P" + twoDigits(index));
      }
    }
    return ids;
  }

  private static List<String> relayIds() {
    List<String> ids = new ArrayList<>();
    ids.add("R1V00");
    ids.add("R1V01");
    ids.add("R1P02");
    ids.add("R1P03");
    return ids;
  }

  private static String relayId(String parentId) {
    int index = Integer.parseInt(parentId.substring(3));
    return "R1" + (index < 2 ? "V" : "P") + twoDigits(index);
  }

  private static boolean java21Id(String id) {
    return id != null && ids().contains(id);
  }

  private static int ordinal(String id) {
    int index = Integer.parseInt(id.substring(3));
    return id.charAt(2) == 'V' ? index : 16 + index;
  }

  private static String expectedTraceId(String id) {
    return paddedHex(ordinal(id) + 1L, 32);
  }

  private static String expectedParentSpanId(String id) {
    return paddedHex(ordinal(id) + 1L, 16);
  }

  private static String twoDigits(int value) {
    return value < 10 ? "0" + value : Integer.toString(value);
  }

  private static String paddedHex(long value, int width) {
    String hex = Long.toHexString(value);
    StringBuilder result = new StringBuilder(width);
    for (int index = hex.length(); index < width; index++) {
      result.append('0');
    }
    return result.append(hex).toString();
  }

  private static SpanResult required(Map<String, SpanResult> spans, String id) {
    SpanResult result = spans.get(id);
    assertTrue(result != null, "missing span for " + id);
    return result;
  }

  private static int count(List<String> lines, String value) {
    int count = 0;
    for (String line : lines) {
      if (value.equals(line)) {
        count++;
      }
    }
    return count;
  }

  private static List<String> outputLines(String output) {
    List<String> lines = new ArrayList<>();
    for (String line : output.split("\\R")) {
      if (!line.isEmpty()) {
        lines.add(line);
      }
    }
    return lines;
  }

  private static Map<String, Long> diagnostics(List<String> outputLines) {
    String marker = "OBI_JAVA21_DIAGNOSTICS\t";
    String line = only(outputLines, marker);
    Map<String, Long> result = new HashMap<>();
    for (String field : line.substring(marker.length()).split(",")) {
      int separator = field.indexOf('=');
      assertTrue(separator > 0 && separator < field.length() - 1, line);
      String name = field.substring(0, separator);
      assertFalse(result.containsKey(name), "duplicate diagnostics field " + name);
      result.put(name, Long.parseLong(field.substring(separator + 1), Character.MAX_RADIX));
    }
    return result;
  }

  private static long counter(Map<String, Long> diagnostics, String name) {
    Long value = diagnostics.get(name);
    assertTrue(value != null, "missing diagnostics counter " + name);
    return value;
  }

  private static List<String> prefix(List<String> lines, String prefix) {
    List<String> matches = new ArrayList<>();
    for (String line : lines) {
      if (line.startsWith(prefix)) {
        matches.add(line);
      }
    }
    return matches;
  }

  private static List<String> containing(List<String> lines, String value) {
    List<String> matches = new ArrayList<>();
    for (String line : lines) {
      if (line.contains(value)) {
        matches.add(line);
      }
    }
    return matches;
  }

  private static int firstIndexWithPrefix(List<String> lines, String prefix) {
    for (int index = 0; index < lines.size(); index++) {
      if (lines.get(index).startsWith(prefix)) {
        return index;
      }
    }
    return -1;
  }

  private static String only(List<String> lines, String prefix) {
    List<String> matches = prefix(lines, prefix);
    assertEquals(1, matches.size(), "expected one line with prefix " + prefix + ": " + matches);
    return matches.get(0);
  }

  private static void assertProbeClasspath(String classpath) {
    assertFalse(classpath.isEmpty());
    boolean probeClass = false;
    Set<String> requiredApiArtifacts = new HashSet<>();
    requiredApiArtifacts.add("opentelemetry-api-1.62.0.jar");
    requiredApiArtifacts.add("opentelemetry-common-1.62.0.jar");
    requiredApiArtifacts.add("opentelemetry-context-1.62.0.jar");
    for (String entry : classpath.split(Pattern.quote(File.pathSeparator))) {
      String name = new File(entry).getName();
      if (name.startsWith("opentelemetry-")) {
        assertTrue(requiredApiArtifacts.remove(name), "unexpected API artifact " + name);
      }
      assertFalse(name.startsWith("jetty-"), classpath);
      assertFalse(name.startsWith("netty-"), classpath);
      assertFalse(name.startsWith("opentelemetry-javaagent"), classpath);
      File candidate =
          new File(entry, "org/example/obi/java21/probe/OfficialAgentJava21ConcurrencyProbe.class");
      probeClass |= candidate.isFile();
    }
    assertTrue(probeClass, classpath);
    assertTrue(requiredApiArtifacts.isEmpty(), "missing API artifacts " + requiredApiArtifacts);
  }

  private static String run(List<String> command, long timeoutSeconds, String name)
      throws Exception {
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    AtomicReference<Throwable> readerFailure = new AtomicReference<>();
    Thread reader = copyOutput(process.getInputStream(), output, readerFailure);
    boolean completed;
    String timeoutThreadDump = "";
    try {
      completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
      if (!completed && process.isAlive()) {
        timeoutThreadDump = captureThreadDump(process);
      }
    } finally {
      if (process.isAlive()) {
        process.destroy();
        if (!process.waitFor(2, TimeUnit.SECONDS)) {
          process.destroyForcibly();
          process.waitFor(2, TimeUnit.SECONDS);
        }
      }
      reader.join(TimeUnit.SECONDS.toMillis(5));
    }
    String text = new String(output.toByteArray(), StandardCharsets.UTF_8) + timeoutThreadDump;
    assertFalse(reader.isAlive(), name + " output reader did not finish\n" + text);
    Throwable readFailure = readerFailure.get();
    if (readFailure != null) {
      throw new AssertionError("cannot read " + name + " output\n" + text, readFailure);
    }
    assertTrue(completed, name + " timed out\n" + text);
    assertFalse(process.isAlive(), name + " did not terminate\n" + text);
    assertEquals(0, process.exitValue(), text);
    return text;
  }

  private static String captureThreadDump(Process target) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    AtomicReference<Throwable> readerFailure = new AtomicReference<>();
    Process dumpProcess = null;
    Thread reader = null;
    try {
      long pid = ((Number) Process.class.getMethod("pid").invoke(target)).longValue();
      File jcmd = new File(System.getProperty("java.home"), "bin/jcmd");
      dumpProcess =
          new ProcessBuilder(jcmd.getAbsolutePath(), Long.toString(pid), "Thread.print", "-l")
              .redirectErrorStream(true)
              .start();
      reader = copyOutput(dumpProcess.getInputStream(), output, readerFailure);
      if (!dumpProcess.waitFor(10, TimeUnit.SECONDS)) {
        dumpProcess.destroyForcibly();
        dumpProcess.waitFor(2, TimeUnit.SECONDS);
      }
      reader.join(TimeUnit.SECONDS.toMillis(2));
      Throwable failure = readerFailure.get();
      if (failure != null) {
        throw failure;
      }
      return "\nOBI_TEST_THREAD_DUMP\n" + new String(output.toByteArray(), StandardCharsets.UTF_8);
    } catch (Throwable failure) {
      return "\nOBI_TEST_THREAD_DUMP_UNAVAILABLE " + failure.getClass().getName() + "\n";
    } finally {
      if (dumpProcess != null && dumpProcess.isAlive()) {
        dumpProcess.destroyForcibly();
      }
      if (reader != null && reader.isAlive()) {
        try {
          reader.join(TimeUnit.SECONDS.toMillis(2));
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
        }
      }
    }
  }

  private static Thread copyOutput(
      InputStream input, ByteArrayOutputStream output, AtomicReference<Throwable> readerFailure) {
    Thread reader =
        new Thread(
            () -> {
              byte[] buffer = new byte[4096];
              int read;
              try {
                while ((read = input.read(buffer)) >= 0) {
                  output.write(buffer, 0, read);
                }
              } catch (Throwable failure) {
                readerFailure.compareAndSet(null, failure);
              }
            },
            "official-agent-java21-output");
    reader.setDaemon(true);
    reader.start();
    return reader;
  }

  private static void assertNoAgentProvidedClasses(File extension) throws Exception {
    try (JarFile jar = new JarFile(extension)) {
      Enumeration<JarEntry> entries = jar.entries();
      while (entries.hasMoreElements()) {
        String name = entries.nextElement().getName();
        assertFalse(
            name.startsWith("io/opentelemetry/api/")
                || name.startsWith("io/opentelemetry/context/")
                || name.startsWith("io/opentelemetry/javaagent/")
                || name.startsWith("io/opentelemetry/sdk/"),
            "extension supplies agent class " + name);
      }
    }
  }

  private static String sha256(Path path) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (InputStream input = Files.newInputStream(path)) {
      byte[] buffer = new byte[8192];
      int read;
      while ((read = input.read(buffer)) >= 0) {
        digest.update(buffer, 0, read);
      }
    }
    StringBuilder result = new StringBuilder(64);
    for (byte value : digest.digest()) {
      result.append(String.format("%02x", value & 0xff));
    }
    return result.toString();
  }

  private static String requiredProperty(String name) {
    String value = System.getProperty(name);
    assertTrue(value != null && !value.isEmpty(), "missing system property " + name);
    return value;
  }

  private static int javaMajorVersion() {
    String version = System.getProperty("java.specification.version");
    return version.startsWith("1.")
        ? Integer.parseInt(version.substring(2))
        : Integer.parseInt(version);
  }

  private static boolean parseBoolean(String value, String line) {
    assertTrue("true".equals(value) || "false".equals(value), line);
    return "true".equals(value);
  }

  private static final class ProbeRecords {
    private final Map<String, String[]> owners = new HashMap<>();
    private final Map<String, String[]> bodies = new HashMap<>();
    private final Map<String, String[]> migrations = new HashMap<>();
    private final Map<String, String[]> edges = new HashMap<>();
    private final Map<String, String[]> spans = new HashMap<>();
    private final Map<String, String[]> virtuals = new HashMap<>();
    private final Map<String, String[]> relays = new HashMap<>();
    private final Map<String, String[]> terminations = new HashMap<>();
    private final Map<String, String[]> baselines = new HashMap<>();
    private final Map<String, String[]> cleanups = new HashMap<>();
    private final Set<String> waves = new HashSet<>();

    private static ProbeRecords parse(List<String> outputLines) {
      ProbeRecords result = new ProbeRecords();
      int finalMarkers = 0;
      for (String line : outputLines) {
        if (!line.startsWith("OBI_JAVA21_")) {
          continue;
        }
        String[] fields = line.split("\\t", -1);
        if ("OBI_JAVA21_OWNER".equals(fields[0])) {
          assertEquals(9, fields.length, line);
          unique(result.owners, fields[1], fields, line);
        } else if ("OBI_JAVA21_BODY".equals(fields[0])) {
          assertEquals(14, fields.length, line);
          unique(result.bodies, fields[1], fields, line);
        } else if ("OBI_JAVA21_MIGRATION".equals(fields[0])) {
          assertEquals(9, fields.length, line);
          unique(result.migrations, fields[1], fields, line);
        } else if ("OBI_JAVA21_EDGE".equals(fields[0])) {
          assertEquals(10, fields.length, line);
          unique(result.edges, fields[1], fields, line);
        } else if ("OBI_JAVA21_SPAN".equals(fields[0])) {
          assertEquals(7, fields.length, line);
          unique(result.spans, fields[1], fields, line);
        } else if ("OBI_JAVA21_VIRTUAL".equals(fields[0])) {
          assertEquals(5, fields.length, line);
          unique(result.virtuals, fields[1], fields, line);
        } else if ("OBI_JAVA21_RELAY".equals(fields[0])) {
          assertEquals(14, fields.length, line);
          unique(result.relays, fields[1], fields, line);
        } else if ("OBI_JAVA21_TERMINATION".equals(fields[0])) {
          assertEquals(16, fields.length, line);
          unique(result.terminations, fields[1], fields, line);
        } else if ("OBI_JAVA21_BASELINE".equals(fields[0])) {
          assertEquals(5, fields.length, line);
          unique(result.baselines, fields[1] + "/" + fields[2], fields, line);
        } else if ("OBI_JAVA21_CLEANUP".equals(fields[0])) {
          assertEquals(15, fields.length, line);
          unique(result.cleanups, fields[1] + "/" + fields[2] + "/" + fields[3], fields, line);
        } else if ("OBI_JAVA21_WAVE".equals(fields[0])) {
          assertEquals(3, fields.length, line);
          assertTrue(result.waves.add(fields[1] + "/" + fields[2]), "duplicate wave " + line);
        } else if ("OBI_JAVA21_PROBE".equals(fields[0])) {
          assertEquals(SUCCESS_MARKER, line);
          finalMarkers++;
        } else if ("OBI_JAVA21_DIAGNOSTICS".equals(fields[0])) {
          assertEquals(2, fields.length, line);
        } else {
          throw new AssertionError("unknown Java 21 probe record " + line);
        }
      }
      assertEquals(1, finalMarkers, outputLines.toString());
      result.assertKeySets(outputLines);
      result.assertInfrastructure(outputLines);
      return result;
    }

    private void assertKeySets(List<String> outputLines) {
      Set<String> expectedIds = new HashSet<>(ids());
      Set<String> expectedVirtuals = new HashSet<>();
      Set<String> expectedEdges = new HashSet<>();
      for (String id : expectedIds) {
        if (id.charAt(2) == 'V') {
          expectedVirtuals.add(id);
        }
        if (id.startsWith("W1")) {
          expectedEdges.add(id);
        }
      }
      Set<String> expectedMigrations = new HashSet<>(expectedVirtuals);
      Set<String> expectedRelays = new HashSet<>(relayIds());
      expectedEdges.addAll(expectedRelays);
      expectedVirtuals.add("R1V00");
      expectedVirtuals.add("R1V01");
      assertEquals(expectedIds, owners.keySet(), outputLines.toString());
      assertEquals(expectedIds, bodies.keySet(), outputLines.toString());
      assertEquals(expectedIds, spans.keySet(), outputLines.toString());
      assertEquals(expectedMigrations, migrations.keySet(), outputLines.toString());
      assertEquals(expectedVirtuals, virtuals.keySet(), outputLines.toString());
      assertEquals(expectedEdges, edges.keySet(), outputLines.toString());
      assertEquals(expectedRelays, relays.keySet(), outputLines.toString());
      assertEquals(expectedVirtuals, terminations.keySet(), outputLines.toString());

      Set<String> expectedBaselines = new HashSet<>();
      Set<String> expectedCleanups = new HashSet<>();
      for (String kind : new String[] {"CARRIER", "PLATFORM"}) {
        for (int index = 0; index < 4; index++) {
          expectedBaselines.add(kind + "/" + index);
          expectedCleanups.add("1/" + kind + "/" + index);
          expectedCleanups.add("2/" + kind + "/" + index);
        }
      }
      assertEquals(expectedBaselines, baselines.keySet(), outputLines.toString());
      assertEquals(expectedCleanups, cleanups.keySet(), outputLines.toString());
      Set<String> expectedWaves = new HashSet<>();
      for (int wave = 1; wave <= 2; wave++) {
        expectedWaves.add(wave + "/START");
        expectedWaves.add(wave + "/RELEASE");
        expectedWaves.add(wave + "/END");
      }
      assertEquals(expectedWaves, waves, outputLines.toString());
    }

    private void assertInfrastructure(List<String> outputLines) {
      Set<Long> edgeTokens = new HashSet<>();
      Set<Long> edgeCaptureSequences = new HashSet<>();
      Set<Long> edgeLinkSequences = new HashSet<>();
      Set<Long> edgeSequences = new HashSet<>();
      for (String[] edge : edges.values()) {
        long token = Long.parseLong(edge[3]);
        long captureSequence = Long.parseLong(edge[7]);
        long linkSequence = Long.parseLong(edge[8]);
        assertTrue(token != 0L, record(edge));
        assertTrue(edgeTokens.add(token), "duplicate edge token " + token);
        assertTrue(
            edgeCaptureSequences.add(captureSequence),
            "duplicate capture sequence " + captureSequence);
        assertTrue(edgeLinkSequences.add(linkSequence), "duplicate link sequence " + linkSequence);
        assertTrue(
            edgeSequences.add(captureSequence), "reused task-event sequence " + captureSequence);
        assertTrue(edgeSequences.add(linkSequence), "reused task-event sequence " + linkSequence);
      }
      assertEquals(24, edgeTokens.size(), outputLines.toString());
      assertEquals(48, edgeSequences.size(), outputLines.toString());

      for (int index = 0; index < 4; index++) {
        String suffix = "P" + twoDigits(index);
        assertEquals(
            owners.get("W1" + suffix)[8],
            owners.get("W2" + suffix)[8],
            "platform Runnable identity changed at " + index);
      }

      Set<Long> allJavaThreads = new HashSet<>();
      Set<Long> allNativeThreads = new HashSet<>();
      Map<String, Set<Long>> baselineJava = new HashMap<>();
      Map<String, Set<Long>> baselineNative = new HashMap<>();
      for (String kind : new String[] {"CARRIER", "PLATFORM"}) {
        Set<Long> javaThreads = new HashSet<>();
        Set<Long> nativeThreads = new HashSet<>();
        for (int index = 0; index < 4; index++) {
          String[] baseline = baselines.get(kind + "/" + index);
          assertEquals(kind, baseline[1], record(baseline));
          assertEquals(index, Integer.parseInt(baseline[2]), record(baseline));
          long javaThread = Long.parseLong(baseline[3]);
          long nativeThread = Long.parseLong(baseline[4]);
          assertTrue(javaThread > 0L && nativeThread > 0L, record(baseline));
          assertTrue(javaThreads.add(javaThread), "duplicate baseline Java thread " + javaThread);
          assertTrue(
              nativeThreads.add(nativeThread), "duplicate baseline native thread " + nativeThread);
          assertTrue(allJavaThreads.add(javaThread), "cross-pool Java thread " + javaThread);
          assertTrue(
              allNativeThreads.add(nativeThread), "cross-pool native thread " + nativeThread);
          for (int wave = 1; wave <= 2; wave++) {
            String[] cleanup = cleanups.get(wave + "/" + kind + "/" + index);
            assertEquals(Integer.toString(wave), cleanup[1], record(cleanup));
            assertEquals(kind, cleanup[2], record(cleanup));
            assertEquals(index, Integer.parseInt(cleanup[3]), record(cleanup));
            assertEquals(javaThread, Long.parseLong(cleanup[4]), record(cleanup));
            assertEquals(nativeThread, Long.parseLong(cleanup[5]), record(cleanup));
            assertEquals(1, Integer.parseInt(cleanup[6]), record(cleanup));
            assertFalse(parseBoolean(cleanup[7], record(cleanup)), record(cleanup));
            assertEquals("NONE", cleanup[8], record(cleanup));
            assertEquals(-1, Integer.parseInt(cleanup[9]), record(cleanup));
            assertFalse(parseBoolean(cleanup[10], record(cleanup)), record(cleanup));
            assertTrue(parseBoolean(cleanup[11], record(cleanup)), record(cleanup));
            assertFalse(parseBoolean(cleanup[12], record(cleanup)), record(cleanup));
            assertEquals(0, Integer.parseInt(cleanup[13]), record(cleanup));
            assertEquals("NONE", cleanup[14], record(cleanup));
          }
        }
        baselineJava.put(kind, javaThreads);
        baselineNative.put(kind, nativeThreads);
      }
      assertEquals(8, allJavaThreads.size(), outputLines.toString());
      assertEquals(8, allNativeThreads.size(), outputLines.toString());

      Set<Long> allVirtualThreads = new HashSet<>();
      for (int wave = 1; wave <= 2; wave++) {
        Set<Long> platformJava = new HashSet<>();
        Set<Long> platformNative = new HashSet<>();
        Set<Long> virtualJava = new HashSet<>();
        Set<Long> carrierJava = new HashSet<>();
        Set<Long> carrierNative = new HashSet<>();
        for (String id : ids()) {
          if (!id.startsWith("W" + wave)) {
            continue;
          }
          String[] body = bodies.get(id);
          if (id.charAt(2) == 'P') {
            platformJava.add(Long.parseLong(body[4]));
            platformNative.add(Long.parseLong(body[5]));
          } else {
            String[] migration = migrations.get(id);
            long virtualThread = Long.parseLong(body[4]);
            assertTrue(virtualJava.add(virtualThread), "duplicate wave virtual thread " + id);
            assertTrue(allVirtualThreads.add(virtualThread), "reused virtual-thread id " + id);
            carrierJava.add(Long.parseLong(migration[3]));
            carrierJava.add(Long.parseLong(migration[5]));
            carrierNative.add(Long.parseLong(migration[4]));
            carrierNative.add(Long.parseLong(migration[6]));
          }
        }
        assertEquals(baselineJava.get("PLATFORM"), platformJava, outputLines.toString());
        assertEquals(baselineNative.get("PLATFORM"), platformNative, outputLines.toString());
        assertEquals(16, virtualJava.size(), outputLines.toString());
        assertEquals(baselineJava.get("CARRIER"), carrierJava, outputLines.toString());
        assertEquals(baselineNative.get("CARRIER"), carrierNative, outputLines.toString());
      }
      for (String relayId : relayIds()) {
        String[] relay = relays.get(relayId);
        String parentId = relay[2];
        String[] parentBody = bodies.get(parentId);
        String[] parentOwner = owners.get(parentId);
        assertEquals(relayId.charAt(2) == 'V' ? "VIRTUAL" : "PLATFORM", relay[3], record(relay));
        long childJavaThread = Long.parseLong(relay[4]);
        long childNativeThread = Long.parseLong(relay[5]);
        assertTrue(childJavaThread > 0L && childNativeThread > 0L, record(relay));
        assertNotEquals(Long.parseLong(parentBody[4]), childJavaThread, record(relay));
        assertNotEquals(Long.parseLong(parentBody[5]), childNativeThread, record(relay));
        assertEquals(2, Integer.parseInt(relay[6]), record(relay));
        assertEquals("LIVE", relay[7], record(relay));
        assertEquals(Integer.parseInt(parentOwner[5]), Integer.parseInt(relay[8]), record(relay));
        assertEquals(Integer.parseInt(parentOwner[4]), Integer.parseInt(relay[9]), record(relay));
        assertTrue(parseBoolean(relay[10], record(relay)), record(relay));
        assertTrue(parseBoolean(relay[11], record(relay)), record(relay));
        assertTrue(parseBoolean(relay[12], record(relay)), record(relay));
        Integer.parseInt(relay[13]);

        String[] relayEdge = edges.get(relayId);
        String[] parentEdge = edges.get(parentId);
        assertEquals("TASK_RELAY_CAPTURE", relayEdge[2], record(relayEdge));
        assertEquals(
            Long.parseLong(parentBody[5]), Long.parseLong(relayEdge[4]), record(relayEdge));
        assertEquals(
            Long.parseLong(parentEdge[6]), Long.parseLong(relayEdge[4]), record(relayEdge));
        assertEquals(Long.parseLong(relayEdge[4]), Long.parseLong(relayEdge[5]), record(relayEdge));
        assertEquals(childNativeThread, Long.parseLong(relayEdge[6]), record(relayEdge));
        assertEquals(childJavaThread, Long.parseLong(relayEdge[9]), record(relayEdge));
        assertTrue(Long.parseLong(parentEdge[8]) < Long.parseLong(relayEdge[7]), record(relayEdge));
        assertTrue(Long.parseLong(relayEdge[7]) < Long.parseLong(relayEdge[8]), record(relayEdge));

        if (relayId.charAt(2) == 'V') {
          assertTrue(
              allVirtualThreads.add(childJavaThread), "reused relay virtual thread " + relayId);
          assertTrue(baselineNative.get("CARRIER").contains(childNativeThread), record(relay));
          String[] virtual = virtuals.get(relayId);
          int mounts = Integer.parseInt(virtual[2]);
          assertTrue(mounts >= 1, record(virtual));
          assertEquals(mounts, Integer.parseInt(virtual[3]), record(virtual));
          assertEquals(1, Integer.parseInt(virtual[4]), record(virtual));
        } else {
          assertTrue(baselineJava.get("PLATFORM").contains(childJavaThread), record(relay));
          assertTrue(baselineNative.get("PLATFORM").contains(childNativeThread), record(relay));
        }
      }
      assertEquals(34, allVirtualThreads.size(), outputLines.toString());

      Set<Long> terminatedVirtualThreads = new HashSet<>();
      for (Map.Entry<String, String[]> entry : terminations.entrySet()) {
        String id = entry.getKey();
        String[] termination = entry.getValue();
        long virtualThread = Long.parseLong(termination[2]);
        assertTrue(
            terminatedVirtualThreads.add(virtualThread),
            "duplicate terminated virtual thread " + virtualThread);
        assertEquals(virtualThread, Long.parseLong(termination[3]), record(termination));
        assertTrue(virtualThread > 0L, record(termination));
        assertTrue(
            baselineNative.get("CARRIER").contains(Long.parseLong(termination[4])),
            record(termination));
        assertEquals(
            id.startsWith("W2") ? 3 : 1, Integer.parseInt(termination[5]), record(termination));
        assertFalse(parseBoolean(termination[6], record(termination)), record(termination));
        assertEquals("NONE", termination[7], record(termination));
        assertEquals(0, Integer.parseInt(termination[8]), record(termination));
        assertEquals(-1, Integer.parseInt(termination[9]), record(termination));
        assertFalse(parseBoolean(termination[10], record(termination)), record(termination));
        assertFalse(parseBoolean(termination[11], record(termination)), record(termination));
        assertFalse(parseBoolean(termination[12], record(termination)), record(termination));
        assertFalse(parseBoolean(termination[13], record(termination)), record(termination));
        assertEquals(0, Integer.parseInt(termination[14]), record(termination));
        assertEquals("NONE", termination[15], record(termination));
      }
      assertEquals(allVirtualThreads, terminatedVirtualThreads, outputLines.toString());
      assertOrdering(outputLines);
    }

    private void assertOwner(String id, AuthorityResult authority, SpanResult extensionSpan) {
      String[] owner = owners.get(id);
      String[] body = bodies.get(id);
      String[] probeSpan = spans.get(id);
      int wave = id.charAt(1) - '0';
      String kind = id.charAt(2) == 'V' ? "VIRTUAL" : "PLATFORM";
      assertEquals(wave, Integer.parseInt(owner[2]), record(owner));
      assertEquals(kind, owner[3], record(owner));
      assertEquals(wave, Integer.parseInt(body[2]), record(body));
      assertEquals(kind, body[3], record(body));
      long taskJavaThread = Long.parseLong(body[4]);
      long taskNativeThread = Long.parseLong(body[5]);
      assertTrue(taskJavaThread > 0L && taskNativeThread > 0L, record(body));
      if (id.startsWith("W1P")) {
        String relayId = relayId(id);
        String[] relay = relays.get(relayId);
        assertEquals(Long.parseLong(relay[4]), authority.javaThreadId, record(relay));
        if ("VIRTUAL".equals(relay[3])) {
          assertTrue(hasBaselineNativeThread("CARRIER", authority.nativeThreadId), record(relay));
          if (Long.parseLong(relay[5]) != authority.nativeThreadId) {
            String[] virtual = virtuals.get(relayId);
            assertTrue(Integer.parseInt(virtual[2]) >= 2, record(virtual));
          }
        } else {
          assertEquals(Long.parseLong(relay[5]), authority.nativeThreadId, record(relay));
        }
      } else {
        assertEquals(taskJavaThread, authority.javaThreadId, record(body));
        assertEquals(taskNativeThread, authority.nativeThreadId, record(body));
      }
      assertEquals(authority.javaThreadId, Long.parseLong(probeSpan[6]), record(probeSpan));
      assertEquals(extensionSpan.traceId, probeSpan[4], record(probeSpan));
      assertEquals(extensionSpan.spanId, probeSpan[5], record(probeSpan));
      assertEquals(wave, Integer.parseInt(probeSpan[2]), record(probeSpan));
      assertEquals(kind, probeSpan[3], record(probeSpan));

      int bodySource = Integer.parseInt(body[10]);
      int bodyLifecycle = Integer.parseInt(body[12]);
      int bodySocket = Integer.parseInt(body[13]);
      if (wave == 1) {
        assertEquals(200 + ordinal(id), Integer.parseInt(owner[4]), record(owner));
        int ownerLifecycle = Integer.parseInt(owner[5]);
        assertNotEquals(0, ownerLifecycle, record(owner));
        assertEquals(expectedTraceId(id), owner[6], record(owner));
        assertEquals(expectedParentSpanId(id), owner[7], record(owner));
        assertEquals(2, bodySource, record(body));
        assertEquals("LIVE", body[11], record(body));
        assertEquals(ownerLifecycle, bodyLifecycle, record(body));
        assertEquals(200 + ordinal(id), bodySocket, record(body));
        assertEquals(ownerLifecycle, authority.lifecycleIdentity, record(body));

        String[] edge = edges.get(id);
        assertEquals("TASK_CAPTURE", edge[2], record(edge));
        long token = Long.parseLong(edge[3]);
        long captureNative = Long.parseLong(edge[4]);
        long linkParent = Long.parseLong(edge[5]);
        long linkChild = Long.parseLong(edge[6]);
        long captureSequence = Long.parseLong(edge[7]);
        long linkSequence = Long.parseLong(edge[8]);
        assertTrue(token != 0L, record(edge));
        assertEquals(captureNative, linkParent, record(edge));
        assertEquals(Long.parseLong(body[7]), linkChild, record(edge));
        assertTrue(captureSequence < linkSequence, record(edge));
        assertEquals(taskJavaThread, Long.parseLong(edge[9]), record(edge));
      } else {
        assertEquals(-1, Integer.parseInt(owner[4]), record(owner));
        assertEquals(0, Integer.parseInt(owner[5]), record(owner));
        assertEquals("-", owner[6], record(owner));
        assertEquals("-", owner[7], record(owner));
        assertEquals(3, bodySource, record(body));
        assertEquals("NONE", body[11], record(body));
        assertEquals(0, bodyLifecycle, record(body));
        assertEquals(-1, bodySocket, record(body));
      }

      if (id.charAt(2) == 'V') {
        String[] migration = migrations.get(id);
        String[] virtual = virtuals.get(id);
        assertEquals(taskJavaThread, Long.parseLong(migration[2]), record(migration));
        assertEquals(Long.parseLong(body[6]), Long.parseLong(migration[3]), record(migration));
        assertEquals(Long.parseLong(body[7]), Long.parseLong(migration[4]), record(migration));
        assertNotEquals(
            Long.parseLong(migration[3]), Long.parseLong(migration[5]), record(migration));
        assertNotEquals(
            Long.parseLong(migration[4]), Long.parseLong(migration[6]), record(migration));
        assertEquals(Long.parseLong(body[8]), Long.parseLong(migration[7]), record(migration));
        assertEquals(Long.parseLong(body[9]), Long.parseLong(migration[8]), record(migration));
        assertNotEquals(taskJavaThread, Long.parseLong(body[6]), record(body));
        assertNotEquals(taskJavaThread, Long.parseLong(body[8]), record(body));
        assertEquals(taskNativeThread, Long.parseLong(body[9]), record(body));
        int mounts = Integer.parseInt(virtual[2]);
        int unmounts = Integer.parseInt(virtual[3]);
        assertTrue(mounts >= 3, record(virtual));
        assertEquals(mounts, unmounts, record(virtual));
        assertEquals(1, Integer.parseInt(virtual[4]), record(virtual));
      } else {
        assertEquals(taskJavaThread, Long.parseLong(body[6]), record(body));
        assertEquals(taskNativeThread, Long.parseLong(body[7]), record(body));
        assertEquals(taskJavaThread, Long.parseLong(body[8]), record(body));
        assertEquals(taskNativeThread, Long.parseLong(body[9]), record(body));
      }
    }

    private boolean hasBaselineNativeThread(String kind, long nativeThreadId) {
      for (int index = 0; index < 4; index++) {
        String[] baseline = baselines.get(kind + "/" + index);
        if (Long.parseLong(baseline[4]) == nativeThreadId) {
          return true;
        }
      }
      return false;
    }

    private void assertOrdering(List<String> outputLines) {
      int firstStart = outputLines.indexOf("OBI_JAVA21_WAVE\t1\tSTART");
      int firstRelease = outputLines.indexOf("OBI_JAVA21_WAVE\t1\tRELEASE");
      int firstEnd = outputLines.indexOf("OBI_JAVA21_WAVE\t1\tEND");
      int secondStart = outputLines.indexOf("OBI_JAVA21_WAVE\t2\tSTART");
      int secondRelease = outputLines.indexOf("OBI_JAVA21_WAVE\t2\tRELEASE");
      int secondEnd = outputLines.indexOf("OBI_JAVA21_WAVE\t2\tEND");
      int passed = outputLines.indexOf(SUCCESS_MARKER);
      assertTrue(
          0 <= firstStart
              && firstStart < firstRelease
              && firstRelease < firstEnd
              && firstEnd < secondStart
              && secondStart < secondRelease
              && secondRelease < secondEnd
              && secondEnd < passed,
          outputLines.toString());

      for (String[] baseline : baselines.values()) {
        assertTrue(outputLines.indexOf(record(baseline)) < firstStart, record(baseline));
      }
      for (String id : ids()) {
        int wave = id.charAt(1) - '0';
        int start = wave == 1 ? firstStart : secondStart;
        int release = wave == 1 ? firstRelease : secondRelease;
        int end = wave == 1 ? firstEnd : secondEnd;
        int owner = outputLines.indexOf(record(owners.get(id)));
        int body = outputLines.indexOf(record(bodies.get(id)));
        int span = outputLines.indexOf(record(spans.get(id)));
        assertTrue(start < owner && owner < release, record(owners.get(id)));
        assertTrue(release < body && body < end, record(bodies.get(id)));
        assertTrue(release < span && span < end, record(spans.get(id)));
        if (id.charAt(2) == 'V') {
          int migration = outputLines.indexOf(record(migrations.get(id)));
          assertTrue(release < migration && migration < body, record(migrations.get(id)));
          int termination = outputLines.indexOf(record(terminations.get(id)));
          assertTrue(span < termination && termination < end, record(terminations.get(id)));
        }
        int virtual = id.charAt(2) == 'V' ? outputLines.indexOf(record(virtuals.get(id))) : -1;
        if (wave == 1) {
          int edge = outputLines.indexOf(record(edges.get(id)));
          assertTrue(firstEnd < edge && edge < secondStart, record(edges.get(id)));
          if (virtual >= 0) {
            assertTrue(firstEnd < virtual && virtual < secondStart, record(virtuals.get(id)));
          }
        } else if (virtual >= 0) {
          assertTrue(secondEnd < virtual && virtual < passed, record(virtuals.get(id)));
        }
      }
      for (String relayId : relayIds()) {
        String[] relay = relays.get(relayId);
        String parentId = relay[2];
        int parentBody = outputLines.indexOf(record(bodies.get(parentId)));
        int relayRecord = outputLines.indexOf(record(relay));
        int parentSpan = outputLines.indexOf(record(spans.get(parentId)));
        int relayEdge = outputLines.indexOf(record(edges.get(relayId)));
        assertTrue(firstRelease < parentBody && parentBody < relayRecord, record(relay));
        assertTrue(relayRecord < parentSpan && parentSpan < firstEnd, record(relay));
        assertTrue(firstEnd < relayEdge && relayEdge < secondStart, record(edges.get(relayId)));
        if (relayId.charAt(2) == 'V') {
          int termination = outputLines.indexOf(record(terminations.get(relayId)));
          int virtual = outputLines.indexOf(record(virtuals.get(relayId)));
          assertTrue(
              parentSpan < termination && termination < firstEnd,
              record(terminations.get(relayId)));
          assertTrue(firstEnd < virtual && virtual < secondStart, record(virtuals.get(relayId)));
        }
      }
      for (Map.Entry<String, String[]> entry : cleanups.entrySet()) {
        int cleanup = outputLines.indexOf(record(entry.getValue()));
        if (entry.getKey().startsWith("1/")) {
          assertTrue(firstEnd < cleanup && cleanup < secondStart, record(entry.getValue()));
        } else {
          assertTrue(secondEnd < cleanup && cleanup < passed, record(entry.getValue()));
        }
      }
    }

    private static void unique(
        Map<String, String[]> records, String key, String[] fields, String line) {
      assertTrue(records.put(key, fields) == null, "duplicate Java 21 record " + line);
    }

    private static String record(String[] fields) {
      StringBuilder result = new StringBuilder();
      for (int index = 0; index < fields.length; index++) {
        if (index > 0) {
          result.append('\t');
        }
        result.append(fields[index]);
      }
      return result.toString();
    }
  }

  private static final class PassResult {
    private final int pass;
    private final String traceId;
    private final String spanId;
    private final boolean remote;
    private final boolean sampled;

    private PassResult(int pass, String traceId, String spanId, boolean remote, boolean sampled) {
      this.pass = pass;
      this.traceId = traceId;
      this.spanId = spanId;
      this.remote = remote;
      this.sampled = sampled;
    }

    private static PassResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(8, fields.length, line);
      return new PassResult(
          Integer.parseInt(fields[3]),
          fields[4],
          fields[5],
          parseBoolean(fields[6], line),
          parseBoolean(fields[7], line));
    }
  }

  private static final class ProviderResult {
    private final int pass;
    private final String status;

    private ProviderResult(int pass, String status) {
      this.pass = pass;
      this.status = status;
    }

    private static ProviderResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(6, fields.length, line);
      assertEquals("PROVIDER", fields[0], line);
      assertEquals("TAKE", fields[1], line);
      assertEquals(1, Integer.parseInt(fields[3]), line);
      return new ProviderResult(Integer.parseInt(fields[4]), fields[5]);
    }
  }

  private static final class AuthorityResult {
    private final int pass;
    private final int source;
    private final boolean direct;
    private final boolean lifecycleActive;
    private final int lifecycleIdentity;
    private final int socketFileDescriptor;
    private final boolean exact;
    private final boolean socketContextPresent;
    private final long javaThreadId;
    private final long nativeThreadId;

    private AuthorityResult(
        int pass,
        int source,
        boolean direct,
        boolean lifecycleActive,
        int lifecycleIdentity,
        int socketFileDescriptor,
        boolean exact,
        boolean socketContextPresent,
        long javaThreadId,
        long nativeThreadId) {
      this.pass = pass;
      this.source = source;
      this.direct = direct;
      this.lifecycleActive = lifecycleActive;
      this.lifecycleIdentity = lifecycleIdentity;
      this.socketFileDescriptor = socketFileDescriptor;
      this.exact = exact;
      this.socketContextPresent = socketContextPresent;
      this.javaThreadId = javaThreadId;
      this.nativeThreadId = nativeThreadId;
    }

    private static AuthorityResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(15, fields.length, line);
      assertEquals("JAVA21", fields[1], line);
      assertEquals("TAKE", fields[2], line);
      assertTrue("LIVE".equals(fields[8]) || "NONE".equals(fields[8]), line);
      return new AuthorityResult(
          Integer.parseInt(fields[5]),
          Integer.parseInt(fields[6]),
          parseBoolean(fields[7], line),
          "LIVE".equals(fields[8]),
          Integer.parseInt(fields[9]),
          Integer.parseInt(fields[10]),
          parseBoolean(fields[11], line),
          parseBoolean(fields[12], line),
          Long.parseLong(fields[13]),
          Long.parseLong(fields[14]));
    }
  }

  private static final class SpanResult {
    private final String line;
    private final String id;
    private final String traceId;
    private final String spanId;
    private final String parentSpanId;
    private final boolean parentRemote;
    private final boolean parentSampled;
    private final boolean spanSampled;
    private final String scope;
    private final String route;

    private SpanResult(
        String line,
        String id,
        String traceId,
        String spanId,
        String parentSpanId,
        boolean parentRemote,
        boolean parentSampled,
        boolean spanSampled,
        String scope,
        String route) {
      this.line = line;
      this.id = id;
      this.traceId = traceId;
      this.spanId = spanId;
      this.parentSpanId = parentSpanId;
      this.parentRemote = parentRemote;
      this.parentSampled = parentSampled;
      this.spanSampled = spanSampled;
      this.scope = scope;
      this.route = route;
    }

    private static SpanResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(10, fields.length, line);
      return new SpanResult(
          line,
          fields[1],
          fields[2],
          fields[3],
          fields[4],
          parseBoolean(fields[5], line),
          parseBoolean(fields[6], line),
          parseBoolean(fields[7], line),
          fields[8],
          fields[9]);
    }
  }
}
