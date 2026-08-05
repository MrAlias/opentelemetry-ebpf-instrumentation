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
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class OfficialAgentJettyRuntimeTest {
  private static final String MODE_BLOCKING = "blocking";
  private static final String MODE_DEFAULT = "default";
  private static final String MODE_HELPER_ABSENT = "helper-absent";
  private static final String MODE_NESTED = "nested";
  private static final String MODE_STANDARD_FIRST = "standard-first";

  private static final String TRACE_A = "11111111111111111111111111111111";
  private static final String PARENT_A = "2222222222222222";
  private static final String TRACE_B = "33333333333333333333333333333333";
  private static final String PARENT_B = "4444444444444444";
  private static final String TRACE_W3C_ONLY = "12121212121212121212121212121212";
  private static final String PARENT_W3C_ONLY = "1313131313131313";
  private static final String TRACE_MATCHING = "34343434343434343434343434343434";
  private static final String PARENT_MATCHING = "5656565656565656";
  private static final String TRACE_W3C = "55555555555555555555555555555555";
  private static final String PARENT_W3C = "6666666666666666";
  private static final String TRACE_CONFLICT = "77777777777777777777777777777777";
  private static final String PARENT_CONFLICT = "8888888888888888";
  private static final String TRACE_MALFORMED_W3C = "90909090909090909090909090909090";
  private static final String PARENT_MALFORMED_W3C = "9191919191919191";
  private static final String TRACE_STALE_W3C = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
  private static final String PARENT_STALE_W3C = "b2b2b2b2b2b2b2b2";
  private static final String TRACE_MALFORMED_OBI_W3C = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
  private static final String PARENT_MALFORMED_OBI_W3C = "d4d4d4d4d4d4d4d4";
  private static final String TRACE_P = "99999999999999999999999999999999";
  private static final String PARENT_P = "aaaaaaaaaaaaaaaa";
  private static final String TRACE_Q = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  private static final String PARENT_Q = "cccccccccccccccc";
  private static final String TRACE_D_W3C = "dddddddddddddddddddddddddddddddd";
  private static final String PARENT_D_W3C = "eeeeeeeeeeeeeeee";
  private static final String TRACE_D_OBI = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";
  private static final String PARENT_D_OBI = "abababababababab";
  private static final String TRACE_T = "20202020202020202020202020202020";
  private static final String PARENT_T = "2121212121212121";
  private static final String INVALID_TRACE = "00000000000000000000000000000000";
  private static final String INVALID_SPAN = "0000000000000000";

  @Test
  void unmodifiedOpenTelemetryAgentPreservesJettyParents() throws Exception {
    verifyAgent(
        "OBI_TEST_OTEL_AGENT",
        "faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",
        "distribution=opentelemetry",
        "agent_version=2.28.1");
  }

  @Test
  void unmodifiedSplunkAgentPreservesJettyParents() throws Exception {
    verifyAgent(
        "OBI_TEST_SPLUNK_AGENT",
        "70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351",
        "distribution=splunk",
        "agent_version=splunk-2.28.0-otel-2.28.1");
  }

  private static void verifyAgent(
      String environmentName, String expectedSha256, String distribution, String version)
      throws Exception {
    String agentPath = System.getenv(environmentName);
    Assumptions.assumeTrue(
        agentPath != null && !agentPath.isEmpty(), environmentName + " is unset");

    File officialAgent = new File(agentPath);
    assertTrue(officialAgent.isFile() && officialAgent.length() > 0, officialAgent.toString());
    assertEquals(expectedSha256, sha256(officialAgent.toPath()));
    Assumptions.assumeTrue(javaMajorVersion() >= 11, "Jetty 11 requires Java 11 or newer");

    File helper = new File(requiredProperty("obi.test.packaged.agent"));
    File extension = new File(requiredProperty("obi.test.extension.jar"));
    File probeExtension = new File(requiredProperty("obi.test.official.agent.probe.extension.jar"));
    String probeClasspath = requiredProperty("obi.test.official.agent.probe.app.classpath");
    assertTrue(helper.isFile() && helper.length() > 0, helper.toString());
    assertTrue(extension.isFile() && extension.length() > 0, extension.toString());
    assertTrue(probeExtension.isFile() && probeExtension.length() > 0, probeExtension.toString());
    assertFalse(probeClasspath.isEmpty());
    assertFalse(probeClasspath.contains("opentelemetry-api-"), probeClasspath);
    assertFalse(probeClasspath.contains("opentelemetry-sdk-"), probeClasspath);
    assertFalse(probeClasspath.contains("opentelemetry-javaagent"), probeClasspath);
    assertNoAgentProvidedClasses(extension);
    assertNoAgentProvidedClasses(probeExtension);

    runMode(
        officialAgent,
        expectedSha256,
        helper,
        extension,
        probeExtension,
        probeClasspath,
        distribution,
        version,
        MODE_BLOCKING,
        "obi,tracecontext,baggage",
        true,
        null,
        true);
    runMode(
        officialAgent,
        expectedSha256,
        helper,
        extension,
        probeExtension,
        probeClasspath,
        distribution,
        version,
        MODE_DEFAULT,
        "obi,tracecontext,baggage",
        true,
        null,
        true);
    // Jetty starts the span, while the nested Servlet advice adds the servlet mapping route. The
    // paired disabled-module run proves that the route came from an actual second stock server
    // advice rather than from the probe or Jetty itself.
    runMode(
        officialAgent,
        expectedSha256,
        helper,
        extension,
        probeExtension,
        probeClasspath,
        distribution,
        version,
        MODE_NESTED,
        "obi,tracecontext,baggage",
        true,
        "_probe__",
        true);
    runMode(
        officialAgent,
        expectedSha256,
        helper,
        extension,
        probeExtension,
        probeClasspath,
        distribution,
        version,
        MODE_NESTED,
        "obi,tracecontext,baggage",
        false,
        "-",
        true);
    runMode(
        officialAgent,
        expectedSha256,
        helper,
        extension,
        probeExtension,
        probeClasspath,
        distribution,
        version,
        MODE_STANDARD_FIRST,
        "tracecontext,obi,baggage",
        true,
        null,
        true);
    runMode(
        officialAgent,
        expectedSha256,
        helper,
        extension,
        probeExtension,
        probeClasspath,
        distribution,
        version,
        MODE_HELPER_ABSENT,
        "obi,tracecontext,baggage",
        true,
        null,
        false);
    assertEquals(expectedSha256, sha256(officialAgent.toPath()));
  }

  private static void runMode(
      File officialAgent,
      String expectedSha256,
      File helper,
      File extension,
      File probeExtension,
      String probeClasspath,
      String distribution,
      String version,
      String mode,
      String propagators,
      boolean servletEnabled,
      String nestedExpectedRoute,
      boolean helperEnabled)
      throws Exception {
    Path directory = Files.createTempDirectory("obi-official-agent-jetty-");
    Path result = directory.resolve("spans.tsv");
    try {
      List<String> command = new ArrayList<>();
      command.add(new File(System.getProperty("java.home"), "bin/java").getAbsolutePath());
      if (helperEnabled) {
        command.add("-javaagent:" + helper.getAbsolutePath() + "=remoteParentTransport=disabled");
      } else {
        command.add("-Dobi.test.official.agent.probe.install-provider=false");
      }
      command.add("-javaagent:" + officialAgent.getAbsolutePath());
      command.add(
          "-Dotel.javaagent.extensions="
              + extension.getAbsolutePath()
              + ","
              + probeExtension.getAbsolutePath());
      command.add("-Dotel.propagators=" + propagators);
      command.add("-Dotel.obi.remote.parent.enabled=true");
      command.add("-Dotel.traces.sampler=always_on");
      command.add("-Dotel.traces.exporter=none");
      command.add("-Dotel.metrics.exporter=none");
      command.add("-Dotel.logs.exporter=none");
      command.add("-Dotel.service.name=obi-official-agent-jetty-probe");
      command.add("-Dobi.test.official.agent.probe.output=" + result);
      command.add("-Dobi.test.official.agent.probe.mode=" + mode);
      if (MODE_DEFAULT.equals(mode)) {
        command.add("-Dobi.test.official.agent.probe.reextract.id=A");
      }
      if (!servletEnabled) {
        command.add("-Dotel.instrumentation.servlet.enabled=false");
      }
      command.add("-cp");
      command.add(probeClasspath);
      command.add("io.opentelemetry.obi.java.extension.probe.OfficialAgentJettyProbe");

      String output;
      try {
        output = run(command);
      } catch (Throwable failure) {
        String partialResult =
            Files.isRegularFile(result)
                ? new String(Files.readAllBytes(result), StandardCharsets.UTF_8)
                : "<missing>";
        throw new AssertionError("official-agent probe result:\n" + partialResult, failure);
      }
      List<String> lines = Files.readAllLines(result, StandardCharsets.UTF_8);
      try {
        assertCommonOutput(output, mode, distribution, version);
        if (helperEnabled) {
          assertCommonResult(lines);
        } else {
          assertHelperAbsentResult(lines, output);
        }
        if (MODE_BLOCKING.equals(mode)) {
          assertBlockingResult(lines, output);
        } else if (MODE_DEFAULT.equals(mode)) {
          assertDefaultResult(lines, output);
        } else if (MODE_NESTED.equals(mode)) {
          assertTrue(nestedExpectedRoute != null, "missing nested route oracle");
          assertNestedResult(lines, output, MODE_NESTED, nestedExpectedRoute);
        } else if (MODE_STANDARD_FIRST.equals(mode)) {
          assertStandardFirstResult(lines, output);
        } else if (MODE_HELPER_ABSENT.equals(mode)) {
          assertHelperAbsentSpans(lines, output);
        } else {
          throw new AssertionError("unsupported mode " + mode);
        }
        assertEquals(expectedSha256, sha256(officialAgent.toPath()));
      } catch (Throwable failure) {
        throw new AssertionError(
            "official-agent output:\n" + output + "\nofficial-agent probe result:\n" + lines,
            failure);
      }
    } finally {
      Files.deleteIfExists(result);
      Files.deleteIfExists(directory);
    }
  }

  private static void assertCommonOutput(
      String output, String mode, String distribution, String version) {
    assertTrue(output.contains("OBI_STOCK_PROBE mode=" + mode + " passed"), output);
    assertTrue(output.contains("OBI remote-parent compatibility"), output);
    assertTrue(output.contains(distribution), output);
    assertTrue(output.contains(version), output);
    assertTrue(output.contains("provider=obi,supported=true,reason=compatible"), output);
    assertFalse(output.contains("LinkageError"), output);
    assertFalse(output.contains("ClassNotFoundException"), output);
  }

  private static void assertCommonResult(List<String> lines) {
    assertEquals(1, count(lines, "EXTENSION\tready"), lines.toString());
    assertEquals(1, count(lines, "PROVIDER\tready\tbootstrap"), lines.toString());
    assertEquals(1, count(lines, "WRAP\tobi\t1"), lines.toString());
    assertEquals(0, prefix(lines, "WRAP\tobi\t2").size(), lines.toString());
    assertEquals(0, prefix(lines, "ERROR\t").size(), lines.toString());
  }

  private static void assertHelperAbsentResult(List<String> resultLines, String output) {
    assertEquals(1, count(resultLines, "EXTENSION\tready"), resultLines.toString());
    assertEquals(1, count(resultLines, "PROVIDER\tabsent"), resultLines.toString());
    assertEquals(0, prefix(resultLines, "PROVIDER\tready\t").size(), resultLines.toString());
    assertEquals(1, count(resultLines, "WRAP\thelper-absent\t1"), resultLines.toString());
    assertEquals(0, prefix(resultLines, "WRAP\thelper-absent\t2").size(), resultLines.toString());
    assertEquals(0, prefix(resultLines, "CALL\t").size(), resultLines.toString());
    assertEquals(0, prefix(resultLines, "ERROR\t").size(), resultLines.toString());

    assertHelperAbsentDeadline(resultLines);
    long burstDeadlineDelta = helperAbsentLookup(resultLines, "BURST", 1L);
    long midDeadlineDelta = helperAbsentLookup(resultLines, "MID", 1L);
    long retryDeadlineDelta = helperAbsentLookup(resultLines, "RETRY", 2L);
    assertTrue(burstDeadlineDelta < 0L, Long.toString(burstDeadlineDelta));
    assertTrue(midDeadlineDelta < 0L, Long.toString(midDeadlineDelta));
    assertTrue(
        retryDeadlineDelta >= TimeUnit.MILLISECONDS.toNanos(500L),
        Long.toString(retryDeadlineDelta));

    List<String> outputLines = lines(output);
    int burstStart = exactLineIndex(outputLines, "OBI_HELPER_ABSENT\tBURST_START");
    int burstEnd = exactLineIndex(outputLines, "OBI_HELPER_ABSENT\tBURST_END");
    int midStart = exactLineIndex(outputLines, "OBI_HELPER_ABSENT\tMID_START");
    int midEnd = exactLineIndex(outputLines, "OBI_HELPER_ABSENT\tMID_END");
    int retryStart = exactLineIndex(outputLines, "OBI_HELPER_ABSENT\tRETRY_START");
    int retryEnd = exactLineIndex(outputLines, "OBI_HELPER_ABSENT\tRETRY_END");
    assertTrue(
        burstStart < burstEnd
            && burstEnd < midStart
            && midStart < midEnd
            && midEnd < retryStart
            && retryStart < retryEnd,
        output);

    List<Integer> diagnosticLines = new ArrayList<>();
    List<Long> diagnosticCounts = new ArrayList<>();
    String diagnostic = "reason=bridge_lookup_missing count=";
    for (int index = 0; index < outputLines.size(); index++) {
      String line = outputLines.get(index);
      int offset = line.indexOf(diagnostic);
      if (offset < 0) {
        continue;
      }
      String count = line.substring(offset + diagnostic.length()).trim();
      assertTrue(count.matches("[0-9]+"), line);
      diagnosticLines.add(index);
      diagnosticCounts.add(Long.parseLong(count));
    }
    assertEquals(2, diagnosticLines.size(), output);
    assertEquals(1L, diagnosticCounts.get(0).longValue(), output);
    assertEquals(2L, diagnosticCounts.get(1).longValue(), output);
    assertTrue(burstStart < diagnosticLines.get(0) && diagnosticLines.get(0) < burstEnd, output);
    assertTrue(retryStart < diagnosticLines.get(1) && diagnosticLines.get(1) < retryEnd, output);
  }

  private static void assertHelperAbsentSpans(List<String> lines, String output) {
    assertDispatch(output, "H");
    Map<String, SpanResult> spans = spans(lines, 1);
    assertRemoteSpan(required(spans, "H"), TRACE_W3C_ONLY, PARENT_W3C_ONLY, true);
  }

  private static long helperAbsentLookup(List<String> lines, String phase, long missing) {
    String line = only(lines, "LOOKUP\t" + phase + "\t");
    String[] fields = line.split("\t", -1);
    assertEquals(6, fields.length, line);
    assertEquals("LOOKUP", fields[0], line);
    assertEquals(phase, fields[1], line);
    long deadlineDelta = Long.parseLong(fields[2]);
    assertEquals(TimeUnit.SECONDS.toNanos(1L), Long.parseLong(fields[3]), line);
    assertEquals(8, Integer.parseInt(fields[4]), line);
    assertEquals(
        "bridge_lookup_missing="
            + missing
            + ",bridge_lookup_version_mismatch=0,bridge_lookup_error=0",
        fields[5],
        line);
    return deadlineDelta;
  }

  private static void assertHelperAbsentDeadline(List<String> lines) {
    String line = only(lines, "DEADLINE\t");
    String[] fields = line.split("\t", -1);
    assertEquals(4, fields.length, line);
    long fromBefore = Long.parseLong(fields[1]);
    long fromAfter = Long.parseLong(fields[2]);
    long interval = Long.parseLong(fields[3]);
    assertEquals(TimeUnit.SECONDS.toNanos(1L), interval, line);
    assertTrue(fromBefore >= interval, line);
    assertTrue(fromAfter <= interval, line);
    assertTrue(fromAfter > 0L, line);
  }

  private static void assertDefaultResult(List<String> lines, String output) {
    Map<String, Integer> invocations = new HashMap<>();
    for (String id : new String[] {"A", "B", "C", "H", "M", "W", "F", "R", "S", "P", "Q"}) {
      invocations.put(id, invocationCount(lines, id));
      assertDispatch(output, id);
    }

    assertRegisteredReextraction(lines, invocations.get("A"));
    assertAllPasses(lines, "B", invocations.get("B"), TRACE_B, PARENT_B, true, false);
    assertAllPasses(lines, "C", invocations.get("C"), INVALID_TRACE, INVALID_SPAN, false, false);
    assertAllPasses(lines, "H", invocations.get("H"), INVALID_TRACE, INVALID_SPAN, false, false);
    assertAllPasses(lines, "M", invocations.get("M"), TRACE_MATCHING, PARENT_MATCHING, true, true);
    assertPasses(lines, "W", 1, TRACE_CONFLICT, PARENT_CONFLICT, true, false);
    for (int invocation = 2; invocation <= invocations.get("W"); invocation++) {
      assertPasses(lines, "W", invocation, TRACE_W3C, PARENT_W3C, true, true);
    }
    assertAllPasses(
        lines, "F", invocations.get("F"), TRACE_MALFORMED_W3C, PARENT_MALFORMED_W3C, true, true);
    assertAllPasses(lines, "R", invocations.get("R"), INVALID_TRACE, INVALID_SPAN, false, false);
    assertAllPasses(lines, "S", invocations.get("S"), INVALID_TRACE, INVALID_SPAN, false, false);
    assertAllPasses(lines, "P", invocations.get("P"), TRACE_P, PARENT_P, true, true);
    assertAllPasses(lines, "Q", invocations.get("Q"), TRACE_Q, PARENT_Q, true, false);

    List<String> reextractionTakes = prefix(lines, "PROVIDER\tTAKE\tA\t");
    assertEquals(2, reextractionTakes.size(), lines.toString());
    assertEquals("PROVIDER\tTAKE\tA\t1\t1\tVALID", reextractionTakes.get(0));
    assertEquals("PROVIDER\tTAKE\tA\t2\t1\tALREADY_CONSUMED", reextractionTakes.get(1));
    for (String id : new String[] {"B", "M", "W", "F", "P", "Q"}) {
      assertEquals(
          "PROVIDER\tTAKE\t" + id + "\t1\t1\tVALID", only(lines, "PROVIDER\tTAKE\t" + id + "\t"));
    }
    int missingInvocations = invocations.get("C") + invocations.get("H");
    for (String id : new String[] {"C", "H"}) {
      assertEquals(
          invocations.get(id) * 2,
          prefix(lines, "PROVIDER\tTAKE\t" + id + "\t").size(),
          lines.toString());
      assertProviderPasses(lines, "TAKE", id, invocations.get(id), "MISSING");
    }
    assertEquals(
        invocations.get("S") * 2, prefix(lines, "PROVIDER\tTAKE\tS\t").size(), lines.toString());
    assertProviderPasses(lines, "TAKE", "S", invocations.get("S"), "STALE");
    assertEquals(
        invocations.get("R") * 2, prefix(lines, "PROVIDER\tTAKE\tR\t").size(), lines.toString());
    assertProviderPasses(lines, "TAKE", "R", invocations.get("R"), "MALFORMED");
    assertEquals(
        8 + (missingInvocations + invocations.get("R") + invocations.get("S")) * 2,
        prefix(lines, "PROVIDER\tTAKE\t").size(),
        lines.toString());
    assertEquals(0, prefix(lines, "PROVIDER\tDISCARD\t").size(), lines.toString());

    Map<String, Long> diagnostics = diagnostics(output, MODE_DEFAULT);
    assertEquals(7L, counter(diagnostics, "t_valid"));
    assertEquals((long) missingInvocations * 2L, counter(diagnostics, "t_missing"));
    assertEquals((long) invocations.get("S") * 2L, counter(diagnostics, "t_stale"));
    assertEquals((long) invocations.get("R") * 2L, counter(diagnostics, "t_malformed"));
    assertEquals(1L, counter(diagnostics, "t_already_consumed"));
    assertEquals(4L, counter(diagnostics, "take_sampled"));
    assertEquals(3L, counter(diagnostics, "take_unsampled"));
    assertEquals(2L, counter(diagnostics, "discard_standard"));
    assertEquals(0L, counter(diagnostics, "d_valid"));
    assertEquals(0L, counter(diagnostics, "d_missing"));
    assertEquals(0L, counter(diagnostics, "d_stale"));
    assertEquals(0L, counter(diagnostics, "d_malformed"));
    assertEquals(0L, counter(diagnostics, "d_already_consumed"));

    Map<String, SpanResult> spans = spans(lines, 11);
    assertEquals(1, prefix(lines, "SPAN\tA\t").size(), lines.toString());
    assertRemoteSpan(required(spans, "A"), TRACE_A, PARENT_A, true);
    assertRemoteSpan(required(spans, "B"), TRACE_B, PARENT_B, false);
    assertRemoteSpan(required(spans, "H"), TRACE_W3C_ONLY, PARENT_W3C_ONLY, true);
    assertRemoteSpan(required(spans, "M"), TRACE_MATCHING, PARENT_MATCHING, true);
    SpanResult standard = required(spans, "W");
    assertRemoteSpan(standard, TRACE_W3C, PARENT_W3C, true);
    assertNotEquals(TRACE_CONFLICT, standard.traceId);
    assertNotEquals(PARENT_CONFLICT, standard.parentSpanId);
    assertRemoteSpan(required(spans, "F"), TRACE_MALFORMED_W3C, PARENT_MALFORMED_W3C, true);
    assertRemoteSpan(required(spans, "R"), TRACE_MALFORMED_OBI_W3C, PARENT_MALFORMED_OBI_W3C, true);
    assertRemoteSpan(required(spans, "S"), TRACE_STALE_W3C, PARENT_STALE_W3C, false);
    assertRemoteSpan(required(spans, "P"), TRACE_P, PARENT_P, true);
    assertRemoteSpan(required(spans, "Q"), TRACE_Q, PARENT_Q, false);
    assertNotEquals(required(spans, "P").spanId, required(spans, "Q").spanId);

    SpanResult root = required(spans, "C");
    assertEquals(INVALID_SPAN, root.parentSpanId);
    assertFalse(root.parentRemote);
    assertFalse(root.parentSampled);
    assertTrue(root.sampled);
    for (String traceId :
        new String[] {
          TRACE_A,
          TRACE_B,
          TRACE_W3C_ONLY,
          TRACE_MATCHING,
          TRACE_W3C,
          TRACE_CONFLICT,
          TRACE_MALFORMED_W3C,
          TRACE_MALFORMED_OBI_W3C,
          TRACE_STALE_W3C,
          TRACE_P,
          TRACE_Q
        }) {
      assertNotEquals(traceId, root.traceId);
    }
  }

  private static void assertBlockingResult(List<String> lines, String output) {
    assertEquals(1, invocationCount(lines, "T"), lines.toString());
    assertPasses(lines, "T", 1, TRACE_T, PARENT_T, true, true);
    assertEquals("PROVIDER\tTAKE\tT\t1\t1\tVALID", only(lines, "PROVIDER\tTAKE\tT\t"));
    assertEquals(1, prefix(lines, "PROVIDER\tTAKE\t").size(), lines.toString());
    assertEquals(0, prefix(lines, "PROVIDER\tDISCARD\t").size(), lines.toString());

    Map<String, Long> diagnostics = diagnostics(output, MODE_BLOCKING);
    assertEquals(1L, counter(diagnostics, "t_valid"));
    assertEquals(0L, counter(diagnostics, "t_missing"));
    assertEquals(0L, counter(diagnostics, "t_stale"));
    assertEquals(0L, counter(diagnostics, "t_malformed"));
    assertEquals(0L, counter(diagnostics, "t_already_consumed"));
    assertEquals(1L, counter(diagnostics, "take_sampled"));
    assertEquals(0L, counter(diagnostics, "take_unsampled"));
    assertEquals(0L, counter(diagnostics, "discard_standard"));
    assertEquals(0L, counter(diagnostics, "d_valid"));
    assertEquals(0L, counter(diagnostics, "d_missing"));
    assertEquals(0L, counter(diagnostics, "d_stale"));
    assertEquals(0L, counter(diagnostics, "d_malformed"));
    assertEquals(0L, counter(diagnostics, "d_already_consumed"));

    Map<String, SpanResult> spans = spans(lines, 1);
    assertRemoteSpan(required(spans, "T"), TRACE_T, PARENT_T, true);

    List<String> outputLines = lines(output);
    long extractionThread = recordedThread(lines, "EXTRACT", "T");
    long spanStartThread = recordedThread(lines, "SPAN_START", "T");
    long requestThread = dispatchThread(outputLines, "REQUEST", "T");
    long responseThread = dispatchThread(outputLines, "BLOCKING", "T");
    assertEquals(extractionThread, spanStartThread, lines.toString());
    assertEquals(extractionThread, requestThread, output);
    assertEquals(extractionThread, responseThread, output);
    assertEquals(2, prefix(outputLines, "OBI_DISPATCH\t").size(), output);
    assertEquals(0, prefix(outputLines, "OBI_DISPATCH\tEXECUTOR\t").size(), output);
    assertEquals(0, prefix(outputLines, "OBI_DISPATCH\tASYNC\t").size(), output);
  }

  private static void assertProviderPasses(
      List<String> lines, String operation, String id, int invocations, String status) {
    for (int invocation = 1; invocation <= invocations; invocation++) {
      for (int pass = 1; pass <= 2; pass++) {
        assertEquals(
            1,
            count(
                lines,
                "PROVIDER\t"
                    + operation
                    + "\t"
                    + id
                    + "\t"
                    + invocation
                    + "\t"
                    + pass
                    + "\t"
                    + status),
            lines.toString());
      }
    }
  }

  private static void assertStandardFirstResult(List<String> lines, String output) {
    int invocations = invocationCount(lines, "D");
    assertDispatch(output, "D");
    assertAllPasses(lines, "D", invocations, TRACE_D_W3C, PARENT_D_W3C, true, false);
    assertEquals(0, prefix(lines, "PROVIDER\tTAKE\t").size(), lines.toString());

    List<String> discards = prefix(lines, "PROVIDER\tDISCARD\tD\t");
    assertEquals(invocations * 2, discards.size(), lines.toString());
    assertEquals("PROVIDER\tDISCARD\tD\t1\t1\tVALID", discards.get(0));
    assertEquals(1, suffix(discards, "\tVALID").size(), lines.toString());
    assertEquals(invocations * 2 - 1, suffix(discards, "\tALREADY_CONSUMED").size());

    Map<String, Long> diagnostics = diagnostics(output, MODE_STANDARD_FIRST);
    assertEquals(0L, counter(diagnostics, "t_valid"));
    assertEquals(0L, counter(diagnostics, "t_missing"));
    assertEquals(0L, counter(diagnostics, "t_already_consumed"));
    assertEquals((long) invocations * 2L, counter(diagnostics, "discard_standard"));
    assertEquals(1L, counter(diagnostics, "d_valid"));
    assertEquals(0L, counter(diagnostics, "d_missing"));
    assertEquals((long) invocations * 2L - 1L, counter(diagnostics, "d_already_consumed"));
    assertEquals(0L, counter(diagnostics, "take_sampled"));
    assertEquals(0L, counter(diagnostics, "take_unsampled"));

    Map<String, SpanResult> spans = spans(lines, 1);
    SpanResult standard = required(spans, "D");
    assertRemoteSpan(standard, TRACE_D_W3C, PARENT_D_W3C, false);
    assertNotEquals(TRACE_D_OBI, standard.traceId);
    assertNotEquals(PARENT_D_OBI, standard.parentSpanId);
  }

  private static void assertNestedResult(
      List<String> lines, String output, String mode, String expectedRoute) {
    int invocations = invocationCount(lines, "A");
    assertDispatch(output, "A");
    assertEquals(1, invocations, lines.toString());
    assertPasses(lines, "A", 1, TRACE_A, PARENT_A, true, true);
    assertEquals("PROVIDER\tTAKE\tA\t1\t1\tVALID", only(lines, "PROVIDER\tTAKE\tA\t"));

    Map<String, Long> diagnostics = diagnostics(output, mode);
    assertEquals(1L, counter(diagnostics, "t_valid"));
    assertEquals(0L, counter(diagnostics, "t_missing"));
    assertEquals(0L, counter(diagnostics, "t_already_consumed"));
    assertEquals(1L, counter(diagnostics, "take_sampled"));
    assertEquals(0L, counter(diagnostics, "take_unsampled"));
    assertEquals(0L, counter(diagnostics, "discard_standard"));

    Map<String, SpanResult> spans = spans(lines, 1, expectedRoute);
    assertRemoteSpan(required(spans, "A"), TRACE_A, PARENT_A, true);
  }

  private static void assertDispatch(String output, String id) {
    List<String> outputLines = lines(output);
    long requestThread = dispatchThread(outputLines, "REQUEST", id);
    long executorThread = dispatchThread(outputLines, "EXECUTOR", id);
    dispatchThread(outputLines, "ASYNC", id);
    assertNotEquals(requestThread, executorThread, output);
  }

  private static long dispatchThread(List<String> lines, String phase, String id) {
    String line = only(lines, "OBI_DISPATCH\t" + phase + "\t" + id + "\t");
    String[] fields = line.split("\\t", -1);
    assertEquals(4, fields.length, line);
    assertEquals("OBI_DISPATCH", fields[0], line);
    assertEquals(phase, fields[1], line);
    assertEquals(id, fields[2], line);
    long thread = Long.parseLong(fields[3]);
    assertTrue(thread > 0, line);
    return thread;
  }

  private static long recordedThread(List<String> lines, String phase, String id) {
    String line = only(lines, "THREAD\t" + phase + "\t" + id + "\t");
    String[] fields = line.split("\\t", -1);
    assertEquals(4, fields.length, line);
    assertEquals("THREAD", fields[0], line);
    assertEquals(phase, fields[1], line);
    assertEquals(id, fields[2], line);
    long thread = Long.parseLong(fields[3]);
    assertTrue(thread > 0, line);
    return thread;
  }

  private static int invocationCount(List<String> lines, String id) {
    List<String> calls = prefix(lines, "CALL\t" + id + "\t");
    assertTrue(!calls.isEmpty(), "missing OBI invocation for " + id);
    boolean[] seen = new boolean[calls.size() + 1];
    for (String call : calls) {
      String[] fields = call.split("\\t", -1);
      assertEquals(3, fields.length, call);
      int invocation = Integer.parseInt(fields[2]);
      assertTrue(invocation >= 1 && invocation <= calls.size(), call);
      assertFalse(seen[invocation], "duplicate OBI invocation " + call);
      seen[invocation] = true;
    }
    for (int invocation = 1; invocation < seen.length; invocation++) {
      assertTrue(seen[invocation], "missing OBI invocation " + id + "/" + invocation);
    }
    return calls.size();
  }

  private static void assertAllPasses(
      List<String> lines,
      String id,
      int invocations,
      String traceId,
      String parentSpanId,
      boolean remote,
      boolean sampled) {
    for (int invocation = 1; invocation <= invocations; invocation++) {
      assertPasses(lines, id, invocation, traceId, parentSpanId, remote, sampled);
    }
  }

  private static void assertRegisteredReextraction(List<String> lines, int invocations) {
    assertTrue(invocations >= 2, "missing registered-chain re-extraction for A");
    assertPasses(lines, "A", 1, TRACE_A, PARENT_A, true, true);
    assertEquals("REENTRY\tA\t2", only(lines, "REENTRY\tA\t"));
    PassResult reentry = pass(lines, "A", 2, 1);
    assertEquals(INVALID_TRACE, reentry.traceId);
    assertEquals(INVALID_SPAN, reentry.parentSpanId);
    assertFalse(reentry.remote);
    assertFalse(reentry.sampled);
    assertEquals(0, prefix(lines, "PASS\tA\t2\t2\t").size(), lines.toString());
    for (int invocation = 3; invocation <= invocations; invocation++) {
      assertPasses(lines, "A", invocation, TRACE_A, PARENT_A, true, true);
    }
  }

  private static void assertPasses(
      List<String> lines,
      String id,
      int invocation,
      String traceId,
      String parentSpanId,
      boolean remote,
      boolean sampled) {
    for (int pass = 1; pass <= 2; pass++) {
      PassResult result = pass(lines, id, invocation, pass);
      assertEquals(traceId, result.traceId);
      assertEquals(parentSpanId, result.parentSpanId);
      assertEquals(remote, result.remote);
      assertEquals(sampled, result.sampled);
    }
  }

  private static PassResult pass(List<String> lines, String id, int invocation, int pass) {
    return PassResult.parse(only(lines, "PASS\t" + id + "\t" + invocation + "\t" + pass + "\t"));
  }

  private static Map<String, SpanResult> spans(List<String> lines, int expected) {
    return spans(lines, expected, "_probe__");
  }

  private static Map<String, SpanResult> spans(
      List<String> lines, int expected, String expectedRoute) {
    List<String> spanLines = prefix(lines, "SPAN\t");
    assertEquals(expected, spanLines.size(), lines.toString());
    assertEquals(0, prefix(lines, "SPAN\t-\t").size(), lines.toString());
    Map<String, SpanResult> spans = new HashMap<>();
    Map<String, String> spanIds = new HashMap<>();
    for (String line : spanLines) {
      SpanResult span = SpanResult.parse(line);
      assertFalse(spans.containsKey(span.id), "duplicate server span for " + span.id);
      assertFalse(spanIds.containsKey(span.spanId), "duplicate server span ID " + span.spanId);
      spans.put(span.id, span);
      spanIds.put(span.spanId, span.id);
      assertEquals("io.opentelemetry.jetty-11.0", span.scope);
      assertEquals(expectedRoute, span.route);
    }
    assertEquals(expected, spans.size());
    return spans;
  }

  private static void assertRemoteSpan(
      SpanResult span, String traceId, String parentSpanId, boolean parentSampled) {
    assertEquals(traceId, span.traceId);
    assertEquals(parentSpanId, span.parentSpanId);
    assertTrue(span.parentRemote);
    assertEquals(parentSampled, span.parentSampled);
    assertTrue(span.sampled);
    assertNotEquals(parentSpanId, span.spanId);
  }

  private static SpanResult required(Map<String, SpanResult> spans, String id) {
    SpanResult span = spans.get(id);
    assertTrue(span != null, "missing server span " + id);
    return span;
  }

  private static Map<String, Long> diagnostics(String output, String mode) {
    String prefix = "OBI_STOCK_PROBE mode=" + mode + " diagnostics=";
    String line = only(lines(output), prefix);
    Map<String, Long> result = new HashMap<>();
    for (String field : line.substring(prefix.length()).split(",")) {
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

  private static int count(List<String> lines, String value) {
    int count = 0;
    for (String line : lines) {
      if (line.equals(value)) {
        count++;
      }
    }
    return count;
  }

  private static int exactLineIndex(List<String> lines, String value) {
    int found = -1;
    for (int index = 0; index < lines.size(); index++) {
      if (value.equals(lines.get(index))) {
        assertEquals(-1, found, lines.toString());
        found = index;
      }
    }
    assertTrue(found >= 0, lines.toString());
    return found;
  }

  private static String only(List<String> lines, String prefix) {
    List<String> matches = prefix(lines, prefix);
    assertEquals(1, matches.size(), lines.toString());
    return matches.get(0);
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

  private static List<String> suffix(List<String> lines, String suffix) {
    List<String> matches = new ArrayList<>();
    for (String line : lines) {
      if (line.endsWith(suffix)) {
        matches.add(line);
      }
    }
    return matches;
  }

  private static List<String> lines(String value) {
    List<String> lines = new ArrayList<>();
    for (String line : value.split("\\r?\\n")) {
      lines.add(line);
    }
    return lines;
  }

  private static String run(List<String> command) throws Exception {
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    AtomicReference<Throwable> readerFailure = new AtomicReference<>();
    Thread reader = copyOutput(process.getInputStream(), output, readerFailure);
    boolean completed;
    try {
      completed = process.waitFor(60, TimeUnit.SECONDS);
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
    String text = new String(output.toByteArray(), StandardCharsets.UTF_8);
    assertFalse(reader.isAlive(), "official-agent output reader did not finish\n" + text);
    Throwable readFailure = readerFailure.get();
    if (readFailure != null) {
      throw new AssertionError("cannot read official-agent output\n" + text, readFailure);
    }
    assertTrue(completed, "official-agent Jetty probe timed out\n" + text);
    assertFalse(process.isAlive(), "official-agent Jetty probe did not terminate\n" + text);
    assertEquals(0, process.exitValue(), text);
    return text;
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
            "official-agent-jetty-output");
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

  private static int javaMajorVersion() {
    String version = System.getProperty("java.specification.version");
    return version.startsWith("1.")
        ? Integer.parseInt(version.substring(2))
        : Integer.parseInt(version);
  }

  private static String requiredProperty(String name) {
    String value = System.getProperty(name);
    assertTrue(value != null && !value.isEmpty(), "missing system property " + name);
    return value;
  }

  private static boolean parseBoolean(String value, String line) {
    assertTrue(value.equals("true") || value.equals("false"), line);
    return value.equals("true");
  }

  private static final class PassResult {
    private final String traceId;
    private final String parentSpanId;
    private final boolean remote;
    private final boolean sampled;

    private PassResult(String traceId, String parentSpanId, boolean remote, boolean sampled) {
      this.traceId = traceId;
      this.parentSpanId = parentSpanId;
      this.remote = remote;
      this.sampled = sampled;
    }

    private static PassResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(8, fields.length, line);
      assertEquals("PASS", fields[0], line);
      assertTrue(Integer.parseInt(fields[2]) >= 1, line);
      int pass = Integer.parseInt(fields[3]);
      assertTrue(pass == 1 || pass == 2, line);
      return new PassResult(
          fields[4], fields[5], parseBoolean(fields[6], line), parseBoolean(fields[7], line));
    }
  }

  private static final class SpanResult {
    private final String id;
    private final String traceId;
    private final String spanId;
    private final String parentSpanId;
    private final boolean parentRemote;
    private final boolean parentSampled;
    private final boolean sampled;
    private final String scope;
    private final String route;

    private SpanResult(
        String id,
        String traceId,
        String spanId,
        String parentSpanId,
        boolean parentRemote,
        boolean parentSampled,
        boolean sampled,
        String scope,
        String route) {
      this.id = id;
      this.traceId = traceId;
      this.spanId = spanId;
      this.parentSpanId = parentSpanId;
      this.parentRemote = parentRemote;
      this.parentSampled = parentSampled;
      this.sampled = sampled;
      this.scope = scope;
      this.route = route;
    }

    private static SpanResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(10, fields.length, line);
      assertEquals("SPAN", fields[0], line);
      return new SpanResult(
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
