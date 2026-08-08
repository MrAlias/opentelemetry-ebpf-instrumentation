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
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class OfficialAgentNettyRuntimeTest {
  private static final String NETTY_VERSION = "4.1.135.Final";
  private static final String TRACE_A = "11111111111111111111111111111111";
  private static final String PARENT_A = "2222222222222222";
  private static final String TRACE_B = "33333333333333333333333333333333";
  private static final String PARENT_B = "4444444444444444";
  private static final String TRACE_P = "99999999999999999999999999999999";
  private static final String PARENT_P = "aaaaaaaaaaaaaaaa";
  private static final String TRACE_Q = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  private static final String PARENT_Q = "cccccccccccccccc";
  private static final String INVALID_TRACE = "00000000000000000000000000000000";
  private static final String INVALID_SPAN = "0000000000000000";

  @Test
  void unmodifiedOpenTelemetryAgentPreservesNettyParents() throws Exception {
    verifyAgent(
        "OBI_TEST_OTEL_AGENT",
        "faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589",
        "distribution=opentelemetry",
        "agent_version=2.28.1");
  }

  @Test
  void unmodifiedSplunkAgentPreservesNettyParents() throws Exception {
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
    File helper = new File(requiredProperty("obi.test.packaged.agent"));
    File extension = new File(requiredProperty("obi.test.extension.jar"));
    File probeExtension = new File(requiredProperty("obi.test.official.agent.probe.extension.jar"));
    String probeClasspath = requiredProperty("obi.test.official.agent.netty.probe.app.classpath");

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
        version);
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
      String version)
      throws Exception {
    Path directory = Files.createTempDirectory("obi-official-agent-netty-");
    Path result = directory.resolve("spans.tsv");
    Path keyStore = directory.resolve("server.p12");
    try {
      generateKeyStore(keyStore);
      List<String> command = new ArrayList<>();
      command.add(new File(System.getProperty("java.home"), "bin/java").getAbsolutePath());
      if (javaMajorVersion() >= 9) {
        command.add("--add-opens=java.base/sun.nio.ch=ALL-UNNAMED");
      }
      command.add("-javaagent:" + helper.getAbsolutePath() + "=remoteParentTransport=disabled");
      command.add("-javaagent:" + officialAgent.getAbsolutePath());
      command.add(
          "-Dotel.javaagent.extensions="
              + extension.getAbsolutePath()
              + ","
              + probeExtension.getAbsolutePath());
      command.add("-Dotel.propagators=obi,tracecontext,baggage");
      command.add("-Dotel.semconv-stability.opt-in=http/dup");
      command.add("-Dotel.obi.remote.parent.enabled=true");
      command.add("-Dotel.traces.sampler=always_on");
      command.add("-Dotel.traces.exporter=none");
      command.add("-Dotel.metrics.exporter=none");
      command.add("-Dotel.logs.exporter=none");
      command.add("-Dotel.service.name=obi-official-agent-netty-probe");
      command.add("-Dobi.test.official.agent.probe.output=" + result);
      command.add("-Dobi.test.official.agent.probe.framework=netty");
      command.add("-Dobi.test.official.agent.netty.probe.key.store=" + keyStore.toAbsolutePath());
      command.add("-cp");
      command.add(probeClasspath);
      command.add("io.opentelemetry.obi.java.extension.probe.OfficialAgentNettyProbe");

      String output;
      try {
        output = run(command);
      } catch (Throwable failure) {
        String partialResult =
            Files.isRegularFile(result)
                ? new String(Files.readAllBytes(result), StandardCharsets.UTF_8)
                : "<missing>";
        throw new AssertionError("official-agent Netty probe result:\n" + partialResult, failure);
      }
      List<String> lines = Files.readAllLines(result, StandardCharsets.UTF_8);
      try {
        Map<String, HandlerResult> handlers = assertOutput(output, distribution, version);
        assertResult(lines, output, handlers);
        assertEquals(expectedSha256, sha256(officialAgent.toPath()));
      } catch (Throwable failure) {
        throw new AssertionError(
            "official-agent Netty output:\n"
                + output
                + "\nofficial-agent Netty probe result:\n"
                + lines,
            failure);
      }
    } finally {
      Files.deleteIfExists(result);
      Files.deleteIfExists(keyStore);
      Files.deleteIfExists(directory);
    }
  }

  private static void generateKeyStore(Path keyStore) throws Exception {
    File keytool = new File(new File(System.getProperty("java.home"), "bin"), "keytool");
    if (!keytool.isFile()) {
      keytool = new File(new File(System.getProperty("java.home"), "bin"), "keytool.exe");
    }
    assertTrue(keytool.isFile(), "missing keytool under " + System.getProperty("java.home"));
    List<String> command = new ArrayList<>();
    command.add(keytool.getAbsolutePath());
    command.add("-genkeypair");
    command.add("-alias");
    command.add("obi-netty");
    command.add("-keyalg");
    command.add("RSA");
    command.add("-keysize");
    command.add("2048");
    command.add("-sigalg");
    command.add("SHA256withRSA");
    command.add("-storetype");
    command.add("PKCS12");
    command.add("-keystore");
    command.add(keyStore.toAbsolutePath().toString());
    command.add("-storepass");
    command.add("1234567");
    command.add("-keypass");
    command.add("1234567");
    command.add("-dname");
    command.add("CN=127.0.0.1");
    command.add("-validity");
    command.add("2");
    command.add("-ext");
    command.add("SAN=IP:127.0.0.1");
    command.add("-noprompt");
    run(command, 30, "Netty probe keytool");
    assertTrue(Files.isRegularFile(keyStore) && Files.size(keyStore) > 0, keyStore.toString());
  }

  private static Map<String, HandlerResult> assertOutput(
      String output, String distribution, String version) {
    assertTrue(output.contains("OBI_STOCK_NETTY_PROBE passed"), output);
    assertTrue(output.contains("OBI remote-parent compatibility"), output);
    assertTrue(output.contains(distribution), output);
    assertTrue(output.contains(version), output);
    assertTrue(output.contains("provider=obi,supported=true,reason=compatible"), output);
    assertFalse(output.contains("LinkageError"), output);
    assertFalse(output.contains("ClassNotFoundException"), output);
    assertFalse(output.contains("Netty helper unavailable"), output);
    assertFalse(output.contains("reason=receive_ambiguous"), output);

    List<String> outputLines = lines(output);
    assertTrue(prefix(outputLines, "OBI_NETTY_TASK\tTASK_CAPTURE\t").size() > 0, output);
    assertTrue(prefix(outputLines, "OBI_NETTY_TASK\tTASK_RELAY_CAPTURE\t").size() >= 2, output);
    assertTrue(prefix(outputLines, "OBI_NETTY_TASK\tTASK_LINK\t").size() > 0, output);
    Map<String, HandlerResult> handlers = new HashMap<>();
    for (String id : new String[] {"A", "B", "C", "P", "Q"}) {
      HandlerResult handler =
          HandlerResult.parse(only(outputLines, "OBI_NETTY_HANDLER\t" + id + "\t"));
      assertFalse(handlers.containsKey(id), "duplicate Netty handler result for " + id);
      handlers.put(id, handler);
      assertTrue(handler.channelFd >= 0, output);
      assertEquals(0, handler.lifecycleIdentity, output);
      assertNotEquals(handler.tlsThread, handler.requestThread, output);
      assertTrue(handler.tlsNativeThread > 0, output);
      assertTrue(handler.requestNativeThread > 0, output);
      assertNotEquals(handler.tlsNativeThread, handler.requestNativeThread, output);
      assertEquals(3, handler.lookupSource, output);
      assertFalse(handler.lifecycleActive, output);
      assertEquals(-1, handler.socketFileDescriptor, output);
    }
    assertEquals(handlers.get("A").channelId, handlers.get("B").channelId, output);
    assertEquals(handlers.get("A").channelId, handlers.get("C").channelId, output);
    assertEquals(handlers.get("A").channelFd, handlers.get("B").channelFd, output);
    assertEquals(handlers.get("A").channelFd, handlers.get("C").channelFd, output);
    assertNotEquals(handlers.get("A").channelId, handlers.get("P").channelId, output);
    assertNotEquals(handlers.get("A").channelId, handlers.get("Q").channelId, output);
    assertNotEquals(handlers.get("P").channelId, handlers.get("Q").channelId, output);
    assertNotEquals(handlers.get("P").channelFd, handlers.get("Q").channelFd, output);

    for (String id : new String[] {"A", "B", "C"}) {
      assertEquals(0, prefix(outputLines, "OBI_NETTY_HANDOFF\t" + id + "\t").size(), output);
    }
    assertEquals(2, prefix(outputLines, "OBI_NETTY_HANDOFF\t").size(), output);
    Map<String, HandoffResult> handoffs = new HashMap<>();
    for (String id : new String[] {"P", "Q"}) {
      HandoffResult handoff =
          HandoffResult.parse(only(outputLines, "OBI_NETTY_HANDOFF\t" + id + "\t"));
      handoffs.put(id, handoff);
      HandlerResult handler = handlers.get(id);
      assertEquals(handler.channelId, handoff.channelId, output);
      assertEquals(handler.channelFd, handoff.channelFd, output);
      assertNotEquals(0, handoff.lifecycleIdentity, output);
      assertEquals(handler.tlsThread, handoff.tlsThread, output);
      assertEquals(handler.requestThread, handoff.requestThread, output);
      assertEquals(handler.tlsNativeThread, handoff.tlsNativeThread, output);
      assertEquals(handler.requestNativeThread, handoff.requestNativeThread, output);
      assertTrue(handoff.tlsThread > 0, output);
      assertTrue(handoff.intermediateThread > 0, output);
      assertTrue(handoff.requestThread > 0, output);
      assertNotEquals(handoff.tlsThread, handoff.intermediateThread, output);
      assertNotEquals(handoff.intermediateThread, handoff.requestThread, output);
      assertNotEquals(handoff.tlsThread, handoff.requestThread, output);
      assertTrue(handoff.tlsNativeThread > 0, output);
      assertTrue(handoff.intermediateNativeThread > 0, output);
      assertTrue(handoff.requestNativeThread > 0, output);
      assertNotEquals(handoff.tlsNativeThread, handoff.intermediateNativeThread, output);
      assertNotEquals(handoff.intermediateNativeThread, handoff.requestNativeThread, output);
      assertNotEquals(handoff.tlsNativeThread, handoff.requestNativeThread, output);
      assertEquals(2, handoff.lookupSource, output);
      assertTrue(handoff.lifecycleActive, output);
      assertEquals(handler.channelFd, handoff.socketFileDescriptor, output);
    }
    assertNotEquals(handoffs.get("P").tlsThread, handoffs.get("Q").tlsThread, output);
    assertEquals(
        handoffs.get("P").intermediateThread, handoffs.get("Q").intermediateThread, output);
    assertNotEquals(handoffs.get("P").requestThread, handoffs.get("Q").requestThread, output);
    assertNotEquals(handoffs.get("P").tlsNativeThread, handoffs.get("Q").tlsNativeThread, output);
    assertEquals(
        handoffs.get("P").intermediateNativeThread,
        handoffs.get("Q").intermediateNativeThread,
        output);
    assertNotEquals(
        handoffs.get("P").requestNativeThread, handoffs.get("Q").requestNativeThread, output);
    assertNotEquals(
        handoffs.get("P").lifecycleIdentity, handoffs.get("Q").lifecycleIdentity, output);

    assertEquals(4, prefix(outputLines, "OBI_NETTY_EDGE\t").size(), output);
    Map<Long, String> edgeTokens = new HashMap<>();
    for (String id : new String[] {"P", "Q"}) {
      HandoffResult handoff = handoffs.get(id);
      EdgeResult first =
          EdgeResult.parse(
              only(
                  outputLines,
                  "OBI_NETTY_EDGE\t" + id + "\t" + handoff.channelId + "\tTLS_TO_INTERMEDIATE\t"));
      EdgeResult second =
          EdgeResult.parse(
              only(
                  outputLines,
                  "OBI_NETTY_EDGE\t"
                      + id
                      + "\t"
                      + handoff.channelId
                      + "\tINTERMEDIATE_TO_REQUEST\t"));
      assertEquals(id, first.id, output);
      assertEquals(id, second.id, output);
      assertEquals(handoff.channelId, first.channelId, output);
      assertEquals(handoff.channelId, second.channelId, output);
      assertEquals("TLS_TO_INTERMEDIATE", first.edge, output);
      assertEquals("INTERMEDIATE_TO_REQUEST", second.edge, output);
      assertEdge(
          outputLines,
          output,
          first,
          "TASK_CAPTURE",
          handoff.tlsNativeThread,
          handoff.intermediateNativeThread);
      assertEdge(
          outputLines,
          output,
          second,
          "TASK_RELAY_CAPTURE",
          handoff.intermediateNativeThread,
          handoff.requestNativeThread);
      assertTrue(first.linkSequence < second.captureSequence, output);
      assertFalse(edgeTokens.containsKey(first.token), "duplicate edge token in " + output);
      edgeTokens.put(first.token, id + "/TLS_TO_INTERMEDIATE");
      assertFalse(edgeTokens.containsKey(second.token), "duplicate edge token in " + output);
      edgeTokens.put(second.token, id + "/INTERMEDIATE_TO_REQUEST");
    }
    assertEquals(4, edgeTokens.size(), output);

    Map<String, IntermediateCleanupResult> intermediateCleanups = new HashMap<>();
    List<String> intermediateCleanupLines = prefix(outputLines, "OBI_NETTY_INTERMEDIATE_CLEANUP\t");
    assertEquals(2, intermediateCleanupLines.size(), output);
    for (String line : intermediateCleanupLines) {
      IntermediateCleanupResult cleanup = IntermediateCleanupResult.parse(line);
      assertFalse(
          intermediateCleanups.containsKey(cleanup.id),
          "duplicate intermediate cleanup for " + cleanup.id);
      intermediateCleanups.put(cleanup.id, cleanup);
    }
    for (String id : new String[] {"P", "Q"}) {
      IntermediateCleanupResult cleanup = intermediateCleanups.get(id);
      HandoffResult handoff = handoffs.get(id);
      assertTrue(cleanup != null, "missing intermediate cleanup for " + id);
      assertEquals(handoff.intermediateThread, cleanup.threadId, output);
      assertEquals(handoff.intermediateNativeThread, cleanup.nativeThreadId, output);
      assertNotEquals(2, cleanup.lookupSource, output);
      assertFalse(cleanup.directAuthority, output);
      assertFalse(cleanup.lifecycleActive, output);
      assertEquals(-1, cleanup.socketFileDescriptor, output);
      assertFalse(cleanup.exactTaskRelayState, output);
      assertTrue(cleanup.baselineRestored, output);
      assertFalse(cleanup.socketContextPresent, output);
      assertEquals(0, cleanup.receiveDepth, output);
    }

    Map<String, TlsCleanupResult> tlsCleanups = new HashMap<>();
    List<String> tlsCleanupLines = prefix(outputLines, "OBI_NETTY_TLS_CLEANUP\t");
    assertEquals(2, tlsCleanupLines.size(), output);
    for (String line : tlsCleanupLines) {
      TlsCleanupResult cleanup = TlsCleanupResult.parse(line);
      assertFalse(tlsCleanups.containsKey(cleanup.id), "duplicate TLS cleanup for " + cleanup.id);
      tlsCleanups.put(cleanup.id, cleanup);
    }
    for (String id : new String[] {"P", "Q"}) {
      TlsCleanupResult cleanup = tlsCleanups.get(id);
      HandoffResult handoff = handoffs.get(id);
      assertTrue(cleanup != null, "missing TLS cleanup for " + id);
      assertEquals(handoff.tlsThread, cleanup.threadId, output);
      assertEquals(handoff.tlsNativeThread, cleanup.nativeThreadId, output);
      assertNotEquals(2, cleanup.lookupSource, output);
      assertFalse(cleanup.directAuthority, output);
      assertFalse(cleanup.lifecycleActive, output);
      assertEquals(-1, cleanup.socketFileDescriptor, output);
      assertFalse(cleanup.exactTaskRelayState, output);
      assertTrue(cleanup.baselineRestored, output);
      assertFalse(cleanup.socketContextPresent, output);
      assertEquals(0, cleanup.receiveDepth, output);
    }

    Map<String, CleanupResult> cleanups = new HashMap<>();
    List<String> cleanupLines = prefix(outputLines, "OBI_NETTY_CLEANUP\t");
    assertEquals(5, cleanupLines.size(), output);
    for (String line : cleanupLines) {
      CleanupResult cleanup = CleanupResult.parse(line);
      assertFalse(cleanups.containsKey(cleanup.id), "duplicate cleanup result for " + cleanup.id);
      cleanups.put(cleanup.id, cleanup);
    }
    for (String id : new String[] {"A", "B", "C", "P", "Q"}) {
      CleanupResult cleanup = cleanups.get(id);
      HandlerResult handler = handlers.get(id);
      assertTrue(cleanup != null, "missing cleanup result for " + id);
      assertEquals(handler.channelId, cleanup.channelId, output);
      assertEquals(handler.requestThread, cleanup.threadId, output);
      assertEquals(handler.requestNativeThread, cleanup.nativeThreadId, output);
      assertNotEquals(2, cleanup.lookupSource, output);
      assertFalse(cleanup.directAuthority, output);
      assertFalse(cleanup.lifecycleActive, output);
      assertEquals(-1, cleanup.socketFileDescriptor, output);
      assertFalse(cleanup.exactTaskRelayState, output);
      assertTrue(cleanup.baselineRestored, output);
      assertFalse(cleanup.socketContextPresent, output);
      assertEquals(0, cleanup.receiveDepth, output);
    }
    return handlers;
  }

  private static void assertEdge(
      List<String> outputLines,
      String output,
      EdgeResult edge,
      String expectedOperation,
      long expectedParentThread,
      long expectedChildThread) {
    assertEquals(expectedOperation, edge.captureOperation, output);
    assertNotEquals(0L, edge.token, output);
    assertEquals(expectedParentThread, edge.captureThreadId, output);
    assertEquals(expectedParentThread, edge.linkParentThreadId, output);
    assertEquals(expectedChildThread, edge.linkChildThreadId, output);
    assertTrue(edge.captureSequence < edge.linkSequence, output);
    assertEquals(
        1,
        count(outputLines, "OBI_NETTY_TASK\t" + expectedOperation + "\t" + edge.token + "\t0"),
        output);
    assertEquals(
        1,
        count(
            outputLines, "OBI_NETTY_TASK\tTASK_LINK\t" + expectedParentThread + "\t" + edge.token),
        output);
    assertEquals(
        0, count(outputLines, "OBI_NETTY_TASK\tTASK_CANCEL\t" + edge.token + "\t0"), output);
  }

  private static void assertResult(
      List<String> lines, String output, Map<String, HandlerResult> handlers) {
    assertEquals(1, count(lines, "EXTENSION\tready"), lines.toString());
    assertEquals(1, count(lines, "PROVIDER\tready\tbootstrap"), lines.toString());
    assertEquals(1, count(lines, "WRAP\tobi\t1"), lines.toString());
    assertEquals(0, prefix(lines, "WRAP\tobi\t2").size(), lines.toString());
    assertEquals(0, prefix(lines, "ERROR\t").size(), lines.toString());
    assertEquals(5, prefix(lines, "THREAD\tSPAN_START\t").size(), lines.toString());
    for (String id : new String[] {"A", "B", "C", "P", "Q"}) {
      assertEquals(
          "THREAD\tSPAN_START\t" + id + "\t" + handlers.get(id).requestThread,
          only(lines, "THREAD\tSPAN_START\t" + id + "\t"),
          lines.toString());
    }

    Map<String, Integer> invocations = new HashMap<>();
    for (String id : new String[] {"A", "B", "C", "P", "Q"}) {
      invocations.put(id, invocationCount(lines, id));
    }
    assertAllPasses(lines, "A", invocations.get("A"), TRACE_A, PARENT_A, true, true);
    assertAllPasses(lines, "B", invocations.get("B"), TRACE_B, PARENT_B, true, false);
    assertAllPasses(lines, "C", invocations.get("C"), INVALID_TRACE, INVALID_SPAN, false, false);
    assertAllPasses(lines, "P", invocations.get("P"), TRACE_P, PARENT_P, true, true);
    assertAllPasses(lines, "Q", invocations.get("Q"), TRACE_Q, PARENT_Q, true, false);

    Map<String, AuthorityResult> exactAuthorities = new HashMap<>();
    for (String id : new String[] {"A", "B", "P", "Q"}) {
      assertEquals(
          "PROVIDER\tTAKE\t" + id + "\t1\t1\tVALID", only(lines, "PROVIDER\tTAKE\t" + id + "\t"));
      AuthorityResult authority = AuthorityResult.parse(only(lines, "AUTH\tTAKE\t" + id + "\t"));
      assertEquals(1, authority.invocation);
      assertEquals(1, authority.pass);
      assertEquals(2, authority.lookupSource);
      assertTrue(authority.lifecycleActive);
      assertNotEquals(0, authority.lifecycleIdentity);
      assertEquals(handlers.get(id).channelFd, authority.socketFileDescriptor);
      assertEquals(handlers.get(id).requestThread, authority.threadId);
      assertNotEquals(handlers.get(id).tlsThread, authority.threadId);
      assertFalse(exactAuthorities.containsKey(id), "duplicate exact authority for " + id);
      exactAuthorities.put(id, authority);
      if ("P".equals(id) || "Q".equals(id)) {
        HandoffResult handoff =
            HandoffResult.parse(only(lines(output), "OBI_NETTY_HANDOFF\t" + id + "\t"));
        assertEquals(handoff.lifecycleIdentity, authority.lifecycleIdentity);
      }
    }

    int missingInvocations = invocations.get("C");
    assertEquals(
        missingInvocations * 2, prefix(lines, "PROVIDER\tTAKE\tC\t").size(), lines.toString());
    List<String> missingAuthority = prefix(lines, "AUTH\tTAKE\tC\t");
    assertEquals(missingInvocations * 2, missingAuthority.size(), lines.toString());
    AuthorityResult firstMissingAuthority = null;
    for (int invocation = 1; invocation <= missingInvocations; invocation++) {
      for (int pass = 1; pass <= 2; pass++) {
        assertEquals(
            1,
            count(lines, "PROVIDER\tTAKE\tC\t" + invocation + "\t" + pass + "\tMISSING"),
            lines.toString());
        AuthorityResult authority =
            AuthorityResult.parse(only(lines, "AUTH\tTAKE\tC\t" + invocation + "\t" + pass + "\t"));
        assertEquals(handlers.get("C").requestThread, authority.threadId);
        assertNotEquals(handlers.get("C").tlsThread, authority.threadId);
        if (invocation == 1 && pass == 1) {
          assertEquals(2, authority.lookupSource);
          assertTrue(authority.lifecycleActive);
          assertNotEquals(0, authority.lifecycleIdentity);
          assertEquals(handlers.get("C").channelFd, authority.socketFileDescriptor);
          firstMissingAuthority = authority;
        } else {
          assertEquals(3, authority.lookupSource);
          assertFalse(authority.lifecycleActive);
          assertEquals(0, authority.lifecycleIdentity);
          assertEquals(-1, authority.socketFileDescriptor);
        }
      }
    }
    assertTrue(firstMissingAuthority != null, "missing first exact authority for C");
    exactAuthorities.put("C", firstMissingAuthority);
    assertEquals(
        exactAuthorities.get("A").lifecycleIdentity, exactAuthorities.get("B").lifecycleIdentity);
    assertEquals(
        exactAuthorities.get("A").lifecycleIdentity, exactAuthorities.get("C").lifecycleIdentity);
    assertNotEquals(
        exactAuthorities.get("A").lifecycleIdentity, exactAuthorities.get("P").lifecycleIdentity);
    assertNotEquals(
        exactAuthorities.get("A").lifecycleIdentity, exactAuthorities.get("Q").lifecycleIdentity);
    assertNotEquals(
        exactAuthorities.get("P").lifecycleIdentity, exactAuthorities.get("Q").lifecycleIdentity);
    assertEquals(4 + missingInvocations * 2, prefix(lines, "PROVIDER\tTAKE\t").size());
    assertEquals(0, prefix(lines, "PROVIDER\tDISCARD\t").size(), lines.toString());

    Map<String, Long> diagnostics = diagnostics(output);
    assertEquals(4L, counter(diagnostics, "t_valid"));
    assertEquals((long) missingInvocations * 2L, counter(diagnostics, "t_missing"));
    assertEquals(0L, counter(diagnostics, "t_already_consumed"));
    assertEquals(2L, counter(diagnostics, "take_sampled"));
    assertEquals(2L, counter(diagnostics, "take_unsampled"));
    assertEquals(0L, counter(diagnostics, "discard_standard"));
    assertEquals(0L, counter(diagnostics, "d_valid"));
    assertEquals(0L, counter(diagnostics, "d_missing"));
    assertEquals(0L, counter(diagnostics, "t_ambiguous"));
    assertEquals(0L, counter(diagnostics, "d_ambiguous"));
    assertTrue(counter(diagnostics, "tls_reads") > 0L);
    assertTrue(counter(diagnostics, "tls_bytes") > 0L);

    Map<String, SpanResult> spans = spans(lines, 5);
    assertRemoteSpan(required(spans, "A"), TRACE_A, PARENT_A, true);
    assertRemoteSpan(required(spans, "B"), TRACE_B, PARENT_B, false);
    assertRemoteSpan(required(spans, "P"), TRACE_P, PARENT_P, true);
    assertRemoteSpan(required(spans, "Q"), TRACE_Q, PARENT_Q, false);
    SpanResult root = required(spans, "C");
    assertEquals(INVALID_SPAN, root.parentSpanId);
    assertFalse(root.parentRemote);
    assertFalse(root.parentSampled);
    assertTrue(root.sampled);
    for (String traceId : new String[] {TRACE_A, TRACE_B, TRACE_P, TRACE_Q}) {
      assertNotEquals(traceId, root.traceId);
    }
    assertHttp(lines);
  }

  private static void assertHttp(List<String> lines) {
    List<String> httpLines = prefix(lines, "HTTP\t");
    assertEquals(5, httpLines.size(), lines.toString());
    Map<String, HttpResult> results = new HashMap<>();
    for (String line : httpLines) {
      HttpResult result = HttpResult.parse(line);
      assertFalse(results.containsKey(result.id), "duplicate HTTP attributes for " + result.id);
      results.put(result.id, result);
    }
    for (String id : new String[] {"A", "B", "C", "P", "Q"}) {
      HttpResult result = results.get(id);
      assertTrue(result != null, "missing HTTP attributes for " + id);
      assertEquals("GET", result.method);
      assertEquals("https", result.scheme);
      assertEquals("/probe/" + id, result.path);
      assertEquals(200L, result.status);
      assertEquals("1.1", result.protocolVersion);
    }
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
      for (int pass = 1; pass <= 2; pass++) {
        PassResult result =
            PassResult.parse(only(lines, "PASS\t" + id + "\t" + invocation + "\t" + pass + "\t"));
        assertEquals(traceId, result.traceId);
        assertEquals(parentSpanId, result.parentSpanId);
        assertEquals(remote, result.remote);
        assertEquals(sampled, result.sampled);
      }
    }
  }

  private static Map<String, SpanResult> spans(List<String> lines, int expected) {
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
      assertNotEquals(INVALID_TRACE, span.traceId);
      assertNotEquals(INVALID_SPAN, span.spanId);
      assertEquals("io.opentelemetry.netty-4.1", span.scope);
      assertFalse(span.routePresent);
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

  private static Map<String, Long> diagnostics(String output) {
    String marker = "OBI_STOCK_NETTY_PROBE diagnostics=";
    String line = only(lines(output), marker);
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

  private static void assertProbeClasspath(String classpath) {
    assertFalse(classpath.isEmpty());
    int nettyJars = 0;
    boolean codec = false;
    boolean codecHttp = false;
    boolean handler = false;
    for (String entry : classpath.split(Pattern.quote(File.pathSeparator))) {
      String name = new File(entry).getName();
      assertFalse(name.startsWith("opentelemetry-"), classpath);
      assertFalse(name.startsWith("jetty-"), classpath);
      assertFalse(name.startsWith("opentelemetry-javaagent"), classpath);
      if (name.startsWith("netty-") && name.endsWith(".jar")) {
        nettyJars++;
        assertTrue(name.endsWith("-" + NETTY_VERSION + ".jar"), name);
        codec |= name.equals("netty-codec-" + NETTY_VERSION + ".jar");
        codecHttp |= name.startsWith("netty-codec-http-");
        handler |= name.startsWith("netty-handler-");
      }
    }
    assertTrue(nettyJars > 0, classpath);
    assertTrue(codec, classpath);
    assertTrue(codecHttp, classpath);
    assertTrue(handler, classpath);
  }

  private static String run(List<String> command) throws Exception {
    return run(command, 90, "official-agent Netty probe");
  }

  private static String run(List<String> command, long timeoutSeconds, String name)
      throws Exception {
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    AtomicReference<Throwable> readerFailure = new AtomicReference<>();
    Thread reader = copyOutput(process.getInputStream(), output, readerFailure);
    boolean completed;
    try {
      completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
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
            "official-agent-netty-output");
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
    assertTrue(value.equals("true") || value.equals("false"), line);
    return value.equals("true");
  }

  private static String decodeReversibleToken(String value, String line) {
    assertNotEquals("-", value, line);
    return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
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

  private static List<String> lines(String value) {
    List<String> lines = new ArrayList<>();
    for (String line : value.split("\\r?\\n")) {
      lines.add(line);
    }
    return lines;
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

  private static final class AuthorityResult {
    private final int invocation;
    private final int pass;
    private final int lookupSource;
    private final boolean lifecycleActive;
    private final int lifecycleIdentity;
    private final int socketFileDescriptor;
    private final long threadId;

    private AuthorityResult(
        int invocation,
        int pass,
        int lookupSource,
        boolean lifecycleActive,
        int lifecycleIdentity,
        int socketFileDescriptor,
        long threadId) {
      this.invocation = invocation;
      this.pass = pass;
      this.lookupSource = lookupSource;
      this.lifecycleActive = lifecycleActive;
      this.lifecycleIdentity = lifecycleIdentity;
      this.socketFileDescriptor = socketFileDescriptor;
      this.threadId = threadId;
    }

    private static AuthorityResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(10, fields.length, line);
      assertEquals("AUTH", fields[0], line);
      assertEquals("TAKE", fields[1], line);
      assertTrue(!fields[2].isEmpty(), line);
      int invocation = Integer.parseInt(fields[3]);
      int pass = Integer.parseInt(fields[4]);
      int lookupSource = Integer.parseInt(fields[5]);
      boolean active = "LIVE".equals(fields[6]);
      assertTrue(active || "NONE".equals(fields[6]), line);
      return new AuthorityResult(
          invocation,
          pass,
          lookupSource,
          active,
          Integer.parseInt(fields[7]),
          Integer.parseInt(fields[8]),
          Long.parseLong(fields[9]));
    }
  }

  private static final class HandlerResult {
    private final String channelId;
    private final int channelFd;
    private final int lifecycleIdentity;
    private final long tlsThread;
    private final long requestThread;
    private final int lookupSource;
    private final boolean lifecycleActive;
    private final int socketFileDescriptor;
    private final long tlsNativeThread;
    private final long requestNativeThread;

    private HandlerResult(
        String channelId,
        int channelFd,
        int lifecycleIdentity,
        long tlsThread,
        long requestThread,
        int lookupSource,
        boolean lifecycleActive,
        int socketFileDescriptor,
        long tlsNativeThread,
        long requestNativeThread) {
      this.channelId = channelId;
      this.channelFd = channelFd;
      this.lifecycleIdentity = lifecycleIdentity;
      this.tlsThread = tlsThread;
      this.requestThread = requestThread;
      this.lookupSource = lookupSource;
      this.lifecycleActive = lifecycleActive;
      this.socketFileDescriptor = socketFileDescriptor;
      this.tlsNativeThread = tlsNativeThread;
      this.requestNativeThread = requestNativeThread;
    }

    private static HandlerResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(12, fields.length, line);
      assertEquals("OBI_NETTY_HANDLER", fields[0], line);
      assertTrue(!fields[1].isEmpty(), line);
      assertTrue(!fields[2].isEmpty(), line);
      return new HandlerResult(
          fields[2],
          Integer.parseInt(fields[3]),
          Integer.parseInt(fields[4]),
          Long.parseLong(fields[5]),
          Long.parseLong(fields[6]),
          Integer.parseInt(fields[7]),
          "LIVE".equals(fields[8]),
          Integer.parseInt(fields[9]),
          Long.parseLong(fields[10]),
          Long.parseLong(fields[11]));
    }
  }

  private static final class HandoffResult {
    private final String channelId;
    private final int channelFd;
    private final int lifecycleIdentity;
    private final long tlsThread;
    private final long intermediateThread;
    private final long requestThread;
    private final long tlsNativeThread;
    private final long intermediateNativeThread;
    private final long requestNativeThread;
    private final int lookupSource;
    private final boolean lifecycleActive;
    private final int socketFileDescriptor;

    private HandoffResult(
        String channelId,
        int channelFd,
        int lifecycleIdentity,
        long tlsThread,
        long intermediateThread,
        long requestThread,
        long tlsNativeThread,
        long intermediateNativeThread,
        long requestNativeThread,
        int lookupSource,
        boolean lifecycleActive,
        int socketFileDescriptor) {
      this.channelId = channelId;
      this.channelFd = channelFd;
      this.lifecycleIdentity = lifecycleIdentity;
      this.tlsThread = tlsThread;
      this.intermediateThread = intermediateThread;
      this.requestThread = requestThread;
      this.tlsNativeThread = tlsNativeThread;
      this.intermediateNativeThread = intermediateNativeThread;
      this.requestNativeThread = requestNativeThread;
      this.lookupSource = lookupSource;
      this.lifecycleActive = lifecycleActive;
      this.socketFileDescriptor = socketFileDescriptor;
    }

    private static HandoffResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(14, fields.length, line);
      assertEquals("OBI_NETTY_HANDOFF", fields[0], line);
      assertTrue(!fields[1].isEmpty(), line);
      assertTrue(!fields[2].isEmpty(), line);
      boolean active = "LIVE".equals(fields[12]);
      assertTrue(active || "NONE".equals(fields[12]), line);
      return new HandoffResult(
          fields[2],
          Integer.parseInt(fields[3]),
          Integer.parseInt(fields[4]),
          Long.parseLong(fields[5]),
          Long.parseLong(fields[6]),
          Long.parseLong(fields[7]),
          Long.parseLong(fields[8]),
          Long.parseLong(fields[9]),
          Long.parseLong(fields[10]),
          Integer.parseInt(fields[11]),
          active,
          Integer.parseInt(fields[13]));
    }
  }

  private static final class EdgeResult {
    private final String id;
    private final String channelId;
    private final String edge;
    private final String captureOperation;
    private final long token;
    private final long captureThreadId;
    private final long linkParentThreadId;
    private final long linkChildThreadId;
    private final long captureSequence;
    private final long linkSequence;

    private EdgeResult(
        String id,
        String channelId,
        String edge,
        String captureOperation,
        long token,
        long captureThreadId,
        long linkParentThreadId,
        long linkChildThreadId,
        long captureSequence,
        long linkSequence) {
      this.id = id;
      this.channelId = channelId;
      this.edge = edge;
      this.captureOperation = captureOperation;
      this.token = token;
      this.captureThreadId = captureThreadId;
      this.linkParentThreadId = linkParentThreadId;
      this.linkChildThreadId = linkChildThreadId;
      this.captureSequence = captureSequence;
      this.linkSequence = linkSequence;
    }

    private static EdgeResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(11, fields.length, line);
      assertEquals("OBI_NETTY_EDGE", fields[0], line);
      assertTrue(!fields[1].isEmpty(), line);
      assertTrue(!fields[2].isEmpty(), line);
      assertTrue(!fields[3].isEmpty(), line);
      return new EdgeResult(
          fields[1],
          fields[2],
          fields[3],
          fields[4],
          Long.parseLong(fields[5]),
          Long.parseLong(fields[6]),
          Long.parseLong(fields[7]),
          Long.parseLong(fields[8]),
          Long.parseLong(fields[9]),
          Long.parseLong(fields[10]));
    }
  }

  private static final class TlsCleanupResult {
    private final String id;
    private final long threadId;
    private final int lookupSource;
    private final boolean directAuthority;
    private final boolean lifecycleActive;
    private final int socketFileDescriptor;
    private final long nativeThreadId;
    private final boolean taskRelayState;
    private final boolean exactTaskRelayState;
    private final boolean baselineRestored;
    private final boolean socketContextPresent;
    private final int receiveDepth;

    private TlsCleanupResult(
        String id,
        long threadId,
        int lookupSource,
        boolean directAuthority,
        boolean lifecycleActive,
        int socketFileDescriptor,
        long nativeThreadId,
        boolean taskRelayState,
        boolean exactTaskRelayState,
        boolean baselineRestored,
        boolean socketContextPresent,
        int receiveDepth) {
      this.id = id;
      this.threadId = threadId;
      this.lookupSource = lookupSource;
      this.directAuthority = directAuthority;
      this.lifecycleActive = lifecycleActive;
      this.socketFileDescriptor = socketFileDescriptor;
      this.nativeThreadId = nativeThreadId;
      this.taskRelayState = taskRelayState;
      this.exactTaskRelayState = exactTaskRelayState;
      this.baselineRestored = baselineRestored;
      this.socketContextPresent = socketContextPresent;
      this.receiveDepth = receiveDepth;
    }

    private static TlsCleanupResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(13, fields.length, line);
      assertEquals("OBI_NETTY_TLS_CLEANUP", fields[0], line);
      assertTrue(!fields[1].isEmpty(), line);
      boolean active = "LIVE".equals(fields[5]);
      assertTrue(active || "NONE".equals(fields[5]), line);
      return new TlsCleanupResult(
          fields[1],
          Long.parseLong(fields[2]),
          Integer.parseInt(fields[3]),
          parseBoolean(fields[4], line),
          active,
          Integer.parseInt(fields[6]),
          Long.parseLong(fields[7]),
          parseBoolean(fields[8], line),
          parseBoolean(fields[9], line),
          parseBoolean(fields[10], line),
          parseBoolean(fields[11], line),
          Integer.parseInt(fields[12]));
    }
  }

  private static final class CleanupResult {
    private final String id;
    private final String channelId;
    private final long threadId;
    private final int lookupSource;
    private final boolean directAuthority;
    private final boolean lifecycleActive;
    private final int socketFileDescriptor;
    private final long nativeThreadId;
    private final boolean taskRelayState;
    private final boolean exactTaskRelayState;
    private final boolean baselineRestored;
    private final boolean socketContextPresent;
    private final int receiveDepth;

    private CleanupResult(
        String id,
        String channelId,
        long threadId,
        int lookupSource,
        boolean directAuthority,
        boolean lifecycleActive,
        int socketFileDescriptor,
        long nativeThreadId,
        boolean taskRelayState,
        boolean exactTaskRelayState,
        boolean baselineRestored,
        boolean socketContextPresent,
        int receiveDepth) {
      this.id = id;
      this.channelId = channelId;
      this.threadId = threadId;
      this.lookupSource = lookupSource;
      this.directAuthority = directAuthority;
      this.lifecycleActive = lifecycleActive;
      this.socketFileDescriptor = socketFileDescriptor;
      this.nativeThreadId = nativeThreadId;
      this.taskRelayState = taskRelayState;
      this.exactTaskRelayState = exactTaskRelayState;
      this.baselineRestored = baselineRestored;
      this.socketContextPresent = socketContextPresent;
      this.receiveDepth = receiveDepth;
    }

    private static CleanupResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(14, fields.length, line);
      assertEquals("OBI_NETTY_CLEANUP", fields[0], line);
      assertTrue(!fields[1].isEmpty(), line);
      assertTrue(!fields[2].isEmpty(), line);
      boolean active = "LIVE".equals(fields[6]);
      assertTrue(active || "NONE".equals(fields[6]), line);
      return new CleanupResult(
          fields[1],
          fields[2],
          Long.parseLong(fields[3]),
          Integer.parseInt(fields[4]),
          parseBoolean(fields[5], line),
          active,
          Integer.parseInt(fields[7]),
          Long.parseLong(fields[8]),
          parseBoolean(fields[9], line),
          parseBoolean(fields[10], line),
          parseBoolean(fields[11], line),
          parseBoolean(fields[12], line),
          Integer.parseInt(fields[13]));
    }
  }

  private static final class IntermediateCleanupResult {
    private final String id;
    private final long threadId;
    private final int lookupSource;
    private final boolean directAuthority;
    private final boolean lifecycleActive;
    private final int socketFileDescriptor;
    private final long nativeThreadId;
    private final boolean taskRelayState;
    private final boolean exactTaskRelayState;
    private final boolean baselineRestored;
    private final boolean socketContextPresent;
    private final int receiveDepth;

    private IntermediateCleanupResult(
        String id,
        long threadId,
        int lookupSource,
        boolean directAuthority,
        boolean lifecycleActive,
        int socketFileDescriptor,
        long nativeThreadId,
        boolean taskRelayState,
        boolean exactTaskRelayState,
        boolean baselineRestored,
        boolean socketContextPresent,
        int receiveDepth) {
      this.id = id;
      this.threadId = threadId;
      this.lookupSource = lookupSource;
      this.directAuthority = directAuthority;
      this.lifecycleActive = lifecycleActive;
      this.socketFileDescriptor = socketFileDescriptor;
      this.nativeThreadId = nativeThreadId;
      this.taskRelayState = taskRelayState;
      this.exactTaskRelayState = exactTaskRelayState;
      this.baselineRestored = baselineRestored;
      this.socketContextPresent = socketContextPresent;
      this.receiveDepth = receiveDepth;
    }

    private static IntermediateCleanupResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(13, fields.length, line);
      assertEquals("OBI_NETTY_INTERMEDIATE_CLEANUP", fields[0], line);
      assertTrue(!fields[1].isEmpty(), line);
      boolean active = "LIVE".equals(fields[5]);
      assertTrue(active || "NONE".equals(fields[5]), line);
      return new IntermediateCleanupResult(
          fields[1],
          Long.parseLong(fields[2]),
          Integer.parseInt(fields[3]),
          parseBoolean(fields[4], line),
          active,
          Integer.parseInt(fields[6]),
          Long.parseLong(fields[7]),
          parseBoolean(fields[8], line),
          parseBoolean(fields[9], line),
          parseBoolean(fields[10], line),
          parseBoolean(fields[11], line),
          Integer.parseInt(fields[12]));
    }
  }

  private static final class HttpResult {
    private final String id;
    private final String method;
    private final String scheme;
    private final String path;
    private final long status;
    private final String protocolVersion;

    private HttpResult(
        String id, String method, String scheme, String path, long status, String protocolVersion) {
      this.id = id;
      this.method = method;
      this.scheme = scheme;
      this.path = path;
      this.status = status;
      this.protocolVersion = protocolVersion;
    }

    private static HttpResult parse(String line) {
      String[] fields = line.split("\\t", -1);
      assertEquals(7, fields.length, line);
      assertEquals("HTTP", fields[0], line);
      return new HttpResult(
          fields[1],
          fields[2],
          fields[3],
          decodeReversibleToken(fields[4], line),
          Long.parseLong(fields[5]),
          fields[6]);
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
    private final boolean routePresent;

    private SpanResult(
        String id,
        String traceId,
        String spanId,
        String parentSpanId,
        boolean parentRemote,
        boolean parentSampled,
        boolean sampled,
        String scope,
        boolean routePresent) {
      this.id = id;
      this.traceId = traceId;
      this.spanId = spanId;
      this.parentSpanId = parentSpanId;
      this.parentRemote = parentRemote;
      this.parentSampled = parentSampled;
      this.sampled = sampled;
      this.scope = scope;
      this.routePresent = routePresent;
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
          parseBoolean(fields[9], line));
    }
  }
}
