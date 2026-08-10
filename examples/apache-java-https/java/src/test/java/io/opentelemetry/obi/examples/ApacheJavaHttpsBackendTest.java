// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletMapping;
import org.junit.jupiter.api.Test;

class ApacheJavaHttpsBackendTest {
  private static final String TRANSPORT_CONFIGURATION =
      "version=2,status=1,requested=2,selected=2,attempted=2,getsockopt=0,unix=1";

  @Test
  void generationFenceHoldIsExplicitAndBounded() {
    assertEquals(0, ApacheJavaHttpsBackend.parseGenerationFenceHold(null, null, false));
    assertEquals(
        ApacheJavaHttpsBackend.MAX_GENERATION_FENCE_HOLD_MILLIS,
        ApacheJavaHttpsBackend.parseGenerationFenceHold("20000", "1", true));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseGenerationFenceHold("20000", "1", false));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseGenerationFenceHold("20000", null, true));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseGenerationFenceHold("0", "1", true));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseGenerationFenceHold("20001", "1", true));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseGenerationFenceHold("not-a-number", "1", true));
  }

  @Test
  void generationFenceServletPathIsExact() {
    ServletContextHandler context = new ServletContextHandler();
    ApacheJavaHttpsBackend.configureServlets(context, "TLSv1.3", null);

    Map<String, String> generationFenceServlets = new HashMap<>();
    String expectedClass =
        ApacheJavaHttpsBackend.class.getName() + "$GenerationFenceServlet";
    for (ServletMapping mapping : context.getServletHandler().getServletMappings()) {
      String servletClass =
          context
              .getServletHandler()
              .getServlet(mapping.getServletName())
              .getHeldClass()
              .getName();
      if (!expectedClass.equals(servletClass)) {
        continue;
      }
      for (String path : mapping.getPathSpecs()) {
        assertNull(generationFenceServlets.put(path, servletClass));
      }
    }
    assertEquals(Map.of("/api/generation-fence", expectedClass), generationFenceServlets);
  }

  @Test
  void diagnosticServletPathsAreExact() {
    ServletContextHandler context = new ServletContextHandler();
    ApacheJavaHttpsBackend.configureServlets(context, "TLSv1.3", null);

    Map<String, String> expected =
        Map.of(
            "/obi-diagnostics",
            ApacheJavaHttpsBackend.class.getName() + "$BridgeDiagnosticsServlet",
            "/obi-transport-configuration",
            ApacheJavaHttpsBackend.class.getName() + "$TransportConfigurationServlet");
    Set<String> diagnosticServletClasses = Set.copyOf(expected.values());
    Map<String, String> diagnosticServlets = new HashMap<>();
    for (ServletMapping mapping : context.getServletHandler().getServletMappings()) {
      String servletClass =
          context
              .getServletHandler()
              .getServlet(mapping.getServletName())
              .getHeldClass()
              .getName();
      if (!diagnosticServletClasses.contains(servletClass)) {
        continue;
      }
      for (String path : mapping.getPathSpecs()) {
        assertNull(diagnosticServlets.put(path, servletClass));
      }
    }
    assertEquals(expected, diagnosticServlets);
  }

  @Test
  void transportConfigurationServletUsesInjectedDiagnosticsSnapshot() throws Exception {
    ServletResponseCapture response =
        capture(
            new ApacheJavaHttpsBackend.TransportConfigurationServlet(
                ApacheJavaHttpsBackendTest.class.getClassLoader()));

    assertEquals(
        TRANSPORT_CONFIGURATION + System.lineSeparator(), response.body());
    assertEquals(
        Map.of(
            "status",
            Integer.toString(HttpServletResponse.SC_OK),
            "content-type",
            "text/plain",
            "character-encoding",
            "US-ASCII",
            "Cache-Control",
            "no-store"),
        response.metadata());
  }

  @Test
  void transportConfigurationServletUsesBootstrapLoaderByDefault() throws Exception {
    ServletResponseCapture response =
        capture(new ApacheJavaHttpsBackend.TransportConfigurationServlet());

    assertEquals("unavailable" + System.lineSeparator(), response.body());
  }

  private static ServletResponseCapture capture(
      ApacheJavaHttpsBackend.TransportConfigurationServlet servlet) throws Exception {
    StringWriter body = new StringWriter();
    PrintWriter writer = new PrintWriter(body);
    Map<String, String> responseMetadata = new HashMap<>();
    HttpServletResponse response =
        (HttpServletResponse)
            Proxy.newProxyInstance(
                ApacheJavaHttpsBackendTest.class.getClassLoader(),
                new Class<?>[] {HttpServletResponse.class},
                (proxy, method, arguments) -> {
                  switch (method.getName()) {
                    case "setStatus":
                      responseMetadata.put("status", arguments[0].toString());
                      return null;
                    case "setContentType":
                      responseMetadata.put("content-type", arguments[0].toString());
                      return null;
                    case "setCharacterEncoding":
                      responseMetadata.put("character-encoding", arguments[0].toString());
                      return null;
                    case "setHeader":
                      responseMetadata.put(arguments[0].toString(), arguments[1].toString());
                      return null;
                    case "getWriter":
                      return writer;
                    default:
                      throw new AssertionError("unexpected response method: " + method.getName());
                  }
                });

    servlet.doGet(null, response);
    return new ServletResponseCapture(body.toString(), Map.copyOf(responseMetadata));
  }

  @Test
  void sharedResponseDiagnosticsRequireStrictOptIn() {
    assertEquals("X-OBI-Java-Diagnostics", ApacheJavaHttpsBackend.BRIDGE_DIAGNOSTICS_HEADER);
    assertEquals("bridge_diagnostics", ApacheJavaHttpsBackend.BRIDGE_DIAGNOSTICS_PARAMETER);
    String diagnostics = ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"1"});
    assertNotNull(diagnostics);
    assertFalse(diagnostics.contains("\r"));
    assertFalse(diagnostics.contains("\n"));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(null));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {""}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"0"}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"true"}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {" 1"}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"1 "}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"1", "1"}));
    assertNull(ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"1", "0"}));
  }

  @Test
  void handoffCountIsBounded() {
    assertEquals(2, ApacheJavaHttpsBackend.parseHops(null));
    assertEquals(1, ApacheJavaHttpsBackend.parseHops("1"));
    assertEquals(8, ApacheJavaHttpsBackend.parseHops("8"));
    assertThrows(IllegalArgumentException.class, () -> ApacheJavaHttpsBackend.parseHops("0"));
    assertThrows(IllegalArgumentException.class, () -> ApacheJavaHttpsBackend.parseHops("9"));
    assertThrows(IllegalArgumentException.class, () -> ApacheJavaHttpsBackend.parseHops("many"));
  }

  @Test
  void dispatchCountIsBounded() {
    assertEquals(2, ApacheJavaHttpsBackend.parseDispatchRounds(null));
    assertEquals(1, ApacheJavaHttpsBackend.parseDispatchRounds("1"));
    assertEquals(8, ApacheJavaHttpsBackend.parseDispatchRounds("8"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseDispatchRounds("0"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseDispatchRounds("9"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseDispatchRounds("many"));
  }

  @Test
  void concurrencyExpectedIsBounded() {
    assertEquals(2, ApacheJavaHttpsBackend.parseConcurrencyExpected("2"));
    assertEquals(64, ApacheJavaHttpsBackend.parseConcurrencyExpected("64"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseConcurrencyExpected(null));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseConcurrencyExpected("1"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseConcurrencyExpected("65"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseConcurrencyExpected("many"));
  }

  @Test
  void concurrencyBarrierProvesDistinctOverlappingWorkers() throws Exception {
    ApacheJavaHttpsBackend.ConcurrencyBarrier barrier =
        new ApacheJavaHttpsBackend.ConcurrencyBarrier();
    ExecutorService workers = Executors.newFixedThreadPool(4);
    try {
      List<Future<ApacheJavaHttpsBackend.BarrierEvidence>> futures =
          List.of(
              workers.submit(() -> barrier.await("c000000000000002a", 4, 11)),
              workers.submit(() -> barrier.await("c000000000000002a", 4, 12)),
              workers.submit(() -> barrier.await("c000000000000002a", 4, 13)),
              workers.submit(() -> barrier.await("c000000000000002a", 4, 14)));
      Set<Integer> arrivals = new HashSet<>();
      Set<Long> workerIDs = new HashSet<>();
      Set<Long> releases = new HashSet<>();
      for (Future<ApacheJavaHttpsBackend.BarrierEvidence> future : futures) {
        ApacheJavaHttpsBackend.BarrierEvidence evidence = future.get();
        assertEquals("c000000000000002a", evidence.batch);
        assertEquals(4, evidence.participants);
        assertEquals(4, evidence.maxActive);
        arrivals.add(evidence.arrival);
        workerIDs.add(evidence.workerID);
        releases.add(evidence.release);
      }
      assertEquals(Set.of(1, 2, 3, 4), arrivals);
      assertEquals(Set.of(11L, 12L, 13L, 14L), workerIDs);
      assertEquals(1, releases.size());
      assertTrue(releases.iterator().next() > 0);
    } finally {
      workers.shutdownNow();
    }
  }

  @Test
  void concurrencyBarrierCanBeReusedAfterSuccessfulBatchDeparture() throws Exception {
    ApacheJavaHttpsBackend.ConcurrencyBarrier barrier =
        new ApacheJavaHttpsBackend.ConcurrencyBarrier();
    ExecutorService workers = Executors.newFixedThreadPool(2);
    try {
      long firstRelease = awaitBarrierPair(barrier, workers, "c000000000000002a", 11, 12);
      long secondRelease = awaitBarrierPair(barrier, workers, "c000000000000002b", 13, 14);

      assertTrue(firstRelease > 0);
      assertTrue(secondRelease > firstRelease);
    } finally {
      workers.shutdownNow();
    }
  }

  @Test
  void concurrencyBarrierTimeoutClearsPartialBatchForReuse() throws Exception {
    ApacheJavaHttpsBackend.ConcurrencyBarrier barrier =
        new ApacheJavaHttpsBackend.ConcurrencyBarrier(TimeUnit.MILLISECONDS.toNanos(250));
    ExecutorService workers = Executors.newFixedThreadPool(2);
    try {
      Future<ApacheJavaHttpsBackend.BarrierEvidence> partial =
          workers.submit(() -> barrier.await("c000000000000002a", 2, 11));
      ExecutionException failure =
          assertThrows(ExecutionException.class, () -> partial.get(2, TimeUnit.SECONDS));
      assertTrue(failure.getCause() instanceof TimeoutException);

      assertTrue(awaitBarrierPair(barrier, workers, "c000000000000002b", 12, 13) > 0);
    } finally {
      workers.shutdownNow();
    }
  }

  private static long awaitBarrierPair(
      ApacheJavaHttpsBackend.ConcurrencyBarrier barrier,
      ExecutorService workers,
      String batch,
      long firstWorker,
      long secondWorker)
      throws Exception {
    Future<ApacheJavaHttpsBackend.BarrierEvidence> first =
        workers.submit(() -> barrier.await(batch, 2, firstWorker));
    Future<ApacheJavaHttpsBackend.BarrierEvidence> second =
        workers.submit(() -> barrier.await(batch, 2, secondWorker));
    ApacheJavaHttpsBackend.BarrierEvidence firstEvidence = first.get(2, TimeUnit.SECONDS);
    ApacheJavaHttpsBackend.BarrierEvidence secondEvidence = second.get(2, TimeUnit.SECONDS);
    assertEquals(firstEvidence.release, secondEvidence.release);
    return firstEvidence.release;
  }

  @Test
  void faultSelectionIsClosed() {
    assertEquals("none", ApacheJavaHttpsBackend.parseHandoffFault(null));
    assertEquals("cancel", ApacheJavaHttpsBackend.parseHandoffFault("cancel"));
    assertEquals("reject", ApacheJavaHttpsBackend.parseHandoffFault("reject"));
    assertEquals("timeout", ApacheJavaHttpsBackend.parseHandoffFault("timeout"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseHandoffFault("arbitrary"));
  }

  @Test
  void virtualThreadFlagsAreStrict() {
    assertTrue(ApacheJavaHttpsBackend.parseFlag(null, true, "mixed"));
    assertFalse(ApacheJavaHttpsBackend.parseFlag(null, false, "cancel"));
    assertTrue(ApacheJavaHttpsBackend.parseFlag("1", false, "mixed"));
    assertFalse(ApacheJavaHttpsBackend.parseFlag("0", true, "mixed"));
    assertThrows(
        IllegalArgumentException.class,
        () -> ApacheJavaHttpsBackend.parseFlag("true", false, "mixed"));
  }

  @Test
  void cancellationResultIsPreserved() {
    FutureTask<Void> pending = new FutureTask<>(() -> null);
    assertTrue(ApacheJavaHttpsBackend.cancelTask(pending, true));

    CompletableFuture<Void> completed = CompletableFuture.completedFuture(null);
    assertFalse(ApacheJavaHttpsBackend.cancelTask(completed, true));
  }

  @Test
  void procSocketLineMatchesBothPortsAndEstablishedState() {
    String established =
        "7: 0100007F:480B 0100007F:C001 01 00000000:00000000 00:00000000"
            + " 00000000 0 0 424242 1 0000000000000000";

    assertEquals(
        424242, ApacheJavaHttpsBackend.socketInodeFromProcLine(established, 18443, 49153));
    assertEquals(
        -1, ApacheJavaHttpsBackend.socketInodeFromProcLine(established, 18443, 49154));
    assertEquals(
        -1,
        ApacheJavaHttpsBackend.socketInodeFromProcLine(
            established.replace(" 01 ", " 06 "), 18443, 49153));
    assertEquals(
        -1,
        ApacheJavaHttpsBackend.socketInodeFromProcLine("sl local_address", 18443, 49153));
  }

  @Test
  void connectionIdentifiersAreStableAndMonotonic() {
    Object first = new Object();
    Object second = new Object();

    long firstID = ApacheJavaHttpsBackend.connectionID(first);
    assertTrue(firstID > 0);
    assertEquals(firstID, ApacheJavaHttpsBackend.connectionID(first));
    assertTrue(ApacheJavaHttpsBackend.connectionID(second) > firstID);
    assertThrows(
        IllegalArgumentException.class, () -> ApacheJavaHttpsBackend.connectionID(null));
  }

  @Test
  void connectionIdentifiersUseObjectIdentity() {
    Object first = new EqualConnection();
    Object second = new EqualConnection();

    assertEquals(first, second);
    long firstID = ApacheJavaHttpsBackend.connectionID(first);
    long secondID = ApacheJavaHttpsBackend.connectionID(second);
    assertTrue(secondID > firstID);
  }

  private static final class EqualConnection {
    @Override
    public boolean equals(Object ignored) {
      return true;
    }

    @Override
    public int hashCode() {
      return 1;
    }
  }

  private record ServletResponseCapture(String body, Map<String, String> metadata) {}
}
