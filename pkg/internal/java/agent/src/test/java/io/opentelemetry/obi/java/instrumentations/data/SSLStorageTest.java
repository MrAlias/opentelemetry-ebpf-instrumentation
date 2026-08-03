/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.BlockingQueueInst;
import io.opentelemetry.obi.java.instrumentations.FutureInst;
import io.opentelemetry.obi.java.instrumentations.JavaExecutorInst;
import io.opentelemetry.obi.java.instrumentations.RunnableInst;
import io.opentelemetry.obi.java.instrumentations.SSLEngineInst;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SSLStorageTest {
  private final List<Connection> ownedConnections = new ArrayList<>();
  private final List<Object> physicalOwners = new ArrayList<>();

  static class DummySSLEngine extends SSLEngine {
    private final SSLSession session;

    DummySSLEngine() {
      this(new byte[0]);
    }

    DummySSLEngine(byte[] sessionId) {
      byte[] id = sessionId.clone();
      session =
          (SSLSession)
              Proxy.newProxyInstance(
                  SSLSession.class.getClassLoader(),
                  new Class<?>[] {SSLSession.class},
                  (proxy, method, args) -> {
                    if (method.getName().equals("getId")) {
                      return id.clone();
                    }
                    throw new UnsupportedOperationException(method.getName());
                  });
    }

    @Override
    public String getPeerHost() {
      return null;
    }

    @Override
    public int getPeerPort() {
      return 0;
    }

    @Override
    public void beginHandshake() {}

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
      return null;
    }

    @Override
    public void closeInbound() {}

    @Override
    public boolean isInboundDone() {
      return false;
    }

    @Override
    public void closeOutbound() {}

    @Override
    public boolean isOutboundDone() {
      return false;
    }

    @Override
    public String[] getSupportedCipherSuites() {
      return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
      return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {}

    @Override
    public String[] getSupportedProtocols() {
      return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
      return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {}

    @Override
    public Runnable getDelegatedTask() {
      return null;
    }

    @Override
    public boolean getEnableSessionCreation() {
      return false;
    }

    @Override
    public boolean getNeedClientAuth() {
      return false;
    }

    @Override
    public boolean getUseClientMode() {
      return false;
    }

    @Override
    public boolean getWantClientAuth() {
      return false;
    }

    @Override
    public void setEnableSessionCreation(boolean b) {}

    @Override
    public void setNeedClientAuth(boolean b) {}

    @Override
    public void setUseClientMode(boolean b) {}

    @Override
    public void setWantClientAuth(boolean b) {}

    @Override
    public javax.net.ssl.SSLSession getHandshakeSession() {
      return null;
    }

    @Override
    public SSLSession getSession() {
      return session;
    }

    @Override
    public SSLEngineResult unwrap(java.nio.ByteBuffer src, java.nio.ByteBuffer dst) {
      return null;
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
        throws SSLException {
      return null;
    }

    @Override
    public SSLEngineResult wrap(java.nio.ByteBuffer src, java.nio.ByteBuffer dst) {
      return null;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
        throws SSLException {
      return null;
    }
  }

  static final class EqualSSLEngine extends DummySSLEngine {
    EqualSSLEngine() {
      super(new byte[] {1});
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof EqualSSLEngine;
    }

    @Override
    public int hashCode() {
      return 1;
    }
  }

  @AfterEach
  void cleanup() {
    // Clean up thread locals
    SSLStorage.unencrypted.remove();
    SSLStorage.nettyConnection.remove();
    SSLStorage.setThreadIdProviderForTest(null);
    SSLStorage.setTlsConnectionMarkerClockForTest(null);
    SSLStorage.clearRemoteParentUnwrapDepthForTest();
    ThreadInfo.setRemoteParentEnabled(false);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    for (Connection connection : ownedConnections) {
      SSLStorage.cleanupConnection(connection);
    }
    ownedConnections.clear();
    physicalOwners.clear();
  }

  @Test
  void testSessionConnectionMapping() throws Exception {
    SSLEngine engine = new DummySSLEngine();
    Connection conn =
        own(
            new Connection(
                InetAddress.getByName("127.0.0.1"),
                1234,
                InetAddress.getByName("1.2.3.4"),
                5678,
                6));

    assertNull(SSLStorage.getConnectionForSession(engine));
    SSLStorage.setConnectionForSession(engine, conn);
    assertEquals(conn, SSLStorage.getConnectionForSession(engine));
    SSLStorage.cleanupConnection(conn);
    assertNull(SSLStorage.getConnectionForSession(engine));
  }

  @Test
  void unassociatedDescriptorConnectionCannotStageCorrelationOrEmit() throws Exception {
    SSLEngine engine = new DummySSLEngine();
    Connection connection = rawConnection(1235, 5679, 80);
    ByteBuffer buffer = ByteBuffer.allocate(8);

    SSLStorage.setConnectionForSession(engine, connection);
    SSLStorage.setConnectionForReadBuffer(buffer, connection);

    assertNull(SSLStorage.getConnectionForSession(engine));
    assertNull(SSLStorage.getConnectionForReadBuffer(buffer));
    assertNull(SSLStorage.remoteParentSocketLifecycle(connection));
    assertEquals(-1, BootstrapNative.emitData(connection, 1L, false));
  }

  @Test
  void clearedPhysicalOwnerFailsClosedBeforeLookupOrNativeEmission() throws Exception {
    Connection connection = connection(1236, 5680, 81);
    Object physicalOwner = SSLStorage.physicalOwnerForTest(connection);
    assertNotNull(physicalOwner);
    Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertNotNull(lifecycle);
    Lifecycle.Lease lease = lifecycle.acquireLookupLease();
    assertNotNull(lease);
    assertSame(physicalOwner, lease.retainedOwnerForTest());
    lease.close();
    RemoteParentSocketContext context =
        new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);

    SSLStorage.clearPhysicalOwnerForTest(connection);

    assertNull(SSLStorage.remoteParentSocketLifecycle(connection));
    assertEquals(-1, context.peek());
    assertNull(context.takeForRemoteParentLookup());
    assertEquals(-1, BootstrapNative.emitData(connection, 1L, false));
  }

  @Test
  void scalarUnwrapThrowableInvalidatesItsExactOwnerLifecycle() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection connection = connection(1235, 5679, 81);
    SSLStorage.setConnectionForSession(engine, connection);
    RemoteParentSocketContext.Lifecycle lifecycle =
        (RemoteParentSocketContext.Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertTrue(
        ThreadInfo.setRemoteParentSocketFileDescriptor(
            connection.getSocketFileDescriptor(), lifecycle));
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);
    ByteBuffer source = ByteBuffer.allocate(1);
    ByteBuffer destination = ByteBuffer.allocate(1);
    Object[] saved = SSLEngineInst.UnwrapAdvice.unwrap(engine, source, destination);

    SSLEngineInst.UnwrapAdvice.unwrap(
        engine, saved, source, destination, null, new SSLException("expected unwrap failure"));

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, alias.peek());
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void arrayUnwrapThrowableInvalidatesItsExactOwnerLifecycle() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection connection = connection(1236, 5680, 82);
    SSLStorage.setConnectionForSession(engine, connection);
    RemoteParentSocketContext.Lifecycle lifecycle =
        (RemoteParentSocketContext.Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertTrue(
        ThreadInfo.setRemoteParentSocketFileDescriptor(
            connection.getSocketFileDescriptor(), lifecycle));
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);
    ByteBuffer source = ByteBuffer.allocate(1);
    ByteBuffer[] destinations = {ByteBuffer.allocate(1)};
    Object[] saved = SSLEngineInst.UnwrapAdviceArray.unwrap(engine, source, destinations);

    SSLEngineInst.UnwrapAdviceArray.unwrap(
        engine, saved, source, destinations, null, new SSLException("expected unwrap failure"));

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, alias.peek());
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void rangedUnwrapThrowableInvalidatesItsExactOwnerLifecycle() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection connection = connection(1237, 5681, 83);
    SSLStorage.setConnectionForSession(engine, connection);
    RemoteParentSocketContext.Lifecycle lifecycle =
        (RemoteParentSocketContext.Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertTrue(
        ThreadInfo.setRemoteParentSocketFileDescriptor(
            connection.getSocketFileDescriptor(), lifecycle));
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);
    ByteBuffer source = ByteBuffer.allocate(1);
    ByteBuffer[] destinations = {ByteBuffer.allocate(1)};
    Object[] saved =
        SSLEngineInst.UnwrapAdviceArrayOffset.unwrap(engine, source, destinations, 0, 1);

    SSLEngineInst.UnwrapAdviceArrayOffset.unwrap(
        engine,
        saved,
        source,
        destinations,
        0,
        1,
        null,
        new SSLException("expected unwrap failure"));

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, alias.peek());
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void malformedScalarUnwrapEntryCannotInvalidateANewerEngineLifecycle() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection stale = connection(1238, 5682, 84);
    SSLStorage.setConnectionForSession(engine, stale);
    Lifecycle staleLifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(stale);
    assertNotNull(staleLifecycle);
    SSLStorage.cleanupConnection(stale);

    Connection current = connection(1239, 5683, 85);
    SSLStorage.setConnectionForSession(engine, current);
    Lifecycle currentLifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(current);
    assertNotNull(currentLifecycle);
    assertTrue(
        ThreadInfo.setRemoteParentSocketFileDescriptor(
            current.getSocketFileDescriptor(), currentLifecycle));
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(current.getSocketFileDescriptor(), currentLifecycle);
    Object[] malformed = {null, null, null, null, null, staleLifecycle, true};

    SSLEngineInst.UnwrapAdvice.unwrap(
        engine, malformed, ByteBuffer.allocate(1), ByteBuffer.allocate(1), null, null);

    assertSame(current, SSLStorage.getConnectionForSession(engine));
    assertEquals(current.getSocketFileDescriptor(), ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(current.getSocketFileDescriptor(), alias.peek());
    SSLStorage.cleanupConnection(current);
  }

  @Test
  void malformedArrayUnwrapEntryStillInvalidatesTheLifecycleCapturedFromItsEngine()
      throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection connection = connection(1237, 5681, 87);
    SSLStorage.setConnectionForSession(engine, connection);
    RemoteParentSocketContext.Lifecycle lifecycle =
        (RemoteParentSocketContext.Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertTrue(
        ThreadInfo.setRemoteParentSocketFileDescriptor(
            connection.getSocketFileDescriptor(), lifecycle));
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);
    ByteBuffer source = ByteBuffer.allocate(1);
    Object[] saved = SSLEngineInst.UnwrapAdviceArray.unwrap(engine, source, null);

    SSLEngineInst.UnwrapAdviceArray.unwrap(engine, saved, source, null, null, null);

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, alias.peek());
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void malformedRangedUnwrapEntryStillInvalidatesTheLifecycleCapturedFromItsEngine()
      throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection connection = connection(1238, 5682, 88);
    SSLStorage.setConnectionForSession(engine, connection);
    RemoteParentSocketContext.Lifecycle lifecycle =
        (RemoteParentSocketContext.Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertTrue(
        ThreadInfo.setRemoteParentSocketFileDescriptor(
            connection.getSocketFileDescriptor(), lifecycle));
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);
    ByteBuffer source = ByteBuffer.allocate(1);
    ByteBuffer[] destinations = {ByteBuffer.allocate(1)};
    Object[] saved =
        SSLEngineInst.UnwrapAdviceArrayOffset.unwrap(engine, source, destinations, -1, 0);

    SSLEngineInst.UnwrapAdviceArrayOffset.unwrap(
        engine, saved, source, destinations, -1, 0, null, null);

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, alias.peek());
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void underflowPreservesTheExactOwnerLifecycle() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection connection = connection(1238, 5682, 84);
    SSLStorage.setConnectionForSession(engine, connection);
    RemoteParentSocketContext.Lifecycle lifecycle =
        (RemoteParentSocketContext.Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertTrue(
        ThreadInfo.setRemoteParentSocketFileDescriptor(
            connection.getSocketFileDescriptor(), lifecycle));
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);
    ByteBuffer source = ByteBuffer.allocate(1);
    ByteBuffer destination = ByteBuffer.allocate(1);
    Object[] saved = SSLEngineInst.UnwrapAdvice.unwrap(engine, source, destination);

    SSLEngineInst.UnwrapAdvice.unwrap(
        engine,
        saved,
        source,
        destination,
        new SSLEngineResult(
            SSLEngineResult.Status.BUFFER_UNDERFLOW,
            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
            0,
            0),
        null);

    assertEquals(
        connection.getSocketFileDescriptor(), ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(connection.getSocketFileDescriptor(), alias.peek());
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void closeInboundAndOwnerCleanupInvalidateTheExactOwnerLifecycle() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection first = connection(1239, 5683, 85);
    SSLStorage.setConnectionForSession(engine, first);
    RemoteParentSocketContext.Lifecycle firstLifecycle =
        (RemoteParentSocketContext.Lifecycle) SSLStorage.remoteParentSocketLifecycle(first);
    RemoteParentSocketContext firstAlias =
        new RemoteParentSocketContext(first.getSocketFileDescriptor(), firstLifecycle);

    SSLEngineInst.CloseInboundAdvice.closeInbound(engine);

    assertEquals(-1, firstAlias.peek());
    assertNull(SSLStorage.remoteParentSocketLifecycle(engine));
    assertNull(SSLStorage.remoteParentSocketLifecycle(first));
    SSLStorage.cleanupConnection(first);

    SSLEngine second = new DummySSLEngine(new byte[] {2});
    Connection secondConnection = connection(1240, 5684, 86);
    SSLStorage.setConnectionForSession(second, secondConnection);
    RemoteParentSocketContext.Lifecycle secondLifecycle =
        (RemoteParentSocketContext.Lifecycle)
            SSLStorage.remoteParentSocketLifecycle(secondConnection);
    RemoteParentSocketContext secondAlias =
        new RemoteParentSocketContext(secondConnection.getSocketFileDescriptor(), secondLifecycle);

    SSLStorage.cleanupConnection(secondConnection);

    assertEquals(-1, secondAlias.peek());
  }

  @Test
  void activeConnectionCapacityEvictionWaitsForAndInvalidatesAStagedAlias() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {9});
    Connection first = connection(32_000, 42_000, 500_000);
    SSLStorage.setConnectionForSession(engine, first);
    RemoteParentSocketContext.Lifecycle lifecycle =
        (RemoteParentSocketContext.Lifecycle) SSLStorage.remoteParentSocketLifecycle(first);
    assertNotNull(lifecycle);
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(first.getSocketFileDescriptor(), lifecycle);
    assertTrue(
        ThreadInfo.setRemoteParentSocketFileDescriptor(first.getSocketFileDescriptor(), lifecycle));
    RemoteParentSocketContext.Lifecycle.Lease lease = lifecycle.acquireLookupLease();
    assertNotNull(lease);

    Connection[] connections = new Connection[SSLStorage.MAX_CONCURRENT];
    CountDownLatch evictionFinished = new CountDownLatch(1);
    java.util.concurrent.atomic.AtomicReference<Throwable> failure =
        new java.util.concurrent.atomic.AtomicReference<>();
    Thread evictor =
        new Thread(
            () -> {
              try {
                for (int i = 0; i < SSLStorage.MAX_CONCURRENT; i++) {
                  Connection candidate = connection(32_001, 42_001, 600_000 + i);
                  connections[i] = candidate;
                  SSLStorage.setConnectionForSession(engine, candidate);
                }
              } catch (Throwable thrown) {
                failure.compareAndSet(null, thrown);
              } finally {
                evictionFinished.countDown();
              }
            });
    evictor.start();

    try {
      assertTrue(waitForInactive(lifecycle));
      assertFalse(evictionFinished.await(250, java.util.concurrent.TimeUnit.MILLISECONDS));
      assertEquals(-1, alias.peek());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(-1, ThreadInfo.takeRemoteParentSocketFileDescriptor());
    } finally {
      lease.close();
      assertTrue(evictionFinished.await(5, java.util.concurrent.TimeUnit.SECONDS));
      for (int i = 0; i < connections.length; i++) {
        if (connections[i] != null) {
          SSLStorage.cleanupConnection(connections[i]);
        }
      }
      SSLStorage.cleanupConnection(first);
    }
    assertNull(failure.get());
    assertEquals(-1, alias.take());
  }

  @Test
  void socketCloseCapacityExhaustionReturnsWithoutSpinningOrRetainingThreadState()
      throws Exception {
    List<Socket> trackedSockets = new ArrayList<>();
    Socket rejectedSocket = null;
    try {
      // Fill whatever capacity remains in the shared weak map, including any live socket
      // lifecycles retained by a preceding test worker.
      for (int i = 0; i <= SSLStorage.MAX_CONCURRENT; i++) {
        Socket candidate = new Socket();
        if (SSLStorage.prepareRemoteParentSocketLifecycle(candidate) == null) {
          rejectedSocket = candidate;
          break;
        }
        trackedSockets.add(candidate);
      }
      assertNotNull(rejectedSocket);

      AtomicReference<Object> closeLifecycle = new AtomicReference<>();
      AtomicReference<Integer> remainingDescriptor = new AtomicReference<>();
      AtomicReference<Throwable> failure = new AtomicReference<>();
      Socket closeTarget = rejectedSocket;
      Thread closer =
          new Thread(
              () -> {
                try {
                  ThreadInfo.setRemoteParentSocketFileDescriptor(60);
                  closeLifecycle.set(BootstrapNative.beginRemoteParentSocketClose(closeTarget));
                  remainingDescriptor.set(ThreadInfo.remoteParentSocketFileDescriptor());
                } catch (Throwable thrown) {
                  failure.set(thrown);
                }
              },
              "socket-close-capacity-test");
      // A regression must fail the test instead of leaving a non-daemon test worker spinning.
      closer.setDaemon(true);
      closer.start();
      closer.join(1_000);

      assertFalse(closer.isAlive());
      assertNull(failure.get());
      assertNull(closeLifecycle.get());
      assertEquals(-1, remainingDescriptor.get());
    } finally {
      if (rejectedSocket != null) {
        rejectedSocket.close();
      }
      for (Socket socket : trackedSockets) {
        SSLStorage.invalidateRemoteParentSocketLifecycle(
            socket, SSLStorage.currentRemoteParentSocketLifecycle(socket));
        socket.close();
      }
    }
  }

  @Test
  void equalTlsEnginesKeepIndependentSessionAndMarkerState() throws Exception {
    SSLEngine firstEngine = new EqualSSLEngine();
    SSLEngine secondEngine = new EqualSSLEngine();
    Connection first = connection(1254, 5698, 17);
    Connection second = connection(1255, 5699, 18);
    assertEquals(firstEngine, secondEngine);

    SSLStorage.setConnectionForSession(firstEngine, first);
    SSLStorage.setConnectionForSession(secondEngine, second);
    assertSame(first, SSLStorage.getConnectionForSession(firstEngine));
    assertSame(second, SSLStorage.getConnectionForSession(secondEngine));

    for (int attempt = 0; attempt < SSLStorage.TLS_CONNECTION_MARKER_BURST_ATTEMPTS; attempt++) {
      assertTrue(SSLStorage.claimTlsConnectionMarkerAttempt(firstEngine, first, 11));
    }
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(firstEngine, first, 11));
    assertTrue(SSLStorage.claimTlsConnectionMarkerAttempt(secondEngine, second, 11));

    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(second);
  }

  @Test
  void testTlsConnectionMarkerRetriesAreBounded() {
    SSLEngine engine = new DummySSLEngine();
    AtomicLong now = new AtomicLong(100L);
    SSLStorage.setTlsConnectionMarkerClockForTest(now::get);
    Connection first =
        own(
            new Connection(
                InetAddress.getLoopbackAddress(), 1234, InetAddress.getLoopbackAddress(), 5678, 7));

    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(null, first, 11));
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, null, 11));
    assertFalse(
        SSLStorage.claimTlsConnectionMarkerAttempt(
            engine,
            new Connection(
                InetAddress.getLoopbackAddress(), 1234, InetAddress.getLoopbackAddress(), 5678, -1),
            11));
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, first, 0));
    SSLStorage.setConnectionForSession(engine, first);

    for (int attempt = 0; attempt < SSLStorage.TLS_CONNECTION_MARKER_BURST_ATTEMPTS; attempt++) {
      assertTrue(SSLStorage.claimTlsConnectionMarkerAttempt(engine, first, 11));
    }
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, first, 11));
    for (int unwrap = 0; unwrap < 1_000_000; unwrap++) {
      assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, first, 11));
    }

    now.addAndGet(SSLStorage.TLS_CONNECTION_MARKER_RETRY_NANOS - 1);
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, first, 11));
    now.incrementAndGet();
    assertTrue(SSLStorage.claimTlsConnectionMarkerAttempt(engine, first, 11));
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, first, 11));
    SSLStorage.cleanupConnection(first);
  }

  @Test
  void testTlsConnectionMarkerChangesResetRetries() {
    SSLEngine engine = new DummySSLEngine();
    AtomicLong now = new AtomicLong(100L);
    SSLStorage.setTlsConnectionMarkerClockForTest(now::get);
    Connection first =
        own(
            new Connection(
                InetAddress.getLoopbackAddress(), 1234, InetAddress.getLoopbackAddress(), 5678, 7));
    Connection changedDescriptor =
        own(
            new Connection(
                InetAddress.getLoopbackAddress(), 1234, InetAddress.getLoopbackAddress(), 5678, 8));
    Connection changedTuple =
        own(
            new Connection(
                InetAddress.getLoopbackAddress(), 1235, InetAddress.getLoopbackAddress(), 5678, 8));

    exhaustTlsConnectionMarkerBurst(engine, first, 11);
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, first, 11));
    exhaustTlsConnectionMarkerBurst(engine, changedDescriptor, 11);
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, changedDescriptor, 11));
    exhaustTlsConnectionMarkerBurst(engine, changedTuple, 11);
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, changedTuple, 11));
    exhaustTlsConnectionMarkerBurst(engine, changedTuple, 12);
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, changedTuple, 12));
    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(changedDescriptor);
    SSLStorage.cleanupConnection(changedTuple);
  }

  @Test
  void reusedExactTlsConnectionGetsAFreshMarkerOwnerGeneration() throws Exception {
    SSLEngine engine = new DummySSLEngine();
    AtomicLong now = new AtomicLong(100L);
    SSLStorage.setTlsConnectionMarkerClockForTest(now::get);
    Connection first = connection(1284, 5728, 19);
    exhaustTlsConnectionMarkerBurst(engine, first, 11);
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, first, 11));

    SSLStorage.cleanupConnection(first);
    Connection reused = connection(1284, 5728, 19);

    exhaustTlsConnectionMarkerBurst(engine, reused, 11);
    assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, reused, 11));
    SSLStorage.cleanupConnection(reused);
  }

  @Test
  void concurrentTlsMarkerClaimsReserveExactlyOneBurst() throws Exception {
    int callers = SSLStorage.TLS_CONNECTION_MARKER_BURST_ATTEMPTS * 4;
    SSLEngine engine = new DummySSLEngine();
    Connection connection = connection(1294, 5738, 20);
    SSLStorage.setConnectionForSession(engine, connection);
    SSLStorage.setTlsConnectionMarkerClockForTest(() -> 100L);
    CountDownLatch ready = new CountDownLatch(callers);
    CountDownLatch start = new CountDownLatch(1);
    ExecutorService executor = Executors.newFixedThreadPool(callers);
    java.util.ArrayList<Future<Boolean>> claims = new java.util.ArrayList<>();

    try {
      for (int caller = 0; caller < callers; caller++) {
        claims.add(
            executor.submit(
                () -> {
                  ready.countDown();
                  assertTrue(start.await(5, java.util.concurrent.TimeUnit.SECONDS));
                  return SSLStorage.claimTlsConnectionMarkerAttempt(engine, connection, 11);
                }));
      }
      assertTrue(ready.await(5, java.util.concurrent.TimeUnit.SECONDS));
      start.countDown();

      int reserved = 0;
      for (Future<Boolean> claim : claims) {
        if (claim.get(5, java.util.concurrent.TimeUnit.SECONDS)) {
          reserved++;
        }
      }
      assertEquals(SSLStorage.TLS_CONNECTION_MARKER_BURST_ATTEMPTS, reserved);
      assertFalse(SSLStorage.claimTlsConnectionMarkerAttempt(engine, connection, 11));
    } finally {
      start.countDown();
      executor.shutdownNow();
      SSLStorage.cleanupConnection(connection);
    }
  }

  private static void exhaustTlsConnectionMarkerBurst(
      SSLEngine engine, Connection connection, long processIncarnation) {
    SSLStorage.setConnectionForSession(engine, connection);
    for (int attempt = 0; attempt < SSLStorage.TLS_CONNECTION_MARKER_BURST_ATTEMPTS; attempt++) {
      assertTrue(
          SSLStorage.claimTlsConnectionMarkerAttempt(engine, connection, processIncarnation));
    }
  }

  @Test
  void tentativeReadBufferIsNotClaimedBeforeHandshake() throws Exception {
    SSLEngine engine = new DummySSLEngine();
    ByteBuffer source = ByteBuffer.wrap(new byte[] {1, 2, 3});
    Connection connection = connection(1234, 5678, 7);
    SSLStorage.setConnectionForReadBuffer(source, connection);

    Object handoff = SSLStorage.captureReadBufferHandoff(source);

    assertNotNull(handoff);
    assertNull(SSLStorage.resolveConnectionForUnwrap(engine, handoff));
    assertNull(
        SSLStorage.claimConnectionForUnwrap(engine, source, handoff, null, null, null, 1, 1));
    assertNull(SSLStorage.getConnectionForSession(engine));
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void scopedConnectionWinsBeforeHandshake() throws Exception {
    SSLEngine engine = new DummySSLEngine();
    Connection connection = connection(2234, 6678, 8);
    installNettyScope(connection);

    Object[] saved =
        SSLEngineInst.UnwrapAdvice.unwrap(
            engine, ByteBuffer.wrap(new byte[] {4, 5, 6}), ByteBuffer.allocate(8));

    assertNotNull(saved);
    assertSame(connection, saved[1]);
    assertSame(connection, SSLStorage.getConnectionForSession(engine));
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void scopedConnectionReplacesStaleSessionOwner() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection stale = connection(2334, 6778, 25);
    Connection scoped = connection(2335, 6779, 26);
    SSLStorage.setConnectionForSession(engine, stale);
    installNettyScope(scoped);

    Object[] saved =
        SSLEngineInst.UnwrapAdvice.unwrap(
            engine, ByteBuffer.wrap(new byte[] {7, 8, 9}), ByteBuffer.allocate(8));

    assertNotNull(saved);
    assertSame(scoped, saved[1]);
    assertSame(scoped, SSLStorage.getConnectionForSession(engine));
    SSLStorage.cleanupConnection(stale);
    SSLStorage.cleanupConnection(scoped);
  }

  @Test
  void changedScopedConnectionAtExitFailsClosed() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection first = connection(2434, 6878, 29);
    Connection second = connection(2435, 6879, 30);
    ByteBuffer source = ByteBuffer.allocate(8);
    ByteBuffer destination = ByteBuffer.allocate(8);
    installNettyScope(first);
    Object[] saved = SSLEngineInst.UnwrapAdvice.unwrap(engine, source, destination);
    destination.put((byte) 1);

    installNettyScope(second);
    SSLEngineInst.UnwrapAdvice.unwrap(
        engine,
        saved,
        source,
        destination,
        new SSLEngineResult(
            SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 1, 1),
        null);

    assertSame(first, SSLStorage.getConnectionForSession(engine));
    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(second);
  }

  @Test
  void sameExactReplacementScopedConnectionAtExitFailsClosed() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection first = connection(2484, 6928, 36);
    Connection replacement = rawConnection(2484, 6928, 36);
    ByteBuffer source = ByteBuffer.allocate(8);
    installNettyScope(first);
    Connection expected = SSLStorage.resolveConnectionForUnwrap(engine, null);
    Object owner = SSLStorage.captureConnectionOwnerForUnwrap(engine, expected);

    SSLStorage.nettyConnection.set(replacement);

    assertNull(
        SSLStorage.claimConnectionForUnwrap(engine, source, null, expected, owner, first, 1, 1));
    assertSame(first, SSLStorage.getConnectionForSession(engine));
    SSLStorage.cleanupConnection(first);
  }

  @Test
  void stableFileDescriptorlessScopedConnectionUsesCachedExactOwner() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection cached = connection(2514, 6958, 39);
    Connection scope = connection(2514, 6958, -1);
    SSLStorage.setConnectionForSession(engine, cached);
    SSLStorage.nettyConnection.set(scope);
    Connection expected = SSLStorage.resolveConnectionForUnwrap(engine, null);
    Object owner = SSLStorage.captureConnectionOwnerForUnwrap(engine, expected);

    assertSame(
        cached,
        SSLStorage.claimConnectionForUnwrap(
            engine, ByteBuffer.allocate(8), null, expected, owner, scope, 1, 1));
    SSLStorage.cleanupConnection(cached);
  }

  @Test
  void fileDescriptorlessReplacementScopedConnectionAtExitFailsClosed() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection cached = connection(2534, 6978, 37);
    Connection firstScope = connection(2534, 6978, -1);
    Connection replacementScope = connection(2534, 6978, -1);
    SSLStorage.setConnectionForSession(engine, cached);
    SSLStorage.nettyConnection.set(firstScope);
    Connection expected = SSLStorage.resolveConnectionForUnwrap(engine, null);
    Object owner = SSLStorage.captureConnectionOwnerForUnwrap(engine, expected);

    SSLStorage.nettyConnection.set(replacementScope);

    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            engine, ByteBuffer.allocate(8), null, expected, owner, firstScope, 1, 1));
    assertSame(cached, SSLStorage.getConnectionForSession(engine));
    SSLStorage.cleanupConnection(cached);
  }

  @Test
  void clearedFileDescriptorlessScopedConnectionAtExitFailsClosed() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection cached = connection(2584, 7028, 38);
    Connection scope = connection(2584, 7028, -1);
    SSLStorage.setConnectionForSession(engine, cached);
    SSLStorage.nettyConnection.set(scope);
    Connection expected = SSLStorage.resolveConnectionForUnwrap(engine, null);
    Object owner = SSLStorage.captureConnectionOwnerForUnwrap(engine, expected);

    SSLStorage.nettyConnection.remove();

    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            engine, ByteBuffer.allocate(8), null, expected, owner, scope, 1, 1));
    assertSame(cached, SSLStorage.getConnectionForSession(engine));
    SSLStorage.cleanupConnection(cached);
  }

  @Test
  void exitOnlyScopedConnectionDoesNotClaimTentativeBuffer() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection readOwner = connection(2534, 6978, 31);
    Connection lateScope = connection(2535, 6979, 32);
    ByteBuffer source = ByteBuffer.allocate(8);
    ByteBuffer destination = ByteBuffer.allocate(8);
    SSLStorage.setConnectionForReadBuffer(source, readOwner);
    Object[] saved = SSLEngineInst.UnwrapAdvice.unwrap(engine, source, destination);
    destination.put((byte) 1);

    installNettyScope(lateScope);
    SSLEngineInst.UnwrapAdvice.unwrap(
        engine,
        saved,
        source,
        destination,
        new SSLEngineResult(
            SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 1, 1),
        null);

    assertNull(SSLStorage.getConnectionForSession(engine));
    assertSame(readOwner, SSLStorage.getConnectionForReadBuffer(source));
    SSLStorage.cleanupConnection(readOwner);
    SSLStorage.cleanupConnection(lateScope);
  }

  @Test
  void scopedOwnerMakesAConflictingReadHandoffAmbiguous() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection scoped = connection(2634, 7078, 33);
    Connection conflicting = connection(2635, 7079, 34);
    ByteBuffer source = ByteBuffer.allocate(8);
    SSLStorage.setConnectionForReadBuffer(source, conflicting);
    Object handoff = SSLStorage.captureReadBufferHandoff(source);
    installNettyScope(scoped);
    Connection expected = SSLStorage.resolveConnectionForUnwrap(engine, handoff);
    Object owner = SSLStorage.captureConnectionOwnerForUnwrap(engine, expected);

    assertSame(
        scoped,
        SSLStorage.claimConnectionForUnwrap(
            engine, source, handoff, expected, owner, scoped, 1, 1));
    SSLStorage.setConnectionForReadBuffer(source, conflicting);
    assertNull(SSLStorage.getConnectionForReadBuffer(source));
    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}),
            source,
            SSLStorage.captureReadBufferHandoff(source),
            null,
            null,
            null,
            1,
            1));
    SSLStorage.cleanupConnection(scoped);
    SSLStorage.cleanupConnection(conflicting);
  }

  @Test
  void scopedOwnerDoesNotPoisonARefreshedHandoff() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection scoped = connection(2734, 7178, 35);
    ByteBuffer source = ByteBuffer.allocate(8);
    SSLStorage.setConnectionForReadBuffer(source, scoped);
    Object captured = SSLStorage.captureReadBufferHandoff(source);
    assertTrue(SSLStorage.setCurrentNettyConnection(scoped));
    Connection expected = SSLStorage.resolveConnectionForUnwrap(engine, captured);
    Object owner = SSLStorage.captureConnectionOwnerForUnwrap(engine, expected);
    SSLStorage.setConnectionForReadBuffer(source, scoped);

    assertSame(
        scoped,
        SSLStorage.claimConnectionForUnwrap(
            engine, source, captured, expected, owner, scoped, 1, 1));
    Object refreshed = SSLStorage.captureReadBufferHandoff(source);
    SSLStorage.nettyConnection.remove();
    assertSame(scoped, SSLStorage.getConnectionForReadBuffer(source));
    assertSame(
        scoped,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}), source, refreshed, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(scoped);
  }

  @Test
  void staleScopedHandoffCannotPoisonAConsumedGeneration() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection scoped = connection(2744, 7188, 53);
    ByteBuffer source = ByteBuffer.allocate(8);
    SSLStorage.setConnectionForReadBuffer(source, scoped);
    Object captured = SSLStorage.captureReadBufferHandoff(source);
    assertTrue(SSLStorage.setCurrentNettyConnection(scoped));
    Connection expected = SSLStorage.resolveConnectionForUnwrap(engine, captured);
    Object owner = SSLStorage.captureConnectionOwnerForUnwrap(engine, expected);

    assertSame(
        scoped,
        SSLStorage.claimConnectionForUnwrap(
            engine, source, captured, expected, owner, scoped, 1, 1));
    assertSame(
        scoped,
        SSLStorage.claimConnectionForUnwrap(
            engine, source, captured, expected, owner, scoped, 1, 1));

    SSLStorage.nettyConnection.remove();
    SSLStorage.setConnectionForReadBuffer(source, scoped);
    assertSame(scoped, SSLStorage.getConnectionForReadBuffer(source));
    SSLStorage.cleanupConnection(scoped);
  }

  @Test
  void identicalCiphertextInDistinctBuffersKeepsExactOwners() throws Exception {
    ByteBuffer firstBuffer = ByteBuffer.wrap(new byte[] {23, 3, 3, 0, 42});
    ByteBuffer secondBuffer = ByteBuffer.wrap(new byte[] {23, 3, 3, 0, 42});
    Connection first = connection(3234, 7678, 9);
    Connection second = connection(3235, 7679, 10);
    SSLEngine firstEngine = new DummySSLEngine(new byte[] {1});
    SSLEngine secondEngine = new DummySSLEngine(new byte[] {2});
    SSLStorage.setConnectionForReadBuffer(firstBuffer, first);
    SSLStorage.setConnectionForReadBuffer(secondBuffer, second);

    Object firstHandoff = SSLStorage.captureReadBufferHandoff(firstBuffer);
    Object secondHandoff = SSLStorage.captureReadBufferHandoff(secondBuffer);

    assertSame(
        first,
        SSLStorage.claimConnectionForUnwrap(
            firstEngine, firstBuffer, firstHandoff, null, null, null, 1, 1));
    assertSame(
        second,
        SSLStorage.claimConnectionForUnwrap(
            secondEngine, secondBuffer, secondHandoff, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(second);
  }

  @Test
  void bufferAliasesFailClosed() throws Exception {
    ByteBuffer heap = ByteBuffer.allocate(8);
    ByteBuffer direct = ByteBuffer.allocateDirect(8);
    Connection heapConnection = connection(4234, 8678, 11);
    Connection directConnection = connection(4235, 8679, 12);
    SSLStorage.setConnectionForReadBuffer(heap, heapConnection);
    SSLStorage.setConnectionForReadBuffer(direct, directConnection);

    assertSame(heapConnection, SSLStorage.getConnectionForReadBuffer(heap));
    assertNull(SSLStorage.getConnectionForReadBuffer(heap.duplicate()));
    assertSame(directConnection, SSLStorage.getConnectionForReadBuffer(direct));
    assertNull(SSLStorage.getConnectionForReadBuffer(direct.duplicate()));
    SSLStorage.cleanupConnection(heapConnection);
    SSLStorage.cleanupConnection(directConnection);
  }

  @Test
  void inactiveOwnerAllowsPooledBufferReuse() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection first = connection(5234, 9678, 13);
    Connection second = connection(5235, 9679, 14);
    SSLStorage.setConnectionForReadBuffer(source, first);
    SSLStorage.cleanupConnection(first);
    SSLStorage.setConnectionForReadBuffer(source, second, true);

    Object handoff = SSLStorage.captureReadBufferHandoff(source);

    assertNotNull(handoff);
    assertSame(second, SSLStorage.getConnectionForReadBuffer(source));
    assertSame(
        second,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {1}), source, handoff, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(second);
  }

  @Test
  void lateStaleClaimCannotTakeInactiveOwnerReplacement() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection first = connection(5244, 9688, 44);
    Connection second = connection(5245, 9689, 45);
    SSLStorage.setConnectionForReadBuffer(source, first);
    Object stale = SSLStorage.captureReadBufferHandoff(source);
    SSLStorage.cleanupConnection(first);
    SSLStorage.setConnectionForReadBuffer(source, second, true);
    Object current = SSLStorage.captureReadBufferHandoff(source);

    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {1}), source, stale, null, null, null, 1, 1));
    assertSame(second, SSLStorage.getConnectionForReadBuffer(source));
    assertSame(
        second,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}), source, current, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(second);
  }

  @Test
  void staleHandoffCannotPoisonRefreshedGeneration() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection connection = connection(6234, 1678, 15);
    SSLStorage.setConnectionForReadBuffer(source, connection);
    Object stale = SSLStorage.captureReadBufferHandoff(source);

    SSLStorage.setConnectionForReadBuffer(source, connection);
    Object current = SSLStorage.captureReadBufferHandoff(source);

    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {1}), source, stale, null, null, null, 1, 1));
    assertSame(connection, SSLStorage.getConnectionForReadBuffer(source));
    assertSame(
        connection,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}), source, current, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void handoffCanOnlyBeClaimedOnce() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection connection = connection(7234, 2678, 16);
    SSLStorage.setConnectionForReadBuffer(source, connection);
    Object handoff = SSLStorage.captureReadBufferHandoff(source);

    assertSame(
        connection,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {1}), source, handoff, null, null, null, 1, 1));
    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}), source, handoff, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void staleClaimingHandoffCannotPoisonAConsumedGeneration() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection connection = connection(7239, 2683, 54);
    SSLStorage.setConnectionForReadBuffer(source, connection);
    SSLStorage.BufferHandoff available =
        (SSLStorage.BufferHandoff) SSLStorage.captureReadBufferHandoff(source);
    SSLStorage.BufferHandoff staleClaiming =
        new SSLStorage.BufferHandoff(available, SSLStorage.BUFFER_HANDOFF_CLAIMING);

    assertSame(
        connection,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {1}), source, available, null, null, null, 1, 1));
    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}), source, staleClaiming, null, null, null, 1, 1));

    SSLStorage.setConnectionForReadBuffer(source, connection);
    assertSame(connection, SSLStorage.getConnectionForReadBuffer(source));
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void completedReadHandoffCanCrossThreadsWithoutOverlap() throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      ByteBuffer source = ByteBuffer.allocate(8);
      Connection connection = connection(7244, 2688, 52);
      SSLStorage.setConnectionForReadBuffer(source, connection);
      Object handoff = SSLStorage.captureReadBufferHandoff(source);
      SSLEngine engine = new DummySSLEngine(new byte[] {1});

      Future<Connection> claimed =
          executor.submit(
              () ->
                  SSLStorage.claimConnectionForUnwrap(
                      engine, source, handoff, null, null, null, 1, 1));

      assertSame(connection, claimed.get(5, java.util.concurrent.TimeUnit.SECONDS));
      SSLStorage.cleanupConnection(connection);
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  void concurrentHandoffClaimsHaveAtMostOneSessionWinner() throws Exception {
    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      for (int iteration = 0; iteration < 32; iteration++) {
        ByteBuffer source = ByteBuffer.allocate(8);
        Connection connection = connection(7200 + iteration, 8200 + iteration, 100 + iteration);
        SSLEngine firstEngine = new DummySSLEngine(new byte[] {1});
        SSLEngine secondEngine = new DummySSLEngine(new byte[] {2});
        SSLStorage.setConnectionForReadBuffer(source, connection);
        Object handoff = SSLStorage.captureReadBufferHandoff(source);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);

        Callable<Connection> firstClaim =
            () -> {
              ready.countDown();
              assertTrue(start.await(5, java.util.concurrent.TimeUnit.SECONDS));
              return SSLStorage.claimConnectionForUnwrap(
                  firstEngine, source, handoff, null, null, null, 1, 1);
            };
        Callable<Connection> secondClaim =
            () -> {
              ready.countDown();
              assertTrue(start.await(5, java.util.concurrent.TimeUnit.SECONDS));
              return SSLStorage.claimConnectionForUnwrap(
                  secondEngine, source, handoff, null, null, null, 1, 1);
            };

        Future<Connection> first = executor.submit(firstClaim);
        Future<Connection> second = executor.submit(secondClaim);
        assertTrue(ready.await(5, java.util.concurrent.TimeUnit.SECONDS));
        start.countDown();
        Connection firstResult = first.get(5, java.util.concurrent.TimeUnit.SECONDS);
        Connection secondResult = second.get(5, java.util.concurrent.TimeUnit.SECONDS);

        assertTrue(firstResult == null || firstResult == connection);
        assertTrue(secondResult == null || secondResult == connection);
        assertTrue(firstResult == null || secondResult == null);
        assertSame(firstResult, SSLStorage.getConnectionForSession(firstEngine));
        assertSame(secondResult, SSLStorage.getConnectionForSession(secondEngine));
        assertNull(SSLStorage.getConnectionForReadBuffer(source));
        SSLStorage.cleanupConnection(connection);
      }
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  void successfulClaimAllowsSameOwnerReadToRearm() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection connection = connection(7284, 2728, 40);
    SSLStorage.setConnectionForReadBuffer(source, connection);
    Object first = SSLStorage.captureReadBufferHandoff(source);

    assertSame(
        connection,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {1}), source, first, null, null, null, 1, 1));
    assertNull(SSLStorage.getConnectionForReadBuffer(source));

    SSLStorage.setConnectionForReadBuffer(source, connection);
    Object second = SSLStorage.captureReadBufferHandoff(source);

    assertSame(
        connection,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}), source, second, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void successfulClaimMakesDistinctOwnerNonemptyReuseAmbiguous() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection firstOwner = connection(7294, 2738, 41);
    Connection secondOwner = connection(7295, 2739, 42);
    SSLStorage.setConnectionForReadBuffer(source, firstOwner);
    Object first = SSLStorage.captureReadBufferHandoff(source);

    assertSame(
        firstOwner,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {1}), source, first, null, null, null, 1, 1));

    SSLStorage.setConnectionForReadBuffer(source, secondOwner);

    assertNull(SSLStorage.getConnectionForReadBuffer(source));
    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}),
            source,
            SSLStorage.captureReadBufferHandoff(source),
            null,
            null,
            null,
            1,
            1));
    SSLStorage.cleanupConnection(firstOwner);
    SSLStorage.cleanupConnection(secondOwner);
  }

  @Test
  void freshPooledBufferReadAllowsDistinctActiveOwnerReuse() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection firstOwner = connection(7304, 2748, 46);
    Connection secondOwner = connection(7305, 2749, 47);
    SSLEngine firstEngine = new DummySSLEngine(new byte[] {1});
    SSLStorage.setConnectionForReadBuffer(source, firstOwner);
    Object stale = SSLStorage.captureReadBufferHandoff(source);

    assertSame(
        firstOwner,
        SSLStorage.claimConnectionForUnwrap(firstEngine, source, stale, null, null, null, 1, 1));

    SSLStorage.setConnectionForReadBuffer(source, secondOwner, true);
    Object current = SSLStorage.captureReadBufferHandoff(source);

    assertNull(
        SSLStorage.claimConnectionForUnwrap(firstEngine, source, stale, null, null, null, 1, 1));
    assertSame(secondOwner, SSLStorage.getConnectionForReadBuffer(source));
    assertSame(
        secondOwner,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}), source, current, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(firstOwner);
    SSLStorage.cleanupConnection(secondOwner);
  }

  @Test
  void freshPooledBufferReadReplacesAHandshakeOnlyOwner() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection handshakeOwner = connection(7309, 2753, 50);
    Connection applicationOwner = connection(7310, 2754, 51);
    SSLEngine handshakingEngine = new DummySSLEngine();
    SSLStorage.setConnectionForReadBuffer(source, handshakeOwner);
    Object handshake = SSLStorage.captureReadBufferHandoff(source);

    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            handshakingEngine, source, handshake, null, null, null, 1, 1));
    assertSame(handshakeOwner, SSLStorage.getConnectionForReadBuffer(source));

    SSLStorage.setConnectionForReadBuffer(source, applicationOwner, true);
    Object application = SSLStorage.captureReadBufferHandoff(source);

    assertSame(applicationOwner, SSLStorage.getConnectionForReadBuffer(source));
    assertSame(
        applicationOwner,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {1}), source, application, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(handshakeOwner);
    SSLStorage.cleanupConnection(applicationOwner);
  }

  @Test
  void nonemptyDistinctOwnerReuseStaysAmbiguousUntilAFreshRead() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection firstOwner = connection(7314, 2758, 48);
    Connection secondOwner = connection(7315, 2759, 49);
    SSLStorage.setConnectionForReadBuffer(source, firstOwner);
    SSLStorage.setConnectionForReadBuffer(source, secondOwner);

    assertNull(SSLStorage.getConnectionForReadBuffer(source));

    SSLStorage.setConnectionForReadBuffer(source, secondOwner, true);
    Object current = SSLStorage.captureReadBufferHandoff(source);

    assertSame(secondOwner, SSLStorage.getConnectionForReadBuffer(source));
    assertSame(
        secondOwner,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}), source, current, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(firstOwner);
    SSLStorage.cleanupConnection(secondOwner);
  }

  @Test
  void handoffRequiresCiphertextConsumptionAndActualPlaintext() throws Exception {
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection connection = connection(7334, 2778, 24);
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    SSLStorage.setConnectionForReadBuffer(source, connection);
    Object handoff = SSLStorage.captureReadBufferHandoff(source);

    assertNull(
        SSLStorage.claimConnectionForUnwrap(engine, source, handoff, null, null, null, 0, 1));
    assertNull(
        SSLStorage.claimConnectionForUnwrap(engine, source, handoff, null, null, null, 1, 0));
    assertNull(SSLStorage.getConnectionForSession(engine));
    assertSame(
        connection,
        SSLStorage.claimConnectionForUnwrap(engine, source, handoff, null, null, null, 1, 1));
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void cachedOwnerCanEmitBufferedPlaintextWithoutClaimingTheCurrentSource() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection connection = connection(7434, 2878, 28);
    ByteBuffer source = ByteBuffer.allocate(8);
    SSLStorage.setConnectionForSession(engine, connection);
    Object owner = SSLStorage.captureConnectionOwnerForUnwrap(engine, connection);

    assertSame(
        connection,
        SSLStorage.claimConnectionForUnwrap(engine, source, null, connection, owner, null, 0, 1));
    SSLStorage.cleanupConnection(connection);
    assertNull(
        SSLStorage.claimConnectionForUnwrap(engine, source, null, connection, owner, null, 0, 1));
  }

  @Test
  void cleanupInvalidatesAllOutstandingBuffersAndSessionCache() throws Exception {
    ByteBuffer first = ByteBuffer.allocate(8);
    ByteBuffer second = ByteBuffer.allocate(8);
    Connection connection = connection(8234, 3678, 17);
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    SSLStorage.setConnectionForReadBuffer(first, connection);
    SSLStorage.setConnectionForReadBuffer(second, connection);
    Object firstHandoff = SSLStorage.captureReadBufferHandoff(first);
    Object secondHandoff = SSLStorage.captureReadBufferHandoff(second);
    assertSame(
        connection,
        SSLStorage.claimConnectionForUnwrap(engine, first, firstHandoff, null, null, null, 1, 1));

    SSLStorage.cleanupConnection(connection);

    assertNull(SSLStorage.getConnectionForSession(engine));
    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}), second, secondHandoff, null, null, null, 1, 1));
  }

  @Test
  void reusedExactDescriptorGetsANewSessionOwnerGeneration() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    Connection firstGeneration = connection(8334, 3778, 27);
    SSLStorage.setConnectionForSession(engine, firstGeneration);
    SSLStorage.cleanupConnection(firstGeneration);
    Connection secondGeneration = connection(8334, 3778, 27);
    ByteBuffer source = ByteBuffer.allocate(8);
    SSLStorage.setConnectionForReadBuffer(source, secondGeneration);
    Object handoff = SSLStorage.captureReadBufferHandoff(source);

    assertNull(SSLStorage.getConnectionForSession(engine));
    assertSame(
        secondGeneration,
        SSLStorage.claimConnectionForUnwrap(engine, source, handoff, null, null, null, 1, 1));
    assertSame(secondGeneration, SSLStorage.getConnectionForSession(engine));
    SSLStorage.cleanupConnection(secondGeneration);
  }

  @Test
  void cleanupOfOldDescriptorDoesNotInvalidateCurrentDescriptor() throws Exception {
    ByteBuffer oldBuffer = ByteBuffer.allocate(8);
    ByteBuffer currentBuffer = ByteBuffer.allocate(8);
    Connection oldOwner = connection(9234, 4678, 18);
    Connection currentOwner = connection(9234, 4678, 19);
    SSLStorage.setConnectionForReadBuffer(oldBuffer, oldOwner);
    SSLStorage.setConnectionForReadBuffer(currentBuffer, currentOwner);
    Object oldHandoff = SSLStorage.captureReadBufferHandoff(oldBuffer);
    Object currentHandoff = SSLStorage.captureReadBufferHandoff(currentBuffer);

    SSLStorage.cleanupConnection(oldOwner);

    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {1}), oldBuffer, oldHandoff, null, null, null, 1, 1));
    assertSame(
        currentOwner,
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}),
            currentBuffer,
            currentHandoff,
            null,
            null,
            null,
            1,
            1));
    SSLStorage.cleanupConnection(currentOwner);
  }

  @Test
  void repeatedSocketChannelCleanupDoesNotInvalidateAReusedExactConnection() throws Exception {
    Connection first = connection(9434, 4878, 28);
    Connection reused = connection(9434, 4878, 28);
    try (SocketChannel firstChannel = SocketChannel.open();
        SocketChannel reusedChannel = SocketChannel.open()) {
      assertSame(first, SSLStorage.associateConnectionWithSocketChannel(firstChannel, first));
      SSLStorage.cleanupConnection(firstChannel, first);
      assertNull(SSLStorage.getConnectionForSocketChannel(firstChannel));

      assertSame(reused, SSLStorage.associateConnectionWithSocketChannel(reusedChannel, reused));
      SSLStorage.cleanupConnection(firstChannel, first);

      assertSame(reused, SSLStorage.getConnectionForSocketChannel(reusedChannel));
      SSLStorage.cleanupConnection(reusedChannel, reused);
    }
  }

  @Test
  void uncachedSocketChannelCleanupInvalidatesOnlyItsCanonicalOwner() throws Exception {
    Connection closed = connection(9435, 4879, 30);
    Connection lateClose = connection(9435, 4879, 30);
    Connection reused = connection(9435, 4879, 30);
    DummySSLEngine engine = new DummySSLEngine(new byte[] {3});
    ByteBuffer reusedBuffer = ByteBuffer.allocate(8);
    SSLStorage.setConnectionForSession(engine, closed);

    try (SocketChannel channel = SocketChannel.open()) {
      SSLStorage.cleanupConnection(channel, closed);
      assertNull(SSLStorage.getConnectionForSession(engine));

      SSLStorage.setConnectionForReadBuffer(reusedBuffer, reused);
      SSLStorage.cleanupConnection(new Object(), lateClose);

      assertSame(reused, SSLStorage.getConnectionForReadBuffer(reusedBuffer));
      assertNull(SSLStorage.associateConnectionWithSocketChannel(channel, reused));
      assertNull(SSLStorage.getConnectionForSocketChannel(channel));
      SSLStorage.cleanupConnection(reused);
    }
  }

  @Test
  void nonterminalSocketChannelCleanupPreservesTheOpenConnection() throws Exception {
    Connection first = rawConnection(9436, 4880, 31);
    DummySSLEngine engine = new DummySSLEngine(new byte[] {4});
    try (SocketChannel channel = SocketChannel.open()) {
      assertSame(first, SSLStorage.associateConnectionWithSocketChannel(channel, first));
      SSLStorage.setConnectionForSession(engine, first);
      SSLStorage.cleanupConnection(channel, first, false);

      assertSame(first, SSLStorage.getConnectionForSession(engine));
      assertSame(first, SSLStorage.getConnectionForSocketChannel(channel));

      SSLStorage.cleanupConnection(channel, first);
      assertNull(SSLStorage.getConnectionForSession(engine));
      assertNull(SSLStorage.getConnectionForSocketChannel(channel));
    }
  }

  @Test
  void closedNettyScopeCannotReactivateAReusedExactConnection() throws Exception {
    Connection closed = connection(9534, 4978, 29);
    ByteBuffer closedBuffer = ByteBuffer.allocate(8);
    ByteBuffer reusedBuffer = ByteBuffer.allocate(8);
    DummySSLEngine reusedEngine = new DummySSLEngine(new byte[] {1});

    SSLStorage.setConnectionForReadBuffer(closedBuffer, closed);
    assertTrue(SSLStorage.setCurrentNettyConnection(closed));
    SSLStorage.cleanupConnection(closed);

    Connection reused = connection(9534, 4978, 29);
    SSLStorage.setConnectionForReadBuffer(reusedBuffer, reused);
    SSLStorage.setConnectionForSession(reusedEngine, reused);

    assertNull(SSLStorage.currentScopedConnection());
    assertNull(SSLStorage.resolveConnectionForUnwrap(reusedEngine, null));
    assertSame(reused, SSLStorage.getConnectionForReadBuffer(reusedBuffer));
    SSLStorage.nettyConnection.remove();
    SSLStorage.cleanupConnection(reused);
  }

  @Test
  void lateSameChannelConnectionCannotReplaceItsActiveOwner() throws Exception {
    Connection first = connection(9544, 4988, 33);
    Connection conflicting = connection(9544, 4988, 34);
    Object channel = new Object();

    assertSame(first, SSLStorage.associateConnectionWithChannel(channel, first));
    assertNull(SSLStorage.associateConnectionWithChannel(channel, conflicting));
    assertSame(first, SSLStorage.getConnectionForChannel(channel));

    SSLStorage.cleanupConnection(channel, conflicting);
  }

  @Test
  void staleRawNettyScopeCannotBindToAReusedExactConnection() throws Exception {
    Connection stale = connection(9554, 4998, 35);
    Connection reused = connection(9554, 4998, 35);
    ByteBuffer buffer = ByteBuffer.allocate(8);

    SSLStorage.nettyConnection.set(stale);
    SSLStorage.cleanupConnection(stale);
    SSLStorage.setConnectionForReadBuffer(buffer, reused);

    assertNull(SSLStorage.currentScopedConnection());
    assertNull(SSLStorage.resolveConnectionForUnwrap(new DummySSLEngine(new byte[] {1}), null));
    SSLStorage.nettyConnection.remove();
    SSLStorage.cleanupConnection(reused);
  }

  @Test
  void conflictingTentativeOwnerDoesNotReplaceSessionOwner() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    ByteBuffer source = ByteBuffer.allocate(8);
    Connection cached = connection(10234, 5678, 20);
    Connection conflicting = connection(10235, 5679, 21);
    Connection later = connection(10236, 5680, 43);
    SSLStorage.setConnectionForSession(engine, cached);
    SSLStorage.setConnectionForReadBuffer(source, conflicting);
    Object handoff = SSLStorage.captureReadBufferHandoff(source);

    assertNull(SSLStorage.resolveConnectionForUnwrap(engine, handoff));
    assertSame(cached, SSLStorage.getConnectionForSession(engine));
    assertNull(
        SSLStorage.claimConnectionForUnwrap(engine, source, handoff, null, null, null, 1, 1));
    assertSame(cached, SSLStorage.getConnectionForSession(engine));
    assertSame(conflicting, SSLStorage.getConnectionForReadBuffer(source));

    SSLStorage.setConnectionForReadBuffer(source, later);

    assertNull(SSLStorage.getConnectionForReadBuffer(source));
    assertNull(
        SSLStorage.claimConnectionForUnwrap(
            new DummySSLEngine(new byte[] {2}),
            source,
            SSLStorage.captureReadBufferHandoff(source),
            null,
            null,
            null,
            1,
            1));
    SSLStorage.cleanupConnection(cached);
    SSLStorage.cleanupConnection(conflicting);
    SSLStorage.cleanupConnection(later);
  }

  @Test
  void underflowDoesNotClaimTentativeOwner() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    ByteBuffer source = ByteBuffer.wrap(new byte[] {23, 3, 3, 0, 43});
    ByteBuffer destination = ByteBuffer.allocate(8);
    Connection connection = connection(11234, 6678, 22);
    SSLStorage.setConnectionForReadBuffer(source, connection);

    Object[] saved = SSLEngineInst.UnwrapAdvice.unwrap(engine, source, destination);
    SSLEngineInst.UnwrapAdvice.unwrap(
        engine,
        saved,
        source,
        destination,
        new SSLEngineResult(
            SSLEngineResult.Status.BUFFER_UNDERFLOW,
            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
            0,
            0),
        null);

    assertNull(saved[1]);
    assertNull(SSLStorage.getConnectionForSession(engine));
    assertSame(connection, SSLStorage.getConnectionForReadBuffer(source));
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void reportedPlaintextWithoutDestinationAdvanceDoesNotClaim() throws Exception {
    SSLEngine engine = new DummySSLEngine(new byte[] {1});
    ByteBuffer source = ByteBuffer.allocate(8);
    ByteBuffer destination = ByteBuffer.allocate(8);
    Connection connection = connection(12234, 7678, 23);
    SSLStorage.setConnectionForReadBuffer(source, connection);

    Object[] saved = SSLEngineInst.UnwrapAdvice.unwrap(engine, source, destination);
    SSLEngineInst.UnwrapAdvice.unwrap(
        engine,
        saved,
        source,
        destination,
        new SSLEngineResult(
            SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 1, 1),
        null);

    assertNull(SSLStorage.getConnectionForSession(engine));
    assertSame(connection, SSLStorage.getConnectionForReadBuffer(source));
    SSLStorage.cleanupConnection(connection);
  }

  private static void installNettyScope(Connection connection) {
    SSLStorage.setConnectionForReadBuffer(ByteBuffer.allocate(1), connection);
    assertTrue(SSLStorage.setCurrentNettyConnection(connection));
  }

  private Connection connection(int localPort, int remotePort, int fileDescriptor)
      throws Exception {
    return own(rawConnection(localPort, remotePort, fileDescriptor));
  }

  private static Connection rawConnection(int localPort, int remotePort, int fileDescriptor)
      throws Exception {
    return new Connection(
        InetAddress.getByName("127.0.0.1"),
        localPort,
        InetAddress.getByName("127.0.0.2"),
        remotePort,
        fileDescriptor);
  }

  private Connection own(Connection connection) {
    if (connection.getSocketFileDescriptor() < 0) {
      return connection;
    }
    Object physicalOwner = new Object();
    physicalOwners.add(physicalOwner);
    assertSame(
        connection,
        SSLStorage.associateConnectionWithPhysicalOwnerForTest(physicalOwner, connection));
    ownedConnections.add(connection);
    return connection;
  }

  @Test
  void testBufferMapping() {
    String encrypted = "enc";
    BytesWithLen plain = new BytesWithLen(new byte[] {1, 2, 3}, 3);

    assertNull(SSLStorage.getUnencryptedBuffer(encrypted));
    SSLStorage.setBufferMapping(encrypted, plain);
    assertEquals(plain, SSLStorage.getUnencryptedBuffer(encrypted));
    SSLStorage.removeBufferMapping(encrypted);
    assertNull(SSLStorage.getUnencryptedBuffer(encrypted));
  }

  @Test
  void taskParentIsConsumedBeforeWorkerReuse() {
    Object reusableTask = new Object();

    SSLStorage.trackTask(101L, reusableTask);
    assertEquals(101L, SSLStorage.takeTaskContext(reusableTask).getParentThreadId());
    assertNull(SSLStorage.takeTaskContext(reusableTask));

    SSLStorage.trackTask(202L, reusableTask);
    assertEquals(202L, SSLStorage.takeTaskContext(reusableTask).getParentThreadId());
    assertNull(SSLStorage.takeTaskContext(reusableTask));
  }

  @Test
  void taskIdentityHashCollisionDoesNotCrossContaminateParents() {
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(4);
    Object first = new Object();
    Object second = new Object();

    tasks.track(first, new TaskContext(101L, 0L), 7);
    tasks.track(second, new TaskContext(202L, 0L), 7);

    assertEquals(101L, tasks.get(first, 7, false).getParentThreadId());
    assertEquals(202L, tasks.get(second, 7, false).getParentThreadId());
    assertEquals(101L, tasks.get(first, 7, true).getParentThreadId());
    assertEquals(202L, tasks.get(second, 7, true).getParentThreadId());
  }

  @Test
  void taskOwnershipMapRemainsBounded() {
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(2);
    Object first = new Object();
    Object second = new Object();
    Object third = new Object();

    tasks.track(first, new TaskContext(101L, 0L), 1);
    tasks.track(second, new TaskContext(202L, 0L), 2);
    tasks.track(third, new TaskContext(303L, 0L), 3);

    assertNull(tasks.get(first, 1, false));
    assertEquals(202L, tasks.get(second, 2, false).getParentThreadId());
    assertEquals(303L, tasks.get(third, 3, false).getParentThreadId());
  }

  @Test
  void repeatedNettyReflectionFailuresLogOnlyOnceWhenDebugIsDisabled() throws Exception {
    PrintStream originalError = System.err;
    boolean originalDebug = SSLStorage.debugOn;
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    SSLStorage.debugOn = false;
    SSLStorage.resetNettyFailureLoggingForTest();
    try {
      System.setErr(new PrintStream(output, true, "UTF-8"));
      for (int i = 0; i < 10; i++) {
        SSLStorage.logNettyAdviceFailure("test operation", new ReflectiveOperationException());
      }
    } finally {
      System.setErr(originalError);
      SSLStorage.debugOn = originalDebug;
      SSLStorage.resetNettyFailureLoggingForTest();
    }

    String message = output.toString("UTF-8");
    assertEquals(1, message.split("Netty helper unavailable", -1).length - 1);
  }

  @Test
  void concurrentParentsForTheSameTaskFailOpenAsAmbiguous() throws Exception {
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(4);
    Object shared = new Object();
    CountDownLatch start = new CountDownLatch(1);
    ExecutorService executor = Executors.newFixedThreadPool(2);

    try {
      Future<?> first =
          executor.submit(
              () -> {
                start.await();
                tasks.track(shared, new TaskContext(101L, 0L), 7);
                return null;
              });
      Future<?> second =
          executor.submit(
              () -> {
                start.await();
                tasks.track(shared, new TaskContext(202L, 0L), 7);
                return null;
              });
      start.countDown();
      first.get();
      second.get();
    } finally {
      executor.shutdownNow();
    }

    assertNull(tasks.get(shared, 7, false));
    assertNull(tasks.get(shared, 7, true));
    assertNull(tasks.get(shared, 7, true));

    tasks.track(shared, new TaskContext(303L, 0L), 7);
    assertEquals(303L, tasks.get(shared, 7, true).getParentThreadId());
  }

  @Test
  void nestedSubmissionAdviceReusesTheOuterTaskCapture() {
    Runnable task = () -> {};
    SSLStorage.setThreadIdProviderForTest(() -> 101L);

    int outer = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(task, "execute");
    TaskContext captured = SSLStorage.taskContext(task);
    int nested = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(task, "addTask");

    assertEquals(SSLStorage.SUBMISSION_OWNER, outer);
    assertEquals(SSLStorage.SUBMISSION_NESTED, nested);
    assertSame(captured, SSLStorage.taskContext(task));
    JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
        Runnable::run, task, "addTask", null, nested);
    JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
        Runnable::run, task, "execute", null, outer);
    assertSame(captured, SSLStorage.takeTaskContext(task));
  }

  @Test
  void concurrentAdviceSubmissionsOfTheSameObjectFailOpenInEitherRunOrder() throws Exception {
    Runnable shared = () -> {};
    CountDownLatch entered = new CountDownLatch(2);
    CountDownLatch exit = new CountDownLatch(1);
    SSLStorage.setThreadIdProviderForTest(() -> Thread.currentThread().getId() + 100L);
    ExecutorService executor = Executors.newFixedThreadPool(2);

    try {
      Future<?> first = executor.submit(() -> submitAndWait(shared, entered, exit));
      Future<?> second = executor.submit(() -> submitAndWait(shared, entered, exit));
      assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS));
      exit.countDown();
      first.get();
      second.get();
    } finally {
      exit.countDown();
      executor.shutdownNow();
    }

    assertFalse(RunnableInst.RunnableAdvice.enter(shared));
    assertFalse(RunnableInst.RunnableAdvice.enter(shared));
    assertNull(SSLStorage.takeTaskContext(shared));
    SSLStorage.untrackTask(shared);
  }

  @Test
  void sequentialSameTidSubmissionsCarryDifferentGenerationsAndBecomeAmbiguous() {
    Runnable shared = () -> {};
    SSLStorage.setThreadIdProviderForTest(() -> 77L);

    int first = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(shared, "execute");
    JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
        Runnable::run, shared, "execute", null, first);
    int second = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(shared, "execute");
    JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
        Runnable::run, shared, "execute", null, second);

    assertNull(SSLStorage.takeTaskContext(shared));
    SSLStorage.untrackTask(shared);
  }

  @Test
  void successfulFutureCancellationCleansWrapperAndSubmittedTask() {
    Runnable submitted = () -> {};
    FutureTask<Void> future = new FutureTask<>(submitted, null);
    SSLStorage.trackTask(101L, submitted);
    SSLStorage.trackTask(101L, future);
    SSLStorage.trackTaskCancellation(future, submitted);

    FutureInst.CancelAdvice.exit(future, true, null);

    assertNull(SSLStorage.taskContext(future));
    assertNull(SSLStorage.taskContext(submitted));
  }

  @Test
  void customFutureCancellationDoesNotDropTheTaskBeforeCancellation() {
    Runnable submitted = () -> {};
    CompletableFuture<Void> future = new CompletableFuture<>();
    SSLStorage.trackTask(101L, submitted);

    SSLStorage.trackTaskCancellation(future, submitted);
    assertNotNull(SSLStorage.taskContext(submitted));
    FutureInst.CancelAdvice.exit(future, true, null);

    assertNull(SSLStorage.taskContext(submitted));
  }

  @Test
  void forkJoinCancellationCleansItsPendingContext() {
    ForkJoinTask<?> task = ForkJoinTask.adapt(() -> {});
    SSLStorage.trackTask(101L, task);

    FutureInst.CancelAdvice.exit(task, true, null);

    assertNull(SSLStorage.taskContext(task));
  }

  @Test
  void executingWrapperConsumesTheSubmittedTasksCancellationEntry() {
    Runnable submitted = () -> {};
    FutureTask<Void> future = new FutureTask<>(submitted, null);
    SSLStorage.trackTask(101L, submitted);
    SSLStorage.trackTask(101L, future);
    SSLStorage.trackTaskCancellation(future, submitted);

    assertNotNull(SSLStorage.takeTaskContext(future));

    assertNull(SSLStorage.taskContext(submitted));
  }

  @Test
  void cancellationOwnerCyclesAreRemovedOnce() {
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(4);
    Object first = new Object();
    Object second = new Object();
    tasks.track(first, new TaskContext(101L, 0L));
    tasks.track(second, new TaskContext(101L, 0L));
    tasks.trackCancellationOwner(first, second);
    tasks.trackCancellationOwner(second, first);

    tasks.untrack(first);

    assertNull(tasks.get(first));
    assertNull(tasks.get(second));
  }

  @Test
  void longCancellationOwnerChainsDoNotRecurse() {
    int chainLength = 1_024;
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(chainLength);
    Object[] chain = new Object[chainLength];
    for (int i = 0; i < chain.length; i++) {
      chain[i] = new Object();
      tasks.track(chain[i], new TaskContext(101L, 0L));
      if (i > 0) {
        tasks.trackCancellationOwner(chain[i - 1], chain[i]);
      }
    }

    tasks.untrack(chain[0]);

    for (Object task : chain) {
      assertNull(tasks.get(task));
    }
  }

  @Test
  void shutdownNowAndQueueRemovalCleanReturnedTasks() {
    FutureTask<Void> removed = new FutureTask<>(() -> {}, null);
    FutureTask<Void> shutdown = new FutureTask<>(() -> {}, null);
    SSLStorage.trackTask(101L, removed);
    SSLStorage.trackTask(101L, shutdown);

    JavaExecutorInst.RemoveTaskAdvice.exit(removed, true, null);
    JavaExecutorInst.ShutdownNowAdvice.exit(java.util.Collections.singletonList(shutdown), null);

    assertNull(SSLStorage.taskContext(removed));
    assertNull(SSLStorage.taskContext(shutdown));
  }

  @Test
  void silentDiscardPolicyCleansTheRejectedTask() {
    Runnable rejected = () -> {};
    SSLStorage.trackTask(101L, rejected);
    Object queue = new Object();

    int rejection =
        SSLStorage.beginRejectedExecution(new ThreadPoolExecutor.DiscardPolicy(), queue);
    SSLStorage.endRejectedExecution(rejection, rejected, false);

    assertNull(SSLStorage.taskContext(rejected));
  }

  @Test
  void discardOldestPolicyCleansOnlyThePolledTaskFromItsQueue() {
    Runnable oldest = () -> {};
    Runnable replacement = () -> {};
    SSLStorage.trackTask(101L, oldest);
    SSLStorage.trackTask(101L, replacement);
    Object rejectedQueue = new Object();
    Object unrelatedQueue = new Object();

    int rejection =
        SSLStorage.beginRejectedExecution(
            new ThreadPoolExecutor.DiscardOldestPolicy(), rejectedQueue);
    BlockingQueueInst.PollAdvice.exit(unrelatedQueue, replacement, null);
    BlockingQueueInst.PollAdvice.exit(rejectedQueue, oldest, null);
    SSLStorage.endRejectedExecution(rejection, replacement, false);

    assertNull(SSLStorage.taskContext(oldest));
    assertNotNull(SSLStorage.taskContext(replacement));
    SSLStorage.untrackTask(replacement);
  }

  @Test
  void discardOldestPolicyCleansTheRejectedTaskAfterShutdown() {
    Runnable rejected = () -> {};
    SSLStorage.trackTask(101L, rejected);

    int rejection =
        SSLStorage.beginRejectedExecution(
            new ThreadPoolExecutor.DiscardOldestPolicy(), new Object());
    SSLStorage.endRejectedExecution(rejection, rejected, true);

    assertNull(SSLStorage.taskContext(rejected));
  }

  @Test
  void customRejectionHandlersRetainTaskOwnership() {
    Runnable rejected = () -> {};
    RejectedExecutionHandler customHandler = (task, executor) -> {};
    SSLStorage.trackTask(101L, rejected);

    int rejection = SSLStorage.beginRejectedExecution(customHandler, new Object());
    SSLStorage.endRejectedExecution(rejection, rejected, false);

    assertNotNull(SSLStorage.taskContext(rejected));
    SSLStorage.untrackTask(rejected);
  }

  @Test
  void bulkSubmissionDoesNotReplaceANestedCallableCapture() {
    Callable<Void> task = () -> null;
    SSLStorage.setThreadIdProviderForTest(() -> 101L);

    Object[][] bulk =
        JavaExecutorInst.SetCallableStateForCallableCollectionAdvice.submitEnter(
            Arrays.asList(task));
    TaskContext captured = SSLStorage.taskContext(task);
    int nested = JavaExecutorInst.SetCallableStateAdvice.enterJobSubmit(task, "submit");

    assertEquals(SSLStorage.SUBMISSION_NESTED, nested);
    assertSame(captured, SSLStorage.taskContext(task));
    JavaExecutorInst.SetCallableStateAdvice.exitJobSubmit(task, "submit", null, null, nested);
    assertSame(captured, SSLStorage.taskContext(task));
    JavaExecutorInst.SetCallableStateForCallableCollectionAdvice.submitExit(bulk);
    assertNull(SSLStorage.taskContext(task));
  }

  @Test
  void forkJoinInternalSubmissionTransfersHiddenRunnableToItsWrapper() {
    Runnable task = () -> {};
    ForkJoinTask<?> wrapper = ForkJoinTask.adapt(task);
    SSLStorage.setThreadIdProviderForTest(() -> 101L);

    int outer = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(task, "execute");
    int wrapped =
        JavaExecutorInst.SetJavaForkJoinStateAdvice.enterJobSubmit(wrapper, "externalPush");
    JavaExecutorInst.SetJavaForkJoinStateAdvice.exitJobSubmit(wrapper, null, wrapped);
    JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
        ForkJoinPool.commonPool(), task, "execute", null, outer);

    assertNull(SSLStorage.taskContext(task));
    assertNotNull(SSLStorage.taskContext(wrapper));
    SSLStorage.untrackTask(wrapper);
  }

  @Test
  void throwingBeforeExecuteCleansTheTaskWithoutAfterExecute() {
    Runnable task = () -> {};
    SSLStorage.trackTask(101L, task);

    boolean outermost = JavaExecutorInst.BeforeExecuteAdvice.enter();
    JavaExecutorInst.BeforeExecuteAdvice.exit(
        task, new IllegalStateException("rejected"), outermost);

    assertNull(SSLStorage.taskContext(task));
  }

  private static void submitAndWait(Runnable task, CountDownLatch entered, CountDownLatch exit) {
    int submission = JavaExecutorInst.SetExecuteRunnableStateAdvice.enterJobSubmit(task, "execute");
    entered.countDown();
    try {
      assertTrue(exit.await(5, java.util.concurrent.TimeUnit.SECONDS));
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new AssertionError(interrupted);
    } finally {
      JavaExecutorInst.SetExecuteRunnableStateAdvice.exitJobSubmit(
          Runnable::run, task, "execute", null, submission);
    }
  }

  private static boolean waitForInactive(RemoteParentSocketContext.Lifecycle lifecycle) {
    long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
    while (lifecycle.active() && System.nanoTime() - deadline < 0) {
      Thread.yield();
    }
    return !lifecycle.active();
  }
}
