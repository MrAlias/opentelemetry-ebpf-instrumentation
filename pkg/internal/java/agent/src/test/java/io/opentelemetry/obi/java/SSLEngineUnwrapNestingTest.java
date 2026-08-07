/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.opentelemetry.obi.java.bridge.RemoteParentBridge;
import io.opentelemetry.obi.java.ebpf.NativeMemoryTestAccess;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.SSLEngineInst;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.ReceiveContext;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SSLEngineUnwrapNestingTest {
  private final List<Object> physicalOwners = new ArrayList<>();

  @AfterEach
  void cleanup() {
    BootstrapNative.setEmitDataOnSocketForTest(null);
    BootstrapNative.setSocketFileDescriptorForTest(null);
    NativeMemoryTestAccess.setSyntheticAddress(false);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    ThreadInfo.takeRemoteParentReceiveContext();
    ThreadInfo.clearRemoteParentLookupSource();
    ThreadInfo.setRemoteParentEnabled(false);
    physicalOwners.clear();
  }

  @Test
  void delegatingPublicUnwrapOverloadsEmitExactlyOnceAndResetTheirNestingScope() throws Exception {
    ThreadInfo.setRemoteParentEnabled(false);
    NativeMemoryTestAccess.setSyntheticAddress(true);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    SSLEngine engine = transformedDelegatingEngine();
    Connection connection = connection(91);
    SSLStorage.setConnectionForSession(engine, connection);
    long initialTlsReadEvents = RemoteParentBridge.tlsReadEvents();

    try {
      engine.unwrap(ByteBuffer.wrap(new byte[] {1}), ByteBuffer.allocate(4));
      assertEquals(1, emissions.get());
      assertEquals(initialTlsReadEvents + 1, RemoteParentBridge.tlsReadEvents());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());

      engine.unwrap(ByteBuffer.wrap(new byte[] {2}), new ByteBuffer[] {ByteBuffer.allocate(4)});
      assertEquals(2, emissions.get());
      assertEquals(initialTlsReadEvents + 2, RemoteParentBridge.tlsReadEvents());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());

      // A direct ranged call after each wrapper proves every nested scope was balanced.
      engine.unwrap(
          ByteBuffer.wrap(new byte[] {3}), new ByteBuffer[] {ByteBuffer.allocate(4)}, 0, 1);
      assertEquals(3, emissions.get());
      assertEquals(initialTlsReadEvents + 3, RemoteParentBridge.tlsReadEvents());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());

      long disabledEpoch = ThreadInfo.remoteParentBridgeEpoch();
      ThreadInfo.setRemoteParentEnabled(true);
      assertEquals(disabledEpoch, ThreadInfo.remoteParentBridgeEpoch());
      Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
      TaskContext handoff = ThreadInfo.captureTaskContext(101L, lifecycle);
      assertEquals(0L, handoff.getHandoffToken());
    } finally {
      SSLStorage.cleanupConnection(connection);
    }
  }

  @Test
  void bridgeEnabledPublicUnwrapOverloadsStartDistinctKeepaliveSequences() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = successfulEmitter();
    SSLEngine engine = transformedDelegatingEngine();
    Connection connection = connection(90);
    SSLStorage.setConnectionForSession(engine, connection);
    byte[] request = ascii("GET /keepalive HTTP/1.1\r\nHost: example\r\n\r\n");

    try {
      engine.unwrap(ByteBuffer.wrap(request), ByteBuffer.allocate(request.length));
      ReceiveContext first = acknowledgeReceive();
      assertEquals(1L, first.requestSequence());

      engine.unwrap(
          ByteBuffer.wrap(request), new ByteBuffer[] {ByteBuffer.allocate(request.length)});
      ReceiveContext second = acknowledgeReceive();
      assertEquals(2L, second.requestSequence());

      engine.unwrap(
          ByteBuffer.wrap(request), new ByteBuffer[] {ByteBuffer.allocate(request.length)}, 0, 1);
      ReceiveContext third = acknowledgeReceive();
      assertEquals(3L, third.requestSequence());

      assertEquals(3, emissions.get());
      assertEquals(first.lifecycle().id(), second.lifecycle().id());
      assertEquals(second.lifecycle().id(), third.lifecycle().id());
    } finally {
      SSLStorage.cleanupConnection(connection);
    }
  }

  @Test
  void bridgeEnabledScalarUnwrapDefersNineLargeHeaderCallbacksUntilOneStart() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = successfulEmitter();
    SSLEngine engine = transformedDelegatingEngine();
    Connection connection = connection(89);
    SSLStorage.setConnectionForSession(engine, connection);
    byte[] header = headerOfSize(18_424);

    try {
      int cursor = 0;
      for (int callback = 0; callback < 9; callback++) {
        int count = Math.min(2048, header.length - cursor);
        byte[] fragment = new byte[count];
        System.arraycopy(header, cursor, fragment, 0, count);
        engine.unwrap(ByteBuffer.wrap(fragment), ByteBuffer.allocate(fragment.length));
        cursor += count;
        assertEquals(callback == 8 ? 1 : 0, emissions.get());
      }
      assertEquals(header.length, cursor);
      assertEquals(1L, acknowledgeReceive().requestSequence());
    } finally {
      SSLStorage.cleanupConnection(connection);
    }
  }

  @Test
  void disabledFragmentsKeepExactLegacyEmissionThenReenableStaysTelemetryOnly() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = successfulEmitter();
    SSLEngine engine = new DelegatingSSLEngine();
    Connection connection = connection(87);
    SSLStorage.setConnectionForSession(engine, connection);
    Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    byte[] request = ascii("GET /old HTTP/1.1\r\nHost: example\r\n\r\n");

    try {
      assertEquals(
          1, SSLStorage.emitRemoteParentReceive(engine, connection, request, 0, request.length));
      assertEquals(1, emissions.get());

      ThreadInfo.advanceRemoteParentBridgeEpoch();
      ThreadInfo.setRemoteParentEnabled(false);
      byte[] disabledOne = ascii("disabled-one");
      byte[] disabledTwo = ascii("disabled-two");
      assertEquals(
          1,
          SSLStorage.emitRemoteParentReceive(
              engine, connection, disabledOne, 0, disabledOne.length));
      assertEquals(3, emissions.get()); // one RESET plus this fragment's one legacy RECEIVE
      assertEquals(
          1,
          SSLStorage.emitRemoteParentReceive(
              engine, connection, disabledTwo, 0, disabledTwo.length));
      assertEquals(4, emissions.get()); // exactly one additional legacy RECEIVE

      ThreadInfo.setRemoteParentEnabled(true);
      byte[] afterReenable = ascii("GET /new HTTP/1.1\r\nHost: example\r\n\r\n");
      assertEquals(
          1,
          SSLStorage.emitRemoteParentReceive(
              engine, connection, afterReenable, 0, afterReenable.length));
      assertEquals(5, emissions.get()); // sticky TELEMETRY_RECEIVE, never a new START

      SSLStorage.closeRemoteParentHttp1(engine, lifecycle);
      SSLStorage.closeRemoteParentHttp1(engine, lifecycle);
      assertEquals(5, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
    } finally {
      SSLStorage.cleanupConnection(connection);
    }
  }

  @Test
  void legacyRawDescriptorReceiveStillStagesThePrimaryProbe() {
    ThreadInfo.setRemoteParentEnabled(true);
    BootstrapNative.setEmitDataOnSocketForTest((socketFileDescriptor, packetAddress) -> 1);

    assertEquals(1, BootstrapNative.emitData(92, 1L, true));
    assertEquals(92, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());
  }

  @Test
  void providerTransitionDuringNativeCallCannotStageAnyLegacyReceivePath() throws Exception {
    ThreadInfo.setRemoteParentEnabled(true);
    long rawEpoch = ThreadInfo.remoteParentBridgeEpoch();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          ThreadInfo.setRemoteParentEnabled(false);
          return 1;
        });

    assertEquals(1, BootstrapNative.emitData(96, 1L, true));
    assertEquals(rawEpoch, ThreadInfo.remoteParentBridgeEpoch());
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());

    ThreadInfo.setRemoteParentEnabled(true);
    Connection connection = connection(97);
    try {
      BootstrapNative.setEmitDataOnSocketForTest(
          (socketFileDescriptor, packetAddress) -> {
            ThreadInfo.advanceRemoteParentBridgeEpoch();
            return 1;
          });

      assertEquals(1, BootstrapNative.emitData(connection, 1L, true));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
    } finally {
      SSLStorage.cleanupConnection(connection);
    }

    ThreadInfo.setRemoteParentEnabled(true);
    BootstrapNative.setSocketFileDescriptorForTest(socket -> 98);
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          ThreadInfo.setRemoteParentEnabled(false);
          return 1;
        });
    try (Socket socket = new Socket()) {
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.prepareRemoteParentSocketLifecycle(socket);

      assertEquals(1, BootstrapNative.emitData(socket, 1L, true));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());

      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, lifecycle);
    }
  }

  @Test
  void zeroResultForTheSameConnectionClearsOwnershipWithoutInvalidatingItsLifecycle()
      throws Exception {
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> emissions.getAndIncrement() == 0 ? 1 : 0);
    Connection connection = connection(98, 1234, 5678);
    Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertNotNull(lifecycle);
    RemoteParentSocketContext alias = new RemoteParentSocketContext(98, lifecycle);

    try {
      assertEquals(1, BootstrapNative.emitData(connection, 1L, true));
      assertEquals(98, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(0, BootstrapNative.emitData(connection, 2L, true));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());
      assertSame(lifecycle, SSLStorage.remoteParentSocketLifecycle(connection));
      assertEquals(98, alias.peek());
    } finally {
      SSLStorage.cleanupConnection(connection);
    }
  }

  @Test
  void acknowledgedHttp1ContinuationRetainsTheExactDescriptorUntilExtraction() throws Exception {
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> emissions.getAndIncrement() == 0 ? 1 : 0);
    Connection connection = connection(88);

    try {
      assertEquals(1, BootstrapNative.emitData(connection, 1L, true));
      assertEquals(88, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(
          0,
          BootstrapNative.emitHttp1Data(
              connection, 2L, OperationType.HTTP1_RECEIVE_CONTINUE, true));
      assertEquals(88, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_DIRECT, ThreadInfo.remoteParentLookupSource());
    } finally {
      SSLStorage.cleanupConnection(connection);
    }
  }

  @Test
  void throwingReceiveRemainsBlockedAfterTheAttemptReturns() {
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          throw new IllegalStateException("emit failed");
        });

    assertThrows(IllegalStateException.class, () -> BootstrapNative.emitData(92, 1L, true));
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void zeroResultForAnotherConnectionCannotRetainAReusedDescriptor() throws Exception {
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> emissions.getAndIncrement() == 0 ? 1 : 0);
    Connection first = connection(99, 1234, 5678);
    Connection second = connection(99, 1235, 5679);

    try {
      assertEquals(1, BootstrapNative.emitData(first, 1L, true));
      assertEquals(99, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(0, BootstrapNative.emitData(second, 2L, true));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    } finally {
      SSLStorage.cleanupConnection(first);
      SSLStorage.cleanupConnection(second);
    }
  }

  @Test
  void zeroResultWithoutAnExactLifecycleKeepsLegacyClearSemantics() {
    BootstrapNative.setEmitDataOnSocketForTest((socketFileDescriptor, packetAddress) -> 0);
    ThreadInfo.setRemoteParentSocketFileDescriptor(100);

    assertEquals(0, BootstrapNative.emitData(100, 1L, true));
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void closeInboundPreventsALateConnectionReceiveFromEmittingOrStaging() throws Exception {
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    SSLEngine engine = new DelegatingSSLEngine();
    Connection connection = connection(93);
    SSLStorage.setConnectionForSession(engine, connection);
    SSLEngineInst.CloseInboundAdvice.closeInbound(engine);
    ThreadInfo.setRemoteParentSocketFileDescriptor(94);

    assertEquals(-1, BootstrapNative.emitData(connection, 1L, true));
    assertEquals(0, emissions.get());
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void scalarFinalPlaintextEmissionRetiresItsDescriptorCorrelation() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    AtomicInteger emissions = successfulEmitter();
    SSLEngine engine = new DelegatingSSLEngine();
    Connection connection = connection(95);
    SSLStorage.setConnectionForSession(engine, connection);
    Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertNotNull(lifecycle);
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);
    ByteBuffer source = ByteBuffer.wrap(new byte[] {1});
    ByteBuffer destination = ByteBuffer.allocate(4);

    try {
      Object[] saved = SSLEngineInst.UnwrapAdvice.unwrap(engine, source, destination);
      destination.put((byte) 1);
      SSLEngineInst.UnwrapAdvice.unwrap(
          engine, saved, source, destination, closedPlaintextResult(), null);

      assertEquals(1, emissions.get());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(-1, alias.peek());
      assertNull(SSLStorage.remoteParentSocketLifecycle(connection));
      assertNull(SSLStorage.getConnectionForSession(engine));
    } finally {
      SSLStorage.cleanupConnection(connection);
    }
  }

  @Test
  void bridgeEnabledClosedScalarUnwrapDrainsDeferredPlaintextBeforeInvalidation() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = successfulEmitter();
    SSLEngine engine = new DelegatingSSLEngine();
    Connection connection = connection(94);
    SSLStorage.setConnectionForSession(engine, connection);
    ByteBuffer source = ByteBuffer.wrap(new byte[] {1});
    ByteBuffer destination = ByteBuffer.allocate(4);

    try {
      Object[] saved = SSLEngineInst.UnwrapAdvice.unwrap(engine, source, destination);
      destination.put((byte) 'G');
      SSLEngineInst.UnwrapAdvice.unwrap(
          engine, saved, source, destination, closedPlaintextResult(), null);

      assertEquals(1, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
      assertNull(SSLStorage.remoteParentSocketLifecycle(connection));
    } finally {
      SSLStorage.cleanupConnection(connection);
    }
  }

  @Test
  void arrayFinalPlaintextEmissionRetiresItsDescriptorCorrelation() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    AtomicInteger emissions = successfulEmitter();
    SSLEngine engine = new DelegatingSSLEngine();
    Connection connection = connection(96);
    SSLStorage.setConnectionForSession(engine, connection);
    Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertNotNull(lifecycle);
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);
    ByteBuffer source = ByteBuffer.wrap(new byte[] {1});
    ByteBuffer[] destinations = {ByteBuffer.allocate(4)};

    try {
      Object[] saved = SSLEngineInst.UnwrapAdviceArray.unwrap(engine, source, destinations);
      destinations[0].put((byte) 1);
      SSLEngineInst.UnwrapAdviceArray.unwrap(
          engine, saved, source, destinations, closedPlaintextResult(), null);

      assertEquals(1, emissions.get());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(-1, alias.peek());
      assertNull(SSLStorage.remoteParentSocketLifecycle(connection));
      assertNull(SSLStorage.getConnectionForSession(engine));
    } finally {
      SSLStorage.cleanupConnection(connection);
    }
  }

  @Test
  void rangedArrayFinalPlaintextEmissionRetiresItsDescriptorCorrelation() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    AtomicInteger emissions = successfulEmitter();
    SSLEngine engine = new DelegatingSSLEngine();
    Connection connection = connection(97);
    SSLStorage.setConnectionForSession(engine, connection);
    Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
    assertNotNull(lifecycle);
    RemoteParentSocketContext alias =
        new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);
    ByteBuffer source = ByteBuffer.wrap(new byte[] {1});
    ByteBuffer[] destinations = {ByteBuffer.allocate(4)};

    try {
      Object[] saved =
          SSLEngineInst.UnwrapAdviceArrayOffset.unwrap(engine, source, destinations, 0, 1);
      destinations[0].put((byte) 1);
      SSLEngineInst.UnwrapAdviceArrayOffset.unwrap(
          engine, saved, source, destinations, 0, 1, closedPlaintextResult(), null);

      assertEquals(1, emissions.get());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(-1, alias.peek());
      assertNull(SSLStorage.remoteParentSocketLifecycle(connection));
      assertNull(SSLStorage.getConnectionForSession(engine));
    } finally {
      SSLStorage.cleanupConnection(connection);
    }
  }

  private static AtomicInteger successfulEmitter() {
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });
    return emissions;
  }

  private static ReceiveContext acknowledgeReceive() {
    ReceiveContext context = ThreadInfo.takeRemoteParentReceiveContext();
    assertNotNull(context);
    ThreadInfo.finishRemoteParentExtraction(context);
    return context;
  }

  private static byte[] headerOfSize(int target) {
    StringBuilder header = new StringBuilder("GET /split HTTP/1.1\r\nHost: example\r\n");
    while (target - header.length() - 2 > 0) {
      int lineLength = Math.min(7000, target - header.length() - 2);
      if (lineLength < 4) {
        throw new IllegalArgumentException("unrepresentable header size");
      }
      header.append("X:");
      for (int i = 0; i < lineLength - 4; i++) {
        header.append('a');
      }
      header.append("\r\n");
    }
    header.append("\r\n");
    byte[] result = ascii(header.toString());
    assertEquals(target, result.length);
    return result;
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static SSLEngineResult closedPlaintextResult() {
    return new SSLEngineResult(
        SSLEngineResult.Status.CLOSED, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 1, 1);
  }

  private SSLEngine transformedDelegatingEngine() throws Exception {
    DynamicType.Builder<?> builder =
        new ByteBuddy()
            .redefine(DelegatingSSLEngine.class)
            .name(DelegatingSSLEngine.class.getName() + "$Instrumented");
    TypeDescription type = new TypeDescription.ForLoadedType(DelegatingSSLEngine.class);
    Class<?> transformed =
        SSLEngineInst.transformer()
            .transform(builder, type, getClass().getClassLoader(), null, null)
            .make()
            .load(getClass().getClassLoader(), ClassLoadingStrategy.Default.WRAPPER)
            .getLoaded();
    return (SSLEngine) transformed.getDeclaredConstructor().newInstance();
  }

  private Connection connection(int fileDescriptor) throws Exception {
    return connection(fileDescriptor, 1234, 5678);
  }

  private Connection connection(int fileDescriptor, int localPort, int remotePort)
      throws Exception {
    Connection connection =
        new Connection(
            InetAddress.getByName("127.0.0.1"),
            localPort,
            InetAddress.getByName("127.0.0.2"),
            remotePort,
            fileDescriptor);
    Object physicalOwner = new Object();
    physicalOwners.add(physicalOwner);
    assertSame(connection, SSLStorage.associateConnectionWithChannel(physicalOwner, connection));
    return connection;
  }

  /**
   * Public wrappers deliberately delegate to the ranged overload, as JDK convenience methods do.
   */
  public static class DelegatingSSLEngine extends SSLEngine {
    private final SSLSession session = session();

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
      return unwrap(src, new ByteBuffer[] {dst}, 0, 1);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
      return unwrap(src, dsts, 0, dsts.length);
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
        throws SSLException {
      if (src == null || dsts == null || length != 1 || dsts[offset] == null) {
        throw new SSLException("invalid test unwrap");
      }
      ByteBuffer dst = dsts[offset];
      if (!src.hasRemaining() || !dst.hasRemaining()) {
        return new SSLEngineResult(
            SSLEngineResult.Status.BUFFER_UNDERFLOW,
            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
            0,
            0);
      }
      int count = Math.min(src.remaining(), dst.remaining());
      for (int i = 0; i < count; i++) {
        dst.put(src.get());
      }
      return new SSLEngineResult(
          SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, count, count);
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) {
      return result();
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) {
      return result();
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
      return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
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
    public void setEnableSessionCreation(boolean enabled) {}

    @Override
    public void setNeedClientAuth(boolean need) {}

    @Override
    public void setUseClientMode(boolean mode) {}

    @Override
    public void setWantClientAuth(boolean want) {}

    @Override
    public SSLSession getSession() {
      return session;
    }

    private static SSLEngineResult result() {
      return new SSLEngineResult(
          SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    }

    private static SSLSession session() {
      byte[] id = {1};
      return (SSLSession)
          Proxy.newProxyInstance(
              SSLSession.class.getClassLoader(),
              new Class<?>[] {SSLSession.class},
              (proxy, method, args) -> {
                if ("getId".equals(method.getName())) {
                  return id.clone();
                }
                throw new UnsupportedOperationException(method.getName());
              });
    }
  }
}
