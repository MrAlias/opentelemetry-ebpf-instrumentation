/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.bridge.RemoteParentBridge;
import io.opentelemetry.obi.java.bridge.RemoteParentStatus;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemoryTestAccess;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.ebpf.ProxyInputStream;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.SSLSocketStreamInst;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.ReceiveContext;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class BootstrapNativeSocketTelemetryTest {
  @AfterEach
  void cleanup() {
    BootstrapNative.setEmitTelemetryReceiveForTest(null);
    BootstrapNative.setSocketFileDescriptorForTest(null);
    BootstrapNative.setDirectSocketFileDescriptorForTest(null);
    BootstrapNative.setEmitDataOnSocketForTest(null);
    NativeMemoryTestAccess.setSyntheticAddress(false);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    ThreadInfo.clearRemoteParentLookupSource();
    ThreadInfo.takeRemoteParentReceiveContext();
    ThreadInfo.setRemoteParentEnabled(false);
  }

  @Test
  void directSocketTelemetryFragmentsAtTheAbiCeilingWithoutAuthorityOrByteLoss() throws Exception {
    byte[] source = new byte[IOCTLPacket.http1MaxPayloadSize + 47];
    for (int index = 0; index < source.length; index++) {
      source[index] = (byte) (index * 31);
    }
    int offset = 5;
    int length = IOCTLPacket.http1MaxPayloadSize + 37;
    List<byte[]> fragments = new ArrayList<>();
    AtomicInteger emissions = new AtomicInteger();
    NativeMemoryTestAccess.setSyntheticAddress(true);
    BootstrapNative.setDirectSocketFileDescriptorForTest(socket -> 73);
    BootstrapNative.setEmitTelemetryReceiveForTest(
        (socketFileDescriptor, packet) -> {
          assertEquals(73, socketFileDescriptor.intValue());
          ByteBuffer bytes = packet.getBuffer().duplicate().order(ByteOrder.nativeOrder());
          assertEquals(OperationType.TELEMETRY_RECEIVE.code, bytes.get(0));
          int fragmentLength = bytes.getInt(IOCTLPacket.bufferLengthOffset);
          assertEquals(0L, bytes.getLong(IOCTLPacket.dataSignalOffset));
          byte[] fragment = new byte[fragmentLength];
          for (int index = 0; index < fragmentLength; index++) {
            fragment[index] = bytes.get(IOCTLPacket.packetPrefixSize + index);
          }
          fragments.add(fragment);
          if (emissions.getAndIncrement() == 0) {
            // A provider replacement while this callback is in flight cannot change its op17-only
            // wire contract or restore the direct authority present before the callback.
            ThreadInfo.setRemoteParentEnabled(false);
            ThreadInfo.advanceRemoteParentBridgeEpoch();
            ThreadInfo.setRemoteParentEnabled(true);
          }
          return 1;
        });

    try (Socket socket = new Socket()) {
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(lifecycle);
      ThreadInfo.setRemoteParentEnabled(true);
      ThreadInfo.markRemoteParentDirectLookup(lifecycle);
      ThreadInfo.setRemoteParentSocketFileDescriptor(73, lifecycle);
      long unsupportedBefore = diagnosticCounter("d_unsupported");

      assertEquals(
          1, BootstrapNative.emitTelemetryReceiveData(socket, lifecycle, source, offset, length));

      assertEquals(2, fragments.size());
      assertEquals(IOCTLPacket.http1MaxPayloadSize, fragments.get(0).length);
      assertEquals(37, fragments.get(1).length);
      ByteArrayOutputStream joined = new ByteArrayOutputStream(length);
      for (byte[] fragment : fragments) {
        joined.write(fragment, 0, fragment.length);
      }
      byte[] expected = new byte[length];
      System.arraycopy(source, offset, expected, 0, length);
      assertArrayEquals(expected, joined.toByteArray());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
      TaskContext handoff = ThreadInfo.captureTaskContext(101L, lifecycle);
      assertEquals(0L, handoff.getHandoffToken());
      assertEquals(unsupportedBefore + 1, diagnosticCounter("d_unsupported"));

      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, lifecycle);
    }
  }

  @Test
  void disabledDirectSocketReceiveStillEmitsTelemetryWithoutUnsupportedAccounting()
      throws Exception {
    AtomicInteger emissions = new AtomicInteger();
    NativeMemoryTestAccess.setSyntheticAddress(true);
    BootstrapNative.setDirectSocketFileDescriptorForTest(socket -> 74);
    BootstrapNative.setEmitTelemetryReceiveForTest(
        (socketFileDescriptor, packet) -> {
          assertEquals(OperationType.TELEMETRY_RECEIVE.code, packet.getBuffer().get(0));
          emissions.incrementAndGet();
          return 0;
        });

    try (Socket socket = new Socket()) {
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(lifecycle);
      ThreadInfo.setRemoteParentEnabled(false);
      long unsupportedBefore = diagnosticCounter("d_unsupported");

      assertEquals(
          0,
          BootstrapNative.emitTelemetryReceiveData(socket, lifecycle, new byte[] {1, 2, 3}, 0, 3));

      assertEquals(1, emissions.get());
      assertEquals(unsupportedBefore, diagnosticCounter("d_unsupported"));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());

      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, lifecycle);
    }
  }

  @Test
  void layeredProxyTelemetryNeverResolvesOrEmitsThroughTheRawDescriptor() throws Exception {
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger directChecks = new AtomicInteger();
    AtomicInteger unsafeResolutions = new AtomicInteger();
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setDirectSocketFileDescriptorForTest(
        socket -> {
          directChecks.incrementAndGet();
          return -1;
        });
    BootstrapNative.setSocketFileDescriptorForTest(
        socket -> {
          unsafeResolutions.incrementAndGet();
          return 74;
        });
    BootstrapNative.setEmitTelemetryReceiveForTest(
        (socketFileDescriptor, packet) -> {
          emissions.incrementAndGet();
          return 0;
        });

    try (Socket socket = new Socket()) {
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(lifecycle);
      long unsupportedBefore = diagnosticCounter("d_unsupported");

      assertEquals(
          -1,
          BootstrapNative.emitTelemetryReceiveData(socket, lifecycle, new byte[] {1, 2, 3}, 0, 3));
      assertEquals(
          -1,
          BootstrapNative.emitTelemetryReceiveData(socket, lifecycle, new byte[] {4, 5, 6}, 0, 3));

      assertEquals(2, directChecks.get());
      assertEquals(0, unsafeResolutions.get());
      assertEquals(0, emissions.get());
      assertSame(lifecycle, SSLStorage.currentRemoteParentSocketLifecycle(socket));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
      assertEquals(unsupportedBefore + 1, diagnosticCounter("d_unsupported"));
      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, lifecycle);
    }
  }

  @Test
  void directSocketReadPublishesAuthorityBeforeTheParserAndSeparatesKeepaliveRequests()
      throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    BootstrapNative.setDirectSocketFileDescriptorForTest(socket -> 75);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          assertEquals(75, socketFileDescriptor);
          emissions.incrementAndGet();
          return 1;
        });

    try (Socket socket = new Socket()) {
      byte[] first = request("/one");
      Object firstRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.remoteParentSocketReadLifecycle(firstRead);
      assertNotNull(lifecycle);

      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, firstRead, first, 0, first.length, null);

      ReceiveContext firstContext = ThreadInfo.takeRemoteParentReceiveContext();
      assertNotNull(firstContext);
      assertEquals(1L, firstContext.requestSequence());
      assertEquals(75, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(1, emissions.get());
      ThreadInfo.finishRemoteParentExtraction(firstContext);

      byte[] second = request("/two");
      Object secondRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      assertSame(lifecycle, BootstrapNative.remoteParentSocketReadLifecycle(secondRead));
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, secondRead, second, 0, second.length, null);

      ReceiveContext secondContext = ThreadInfo.takeRemoteParentReceiveContext();
      assertNotNull(secondContext);
      assertEquals(2L, secondContext.requestSequence());
      assertEquals(firstContext.lifecycle().id(), secondContext.lifecycle().id());
      assertEquals(2, emissions.get());
      ThreadInfo.finishRemoteParentExtraction(secondContext);
      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, lifecycle);
    }
  }

  @Test
  void layeredSocketReadSkipsUnfencedTelemetryAndBoundsUnsupportedDiagnostics() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger directChecks = new AtomicInteger();
    AtomicInteger unsafeResolutions = new AtomicInteger();
    BootstrapNative.setDirectSocketFileDescriptorForTest(
        socket -> {
          directChecks.incrementAndGet();
          return -1;
        });
    BootstrapNative.setSocketFileDescriptorForTest(
        socket -> {
          unsafeResolutions.incrementAndGet();
          return 76;
        });
    AtomicInteger telemetry = new AtomicInteger();
    BootstrapNative.setEmitTelemetryReceiveForTest(
        (socketFileDescriptor, packet) -> {
          telemetry.incrementAndGet();
          return 0;
        });

    try (Socket socket = new Socket()) {
      long unsupportedBefore = diagnosticCounter("d_unsupported");
      byte[] request = request("/layered");
      Object firstRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.remoteParentSocketReadLifecycle(firstRead);

      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, firstRead, request, 0, request.length, null);
      Object secondRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, secondRead, request, 0, request.length, null);

      assertEquals(2, directChecks.get());
      assertEquals(0, unsafeResolutions.get());
      assertEquals(0, telemetry.get());
      assertSame(lifecycle, SSLStorage.currentRemoteParentSocketLifecycle(socket));
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
      assertEquals(unsupportedBefore + 1, diagnosticCounter("d_unsupported"));
      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, lifecycle);
    }
  }

  @Test
  void terminalReadFailurePoisonsTheSocketBeforeRequestLookingBodyBytes() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    BootstrapNative.setDirectSocketFileDescriptorForTest(socket -> 81);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    Socket socket = new Socket();
    Lifecycle lifecycle = null;
    try {
      byte[] requestLookingBody = request("/body-is-not-a-request");
      byte[] headers = postHeaders("/upload", requestLookingBody.length);
      Object headerRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      lifecycle = (Lifecycle) BootstrapNative.remoteParentSocketReadLifecycle(headerRead);
      assertNotNull(lifecycle);

      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, headerRead, headers, 0, headers.length, null);
      ReceiveContext context = ThreadInfo.takeRemoteParentReceiveContext();
      assertNotNull(context);
      ThreadInfo.finishRemoteParentExtraction(context);
      assertEquals(1, emissions.get());

      Object failedRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      SocketTimeoutException timeout = new SocketTimeoutException("recoverable timeout");
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, failedRead, new byte[1], 0, 0, timeout);

      int emissionsAfterPoison = emissions.get();
      assertEquals(2, emissionsAfterPoison); // START plus the terminal RESET.
      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(socket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(socket));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());

      Object bodyRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      assertNull(BootstrapNative.remoteParentSocketReadLifecycle(bodyRead));
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, bodyRead, requestLookingBody, 0, requestLookingBody.length, null);

      assertEquals(emissionsAfterPoison, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    } finally {
      Object closeLifecycle = BootstrapNative.beginRemoteParentSocketClose(socket);
      assertNotNull(closeLifecycle);
      if (lifecycle != null) {
        assertTrue(closeLifecycle != lifecycle);
      }
      socket.close();
      BootstrapNative.finishRemoteParentSocketClose(socket, closeLifecycle);
    }

    try (Socket freshSocket = new Socket()) {
      Object fresh = SSLStorage.prepareRemoteParentSocketLifecycle(freshSocket);
      assertNotNull(fresh);
      SSLStorage.invalidateRemoteParentSocketLifecycle(freshSocket, fresh);
    }
  }

  @Test
  void nativeStartFailurePoisonsTheSocketBeforeASecondRequestLikeFragment() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    BootstrapNative.setDirectSocketFileDescriptorForTest(socket -> 82);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> emissions.incrementAndGet() == 1 ? -1 : 1);

    Socket socket = new Socket();
    try {
      byte[] headers = postHeaders("/native-failure", request("/forged").length);
      Object firstRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.remoteParentSocketReadLifecycle(firstRead);
      assertNotNull(lifecycle);

      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, firstRead, headers, 0, headers.length, null);

      assertEquals(1, emissions.get());
      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(socket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(socket));
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());

      byte[] forged = request("/forged");
      Object forgedRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      assertNull(BootstrapNative.remoteParentSocketReadLifecycle(forgedRead));
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, forgedRead, forged, 0, forged.length, null);

      assertEquals(1, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
    } finally {
      Object closeLifecycle = BootstrapNative.beginRemoteParentSocketClose(socket);
      socket.close();
      BootstrapNative.finishRemoteParentSocketClose(socket, closeLifecycle);
    }
  }

  @Test
  void delayedTerminalCallbackCannotPoisonANewerExactOwner() throws Exception {
    try (Socket socket = new Socket()) {
      Lifecycle old = (Lifecycle) SSLStorage.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(old);
      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, old);
      Lifecycle fresh = (Lifecycle) SSLStorage.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(fresh);

      BootstrapNative.invalidateRemoteParentSocketFileDescriptor(socket, old);

      assertSame(fresh, SSLStorage.currentRemoteParentSocketLifecycle(socket));
      assertTrue(fresh.active());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, fresh);
    }
  }

  @Test
  void stockArrayDelegationEmitsOnlyAfterTheOutermostReadReturns() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    BootstrapNative.setDirectSocketFileDescriptorForTest(socket -> 77);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    try (Socket directSocket = new Socket()) {
      byte[] request = request("/nested");
      Object outerRead = SSLSocketStreamInst.InputStreamReadAdvice.enter(directSocket);
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.remoteParentSocketReadLifecycle(outerRead);
      Object innerRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(directSocket);
      assertSame(lifecycle, BootstrapNative.remoteParentSocketReadLifecycle(innerRead));

      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          directSocket, innerRead, request, 0, request.length, null);

      assertEquals(0, emissions.get());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());

      SSLSocketStreamInst.InputStreamReadAdvice.read(
          directSocket, outerRead, request, request.length, null);

      assertEquals(1, emissions.get());
      ReceiveContext context = ThreadInfo.takeRemoteParentReceiveContext();
      assertNotNull(context);
      assertEquals(77, ThreadInfo.remoteParentSocketFileDescriptor());
      ThreadInfo.finishRemoteParentExtraction(context);
      SSLStorage.invalidateRemoteParentSocketLifecycle(directSocket, lifecycle);
    }
  }

  @Test
  void repeatedSameOwnerInnerReadsRemainDeferredUntilTheOuterResult() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    BootstrapNative.setDirectSocketFileDescriptorForTest(socket -> 87);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    try (Socket directSocket = new Socket()) {
      byte[] visibleRequest = request("/repeated");
      Object outerRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(directSocket);
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.remoteParentSocketReadLifecycle(outerRead);
      for (int inner = 0; inner < 2; inner++) {
        Object innerRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(directSocket);
        assertSame(lifecycle, BootstrapNative.remoteParentSocketReadLifecycle(innerRead));
        byte[] readAhead = {(byte) ('a' + inner)};
        SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
            directSocket, innerRead, readAhead, 0, readAhead.length, null);
      }

      assertEquals(0, emissions.get());
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          directSocket, outerRead, visibleRequest, 0, visibleRequest.length, null);

      assertEquals(1, emissions.get());
      ReceiveContext context = ThreadInfo.takeRemoteParentReceiveContext();
      assertNotNull(context);
      assertEquals(87, ThreadInfo.remoteParentSocketFileDescriptor());
      ThreadInfo.finishRemoteParentExtraction(context);
      SSLStorage.invalidateRemoteParentSocketLifecycle(directSocket, lifecycle);
    }
  }

  @Test
  void sameLengthTransformUsesOnlyTheApplicationVisibleBytes() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    try (Socket directSocket = new Socket()) {
      BootstrapNative.setDirectSocketFileDescriptorForTest(
          socket -> socket == directSocket ? 78 : -1);
      byte[] innerRequest = request("/inner");
      byte[] transformed = new byte[innerRequest.length];
      Arrays.fill(transformed, (byte) 'X');
      InputStream delegate =
          transformingNestedDefaultStream(directSocket, innerRequest, transformed);
      ProxyInputStream proxy = new ProxyInputStream(delegate, directSocket);
      byte[] destination = new byte[transformed.length];

      assertEquals(transformed.length, proxy.read(destination));

      assertArrayEquals(transformed, destination);
      assertEquals(0, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      Object lifecycle = SSLStorage.currentRemoteParentSocketLifecycle(directSocket);
      assertNotNull(lifecycle);
      SSLStorage.invalidateRemoteParentSocketLifecycle(directSocket, lifecycle);
    }
  }

  @Test
  void sameLengthTransformCanPublishOnlyTheVisibleRequest() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    try (Socket directSocket = new Socket()) {
      BootstrapNative.setDirectSocketFileDescriptorForTest(
          socket -> socket == directSocket ? 86 : -1);
      byte[] visibleRequest = request("/outer");
      byte[] innerPlaintext = new byte[visibleRequest.length];
      Arrays.fill(innerPlaintext, (byte) 'X');
      ProxyInputStream proxy =
          new ProxyInputStream(
              transformingNestedDefaultStream(directSocket, innerPlaintext, visibleRequest),
              directSocket);
      byte[] destination = new byte[visibleRequest.length];

      assertEquals(visibleRequest.length, proxy.read(destination));

      assertArrayEquals(visibleRequest, destination);
      assertEquals(1, emissions.get());
      ReceiveContext context = ThreadInfo.takeRemoteParentReceiveContext();
      assertNotNull(context);
      assertEquals(86, ThreadInfo.remoteParentSocketFileDescriptor());
      ThreadInfo.finishRemoteParentExtraction(context);
      SSLStorage.invalidateRemoteParentSocketLifecycle(directSocket, context.lifecycle());
    }
  }

  @Test
  void bufferedReadAheadPublishesOnlyAfterTheVisibleRequestCompletes() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    try (Socket directSocket = new Socket()) {
      BootstrapNative.setDirectSocketFileDescriptorForTest(
          socket -> socket == directSocket ? 79 : -1);
      byte[] request = request("/buffered");
      int split = request.length / 2;
      ProxyInputStream proxy =
          new ProxyInputStream(
              bufferedNestedDefaultStream(directSocket, request, split), directSocket);
      byte[] destination = new byte[request.length];

      assertEquals(split, proxy.read(destination, 0, destination.length));
      assertEquals(0, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());

      assertEquals(
          request.length - split, proxy.read(destination, split, destination.length - split));

      assertArrayEquals(request, destination);
      assertEquals(1, emissions.get());
      ReceiveContext context = ThreadInfo.takeRemoteParentReceiveContext();
      assertNotNull(context);
      assertEquals(79, ThreadInfo.remoteParentSocketFileDescriptor());
      ThreadInfo.finishRemoteParentExtraction(context);
      SSLStorage.invalidateRemoteParentSocketLifecycle(directSocket, context.lifecycle());
    }
  }

  @Test
  void unrelatedNestedSocketCannotPublishForTheOuterProxy() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    try (Socket outerSocket = new Socket();
        Socket directSocket = new Socket()) {
      BootstrapNative.setDirectSocketFileDescriptorForTest(
          socket -> socket == directSocket ? 80 : socket == outerSocket ? 83 : -1);
      byte[] request = request("/unrelated");
      ProxyInputStream proxy =
          new ProxyInputStream(nestedDefaultStream(directSocket, request, null), outerSocket);
      byte[] destination = new byte[request.length];

      assertEquals(request.length, proxy.read(destination));

      assertArrayEquals(request, destination);
      assertEquals(0, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(directSocket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(directSocket));
      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(outerSocket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(outerSocket));
      closeTrackedSocket(directSocket);
      closeTrackedSocket(outerSocket);
    }
  }

  @Test
  void multipleNestedSocketOwnersAreAllFailedClosed() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    try (Socket outerSocket = new Socket();
        Socket firstSocket = new Socket();
        Socket secondSocket = new Socket()) {
      BootstrapNative.setDirectSocketFileDescriptorForTest(
          socket ->
              socket == firstSocket
                  ? 81
                  : socket == secondSocket ? 82 : socket == outerSocket ? 84 : -1);
      byte[] request = request("/ambiguous");
      Object outerRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(outerSocket);
      Object firstRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(firstSocket);
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          firstSocket, firstRead, request, 0, request.length, null);
      Object secondRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(secondSocket);
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          secondSocket, secondRead, request, 0, request.length, null);

      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          outerSocket, outerRead, request, 0, request.length, null);

      assertEquals(0, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(firstSocket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(firstSocket));
      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(secondSocket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(secondSocket));
      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(outerSocket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(outerSocket));
      closeTrackedSocket(firstSocket);
      closeTrackedSocket(secondSocket);
      closeTrackedSocket(outerSocket);
    }
  }

  @Test
  void unownedNestedSocketBlocksAnOtherwiseDirectOuterOwner() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    try (Socket outerSocket = new Socket();
        Socket unownedSocket =
            new Socket() {
              @Override
              public boolean isClosed() {
                return true;
              }
            }) {
      BootstrapNative.setDirectSocketFileDescriptorForTest(
          socket -> socket == outerSocket ? 85 : -1);
      byte[] request = request("/unowned");
      Object outerRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(outerSocket);
      Object innerRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(unownedSocket);
      assertNull(BootstrapNative.remoteParentSocketReadLifecycle(innerRead));
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          unownedSocket, innerRead, request, 0, request.length, null);

      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          outerSocket, outerRead, request, 0, request.length, null);

      assertEquals(0, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(outerSocket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(outerSocket));
      closeTrackedSocket(outerSocket);
    }
  }

  @Test
  void nestedZeroEofAndExceptionBlockSynthesizedOuterBytes() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    BootstrapNative.setDirectSocketFileDescriptorForTest(socket -> 88);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    assertNestedTerminalBlocksOuter(0, null);
    assertNestedTerminalBlocksOuter(-1, null);
    assertNestedTerminalBlocksOuter(0, new IOException("nested failure"));

    assertEquals(0, emissions.get());
  }

  @Test
  void failedOuterProxyReadRevokesAuthorityFromItsSuccessfulNestedRead() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    BootstrapNative.setDirectSocketFileDescriptorForTest(socket -> 78);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> emissions.incrementAndGet() == 1 ? 1 : 0);
    IOException expected = new IOException("outer failure");

    try (Socket outerSocket = new Socket();
        Socket directSocket = new Socket()) {
      InputStream nestedDefaultStream =
          nestedDefaultStream(directSocket, request("/failed"), expected);
      ProxyInputStream proxy = new ProxyInputStream(nestedDefaultStream, outerSocket);

      assertSame(expected, assertThrows(IOException.class, () -> proxy.read(new byte[128])));

      assertEquals(0, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(directSocket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(directSocket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(outerSocket));
      closeTrackedSocket(directSocket);
      closeTrackedSocket(outerSocket);
    }
  }

  @Test
  void zeroAndTerminalDirectReadsNeverEmitOrLeaveAReusableGeneration() throws Exception {
    ThreadInfo.setRemoteParentEnabled(true);
    AtomicInteger descriptorResolutions = new AtomicInteger();
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setDirectSocketFileDescriptorForTest(
        socket -> {
          descriptorResolutions.incrementAndGet();
          return 79;
        });
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 1;
        });

    try (Socket socket = new Socket()) {
      Object zeroRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.remoteParentSocketReadLifecycle(zeroRead);
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, zeroRead, new byte[1], 0, 0, null);

      assertSame(lifecycle, SSLStorage.currentRemoteParentSocketLifecycle(socket));
      assertEquals(0, descriptorResolutions.get());
      assertEquals(0, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());

      Object eofRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, eofRead, new byte[1], 0, -1, null);

      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(socket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(socket));
      assertEquals(0, descriptorResolutions.get());
      assertEquals(0, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
      closeTrackedSocket(socket);
    }
  }

  @Test
  void providerChangeBeforeDirectReadExitFallsBackWithoutPublishingAuthority() throws Exception {
    NativeMemoryTestAccess.setSyntheticAddress(true);
    ThreadInfo.setRemoteParentEnabled(true);
    BootstrapNative.setDirectSocketFileDescriptorForTest(socket -> 80);
    AtomicInteger emissions = new AtomicInteger();
    BootstrapNative.setEmitDataOnSocketForTest(
        (socketFileDescriptor, packetAddress) -> {
          emissions.incrementAndGet();
          return 0;
        });

    try (Socket socket = new Socket()) {
      long staleBefore = diagnosticCounter("d_stale");
      Object readState = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(socket);
      Lifecycle lifecycle = (Lifecycle) BootstrapNative.remoteParentSocketReadLifecycle(readState);
      ThreadInfo.advanceRemoteParentBridgeEpoch();
      byte[] request = request("/provider-change");

      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          socket, readState, request, 0, request.length, null);

      assertEquals(1, emissions.get());
      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
      assertEquals(staleBefore + 1, diagnosticCounter("d_stale"));
      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, lifecycle);
    }
  }

  @Test
  void diagnosticCounterDecodesTheSnapshotRadixBeyondDecimalDigits() {
    long unsupportedBefore = diagnosticCounter("d_unsupported");

    for (int increment = 0; increment < 12; increment++) {
      RemoteParentBridge.recordReceiveFailure(RemoteParentStatus.UNSUPPORTED);
    }

    long unsupportedAfter = diagnosticCounter("d_unsupported");
    assertEquals(unsupportedBefore + 12, unsupportedAfter);
    assertTrue(unsupportedAfter >= 10);
  }

  private static long diagnosticCounter(String name) {
    for (String field : RemoteParentBridge.diagnosticsSnapshot().split(",")) {
      int separator = field.indexOf('=');
      if (separator > 0 && name.equals(field.substring(0, separator))) {
        return Long.parseLong(field.substring(separator + 1), Character.MAX_RADIX);
      }
    }
    throw new AssertionError("missing diagnostics counter " + name);
  }

  private static byte[] request(String path) {
    return ("GET " + path + " HTTP/1.1\r\nHost: example\r\n\r\n")
        .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
  }

  private static byte[] postHeaders(String path, int contentLength) {
    return ("POST "
            + path
            + " HTTP/1.1\r\nHost: example\r\nContent-Length: "
            + contentLength
            + "\r\n\r\n")
        .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
  }

  private static void closeTrackedSocket(Socket socket) throws IOException {
    Object closeLifecycle = BootstrapNative.beginRemoteParentSocketClose(socket);
    try {
      socket.close();
    } finally {
      BootstrapNative.finishRemoteParentSocketClose(socket, closeLifecycle);
    }
  }

  private static InputStream nestedDefaultStream(
      Socket directSocket, byte[] plaintext, IOException failureAfterRead) {
    return new InputStream() {
      @Override
      public int read() {
        return -1;
      }

      @Override
      public int read(byte[] destination, int offset, int length) throws IOException {
        int count = Math.min(length, plaintext.length);
        System.arraycopy(plaintext, 0, destination, offset, count);
        Object readState = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(directSocket);
        SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
            directSocket, readState, destination, offset, count, null);
        if (failureAfterRead != null) {
          throw failureAfterRead;
        }
        return count;
      }
    };
  }

  private static void assertNestedTerminalBlocksOuter(int bytesRead, Throwable failure)
      throws Exception {
    Socket directSocket = new Socket();
    try {
      byte[] visibleRequest = request("/synthesized");
      Object outerRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(directSocket);
      Object innerRead = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(directSocket);
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          directSocket, innerRead, new byte[1], 0, bytesRead, failure);
      SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
          directSocket, outerRead, visibleRequest, 0, visibleRequest.length, null);

      assertNull(ThreadInfo.takeRemoteParentReceiveContext());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertNull(SSLStorage.currentRemoteParentSocketLifecycle(directSocket));
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(directSocket));
      closeTrackedSocket(directSocket);
    } finally {
      if (!directSocket.isClosed()) {
        directSocket.close();
      }
    }
  }

  private static InputStream transformingNestedDefaultStream(
      Socket directSocket, byte[] innerPlaintext, byte[] applicationPlaintext) {
    return new InputStream() {
      @Override
      public int read() {
        return -1;
      }

      @Override
      public int read(byte[] destination, int offset, int length) {
        byte[] innerBuffer = innerPlaintext.clone();
        Object readState = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(directSocket);
        SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
            directSocket, readState, innerBuffer, 0, innerBuffer.length, null);
        int count = Math.min(length, applicationPlaintext.length);
        System.arraycopy(applicationPlaintext, 0, destination, offset, count);
        return count;
      }
    };
  }

  private static InputStream bufferedNestedDefaultStream(
      Socket directSocket, byte[] plaintext, int split) {
    return new InputStream() {
      private boolean readAhead;
      private int applicationOffset;

      @Override
      public int read() {
        return -1;
      }

      @Override
      public int read(byte[] destination, int offset, int length) {
        if (!readAhead) {
          readAhead = true;
          byte[] innerBuffer = plaintext.clone();
          Object readState = SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(directSocket);
          SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
              directSocket, readState, innerBuffer, 0, innerBuffer.length, null);
        }
        if (applicationOffset >= plaintext.length) {
          return -1;
        }
        int requested = applicationOffset == 0 ? split : plaintext.length - applicationOffset;
        int count = Math.min(length, requested);
        System.arraycopy(plaintext, applicationOffset, destination, offset, count);
        applicationOffset += count;
        return count;
      }
    };
  }
}
