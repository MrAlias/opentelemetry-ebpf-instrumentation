/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.bridge.RemoteParentBridge;
import io.opentelemetry.obi.java.bridge.RemoteParentStatus;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemoryTestAccess;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class BootstrapNativeSocketTelemetryTest {
  @AfterEach
  void cleanup() {
    BootstrapNative.setEmitTelemetryReceiveForTest(null);
    BootstrapNative.setSocketFileDescriptorForTest(null);
    NativeMemoryTestAccess.setSyntheticAddress(false);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    ThreadInfo.clearRemoteParentLookupSource();
    ThreadInfo.setRemoteParentEnabled(false);
  }

  @Test
  void socketTelemetryFragmentsAtTheAbiCeilingWithoutAuthorityOrByteLoss() throws Exception {
    byte[] source = new byte[IOCTLPacket.http1MaxPayloadSize + 47];
    for (int index = 0; index < source.length; index++) {
      source[index] = (byte) (index * 31);
    }
    int offset = 5;
    int length = IOCTLPacket.http1MaxPayloadSize + 37;
    List<byte[]> fragments = new ArrayList<>();
    AtomicInteger emissions = new AtomicInteger();
    NativeMemoryTestAccess.setSyntheticAddress(true);
    BootstrapNative.setSocketFileDescriptorForTest(socket -> 73);
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
  void disabledSocketReceiveStillEmitsTelemetryWithoutUnsupportedAccounting() throws Exception {
    AtomicInteger emissions = new AtomicInteger();
    NativeMemoryTestAccess.setSyntheticAddress(true);
    BootstrapNative.setSocketFileDescriptorForTest(socket -> 74);
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
}
