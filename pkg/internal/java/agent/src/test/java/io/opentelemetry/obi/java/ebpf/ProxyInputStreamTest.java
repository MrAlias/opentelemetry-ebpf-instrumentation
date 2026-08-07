/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ProxyInputStreamTest {
  @AfterEach
  void clearRemoteParentSocketFileDescriptor() {
    ThreadInfo.setRemoteParentEnabled(false);
    ThreadInfo.setTaskContextEmitterForTest(null);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    ThreadInfo.clearRemoteParentLookupSource();
  }

  @Test
  void readPacketUsesBytesReadForPartialBuffer() {
    byte[] buffer = {10, 20, 30, 40, 50};
    int bytesRead = 3;
    NativeMemory packet = new NativeMemory(IOCTLPacket.packetPrefixSize + bytesRead + 1, true);

    int end = ProxyInputStream.writeReadPacket(packet, null, buffer, 0, bytesRead);

    assertEquals(IOCTLPacket.packetPrefixSize + bytesRead, end);
    assertEquals(OperationType.TELEMETRY_RECEIVE.code, packet.getBuffer().get(0));
    assertEquals(bytesRead, packet.getInt(IOCTLPacket.bufferLengthOffset));
    assertEquals(0L, packet.getLong(IOCTLPacket.dataSignalOffset));
    for (int i = 0; i < bytesRead; i++) {
      assertEquals(buffer[i], packet.getBuffer().get(IOCTLPacket.packetPrefixSize + i));
    }
    assertEquals(0, packet.getBuffer().get(IOCTLPacket.packetPrefixSize + bytesRead));
  }

  @Test
  void readByteArrayForwardsActualReadLength() throws Exception {
    CapturingProxyInputStream stream =
        new CapturingProxyInputStream(new ByteArrayInputStream(new byte[] {1, 2}));
    byte[] buffer = new byte[8];

    int bytesRead = stream.read(buffer);

    assertEquals(2, bytesRead);
    assertEquals(0, stream.forwardedOffset);
    assertEquals(2, stream.forwardedLength);
    assertArrayEquals(new byte[] {1, 2}, stream.forwardedBytes);
  }

  @Test
  void readByteArrayWithOffsetForwardsOffsetAndBytesRead() throws Exception {
    CapturingProxyInputStream stream =
        new CapturingProxyInputStream(new ByteArrayInputStream(new byte[] {3, 4}));
    byte[] buffer = new byte[8];

    int bytesRead = stream.read(buffer, 3, 4);

    assertEquals(2, bytesRead);
    assertEquals(3, stream.forwardedOffset);
    assertEquals(2, stream.forwardedLength);
    assertArrayEquals(new byte[] {3, 4}, stream.forwardedBytes);
  }

  @Test
  void readSingleByteForwardsExactlyOneByte() throws Exception {
    CapturingProxyInputStream stream =
        new CapturingProxyInputStream(new ByteArrayInputStream(new byte[] {(byte) 0xA5}));

    int value = stream.read();

    assertEquals(0xA5, value);
    assertEquals(0, stream.forwardedOffset);
    assertEquals(1, stream.forwardedLength);
    assertArrayEquals(new byte[] {(byte) 0xA5}, stream.forwardedBytes);
  }

  @Test
  void terminalOrFailedReadsClearStagedRemoteParentSocket() throws Exception {
    ThreadInfo.setRemoteParentSocketFileDescriptor(41);
    CapturingProxyInputStream eof =
        new CapturingProxyInputStream(new ByteArrayInputStream(new byte[0]));

    assertEquals(-1, eof.read());
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());

    ThreadInfo.setRemoteParentSocketFileDescriptor(42);
    assertEquals(-1, eof.read(new byte[1]));
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());

    ThreadInfo.setRemoteParentSocketFileDescriptor(43);
    assertEquals(-1, eof.read(new byte[1], 0, 1));
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());

    ThreadInfo.setRemoteParentSocketFileDescriptor(44);
    CapturingProxyInputStream failing =
        new CapturingProxyInputStream(
            new InputStream() {
              @Override
              public int read() throws IOException {
                throw new IOException("expected read failure");
              }

              @Override
              public int read(byte[] buffer, int offset, int length) throws IOException {
                throw new IOException("expected read failure");
              }
            });

    assertThrows(IOException.class, () -> failing.read(new byte[1], 0, 1));
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());

    ThreadInfo.setRemoteParentSocketFileDescriptor(45);
    assertThrows(IOException.class, failing::read);
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void zeroLengthReadsDoNotForwardOrClearStagedRemoteParentSocket() throws Exception {
    ThreadInfo.setRemoteParentSocketFileDescriptor(46);
    CapturingProxyInputStream zeroRead =
        new CapturingProxyInputStream(
            new InputStream() {
              @Override
              public int read(byte[] buffer) {
                return 0;
              }

              @Override
              public int read() {
                return 0;
              }
            });

    assertEquals(0, zeroRead.read(new byte[1]));
    assertEquals(46, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, zeroRead.forwardedLength);

    assertEquals(0, zeroRead.read(new byte[1], 0, 0));
    assertEquals(46, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, zeroRead.forwardedLength);
  }

  @Test
  void closeClearsStagedRemoteParentSocketEvenWhenDelegateCloseFails() throws Exception {
    ThreadInfo.setRemoteParentSocketFileDescriptor(47);
    CapturingProxyInputStream successfulClose =
        new CapturingProxyInputStream(new ByteArrayInputStream(new byte[0]));

    successfulClose.close();
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());

    ThreadInfo.setRemoteParentSocketFileDescriptor(48);
    CapturingProxyInputStream failingClose =
        new CapturingProxyInputStream(
            new InputStream() {
              @Override
              public int read() {
                return -1;
              }

              @Override
              public void close() throws IOException {
                throw new IOException("expected close failure");
              }
            });

    assertThrows(IOException.class, failingClose::close);
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void forwardingFailureFailsOpenAndInvalidatesTheStagedRemoteParentSocket() throws Exception {
    ThreadInfo.setRemoteParentSocketFileDescriptor(49);
    ProxyInputStream failingForward =
        new ProxyInputStream(new ByteArrayInputStream(new byte[] {1}), null) {
          @Override
          void forwardRead(byte[] b, int off, int len, Object lifecycle) {
            throw new IllegalStateException("expected forwarding failure");
          }
        };

    assertEquals(1, failingForward.read());
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void lifecyclePreparationFailurePreservesEveryReadOverload() throws Exception {
    Socket failingSocket = socketWithFailingLifecyclePreparation();

    ProxyInputStream single =
        new ProxyInputStream(new ByteArrayInputStream(new byte[] {(byte) 0xA5}), failingSocket);
    assertEquals(0xA5, single.read());

    ProxyInputStream array =
        new ProxyInputStream(new ByteArrayInputStream(new byte[] {1, 2}), failingSocket);
    byte[] arrayBuffer = new byte[4];
    assertEquals(2, array.read(arrayBuffer));
    assertArrayEquals(new byte[] {1, 2, 0, 0}, arrayBuffer);

    ProxyInputStream ranged =
        new ProxyInputStream(new ByteArrayInputStream(new byte[] {3, 4}), failingSocket);
    byte[] rangedBuffer = new byte[6];
    assertEquals(2, ranged.read(rangedBuffer, 2, 3));
    assertArrayEquals(new byte[] {0, 0, 3, 4, 0, 0}, rangedBuffer);
  }

  @Test
  void lifecyclePreparationFailureDoesNotReplaceDelegateExceptions() {
    IOException expected = new IOException("expected delegate failure");
    InputStream failingDelegate =
        new InputStream() {
          @Override
          public int read() throws IOException {
            throw expected;
          }

          @Override
          public int read(byte[] buffer) throws IOException {
            throw expected;
          }

          @Override
          public int read(byte[] buffer, int offset, int length) throws IOException {
            throw expected;
          }
        };
    Socket failingSocket = socketWithFailingLifecyclePreparation();

    assertSame(
        expected,
        assertThrows(
            IOException.class, () -> new ProxyInputStream(failingDelegate, failingSocket).read()));
    assertSame(
        expected,
        assertThrows(
            IOException.class,
            () -> new ProxyInputStream(failingDelegate, failingSocket).read(new byte[1])));
    assertSame(
        expected,
        assertThrows(
            IOException.class,
            () -> new ProxyInputStream(failingDelegate, failingSocket).read(new byte[1], 0, 1)));
  }

  @Test
  void terminalSocketLifecycleIsRemovedSoARecoverableReadCanUseAFreshGeneration() throws Exception {
    try (Socket socket = new Socket()) {
      Object first = SSLStorage.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(first);

      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, first);

      Object retried = SSLStorage.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(retried);
      assertNotSame(first, retried);
      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, retried);
    }
  }

  @Test
  void delayedNullSocketSnapshotDoesNotRevokeAFreshLifecycle() throws Exception {
    try (Socket socket = new Socket()) {
      Object absentAtReadEntry = SSLStorage.currentRemoteParentSocketLifecycle(socket);
      assertNull(absentAtReadEntry);

      Object fresh = SSLStorage.prepareRemoteParentSocketLifecycle(socket);
      ThreadInfo.setRemoteParentSocketFileDescriptor(57);
      BootstrapNative.invalidateRemoteParentSocketFileDescriptor(socket, absentAtReadEntry);

      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertSame(fresh, SSLStorage.currentRemoteParentSocketLifecycle(socket));

      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, absentAtReadEntry);

      assertSame(fresh, SSLStorage.currentRemoteParentSocketLifecycle(socket));
      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, fresh);
    }
  }

  @Test
  void unavailableSocketLifecycleDetachesCurrentThreadState() throws Exception {
    try (Socket socket = new Socket()) {
      Object tombstone = SSLStorage.beginRemoteParentSocketClose(socket);
      ThreadInfo.setRemoteParentSocketFileDescriptor(58);

      assertEquals(-1, BootstrapNative.emitData(socket, 1L, true));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());

      SSLStorage.finishRemoteParentSocketClose(socket, tombstone);
    }
  }

  @Test
  void closedSocketReceiveInvalidatesLiveLifecycleAndCapturedAlias() throws Exception {
    try (Socket socket = new Socket()) {
      RemoteParentSocketContext.Lifecycle lifecycle =
          (RemoteParentSocketContext.Lifecycle)
              SSLStorage.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(lifecycle);
      ThreadInfo.setRemoteParentEnabled(true);
      ThreadInfo.setTaskContextEmitterForTest((operation, value, token) -> {});
      assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(59, lifecycle));
      ThreadInfo.markRemoteParentDirectLookup(lifecycle);
      TaskContext alias = ThreadInfo.captureTaskContext(101L, lifecycle);

      socket.close();

      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(-1, alias.getRemoteParentSocketContext().peek());
      assertEquals(-1, BootstrapNative.emitData(socket, 1L, true));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(-1, alias.getRemoteParentSocketContext().peek());
    }
  }

  @Test
  void closeTombstoneBlocksConcurrentStagingAndIsReleasedAfterCloseReturns() throws Exception {
    try (Socket socket = new Socket()) {
      Object readLifecycle = SSLStorage.prepareRemoteParentSocketLifecycle(socket);
      Object outerTombstone = SSLStorage.beginRemoteParentSocketClose(socket);
      Object nestedTombstone = SSLStorage.beginRemoteParentSocketClose(socket);
      assertNotNull(outerTombstone);
      assertNotSame(readLifecycle, outerTombstone);
      assertSame(outerTombstone, nestedTombstone);
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(socket));

      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, readLifecycle);
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(socket));
      SSLStorage.finishRemoteParentSocketClose(socket, nestedTombstone);
      assertNull(SSLStorage.prepareRemoteParentSocketLifecycle(socket));
      SSLStorage.finishRemoteParentSocketClose(socket, outerTombstone);

      Object retried = SSLStorage.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(retried);
      assertNotSame(outerTombstone, retried);
      SSLStorage.invalidateRemoteParentSocketLifecycle(socket, retried);
    }
  }

  private static class CapturingProxyInputStream extends ProxyInputStream {
    private int forwardedOffset = -1;
    private int forwardedLength = -1;
    private byte[] forwardedBytes;

    CapturingProxyInputStream(InputStream delegate) {
      super(delegate, null);
    }

    @Override
    void forwardRead(byte[] b, int off, int len, Object lifecycle) {
      forwardedOffset = off;
      forwardedLength = len;
      forwardedBytes = Arrays.copyOfRange(b, off, off + len);
    }
  }

  private static Socket socketWithFailingLifecyclePreparation() {
    return new Socket() {
      @Override
      public boolean isClosed() {
        throw new AssertionError("expected lifecycle preparation failure");
      }
    };
  }
}
