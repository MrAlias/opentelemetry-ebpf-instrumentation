/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SocketChannelInstTest {
  private static final InetSocketAddress LOCAL = new InetSocketAddress("127.0.0.1", 1234);
  private static final InetSocketAddress REMOTE = new InetSocketAddress("127.0.0.2", 5678);

  @AfterEach
  void clearRemoteParentSocketState() {
    ThreadInfo.setRemoteParentEnabled(false);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
  }

  @Test
  void scalarReadPublishesOnlyAReportedPositionAdvance() {
    Object channel = new Object();
    ByteBuffer read = ByteBuffer.allocate(8);
    long initialPosition = SocketChannelInst.ReadAdvice.read(read);
    read.put(new byte[] {1, 2});

    SocketChannelInst.ReadAdvice.read(channel, read, initialPosition, 2, null, LOCAL, REMOTE, 7);

    Connection connection = SSLStorage.getConnectionForReadBuffer(read);
    assertNotNull(connection);
    assertEquals(7, connection.getSocketFileDescriptor());
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void scalarReadRejectsZeroEofExceptionAndInconsistentAdvance() {
    ByteBuffer zero = ByteBuffer.allocate(8);
    SocketChannelInst.ReadAdvice.read(null, zero, 0, 0, null, LOCAL, REMOTE, 8);
    assertNull(SSLStorage.getConnectionForReadBuffer(zero));

    ByteBuffer eof = ByteBuffer.allocate(8);
    SocketChannelInst.ReadAdvice.read(null, eof, 0, -1, null, LOCAL, REMOTE, 8);
    assertNull(SSLStorage.getConnectionForReadBuffer(eof));

    ByteBuffer failed = ByteBuffer.allocate(8);
    failed.put((byte) 1);
    SocketChannelInst.ReadAdvice.read(
        null, failed, 0, 1, new IOException("read failed"), LOCAL, REMOTE, 8);
    assertNull(SSLStorage.getConnectionForReadBuffer(failed));

    ByteBuffer inconsistent = ByteBuffer.allocate(8);
    inconsistent.put((byte) 1);
    SocketChannelInst.ReadAdvice.read(null, inconsistent, 0, 2, null, LOCAL, REMOTE, 8);
    assertNull(SSLStorage.getConnectionForReadBuffer(inconsistent));
  }

  @Test
  void eofRetiresAStagedChannelAliasWhileZeroRemainsNonterminal() throws IOException {
    try (SocketChannel channel = SocketChannel.open()) {
      Connection connection = connection(26);
      assertSame(connection, SSLStorage.associateConnectionWithChannel(channel, connection));
      Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
      assertNotNull(lifecycle);
      assertTrue(
          ThreadInfo.setRemoteParentSocketFileDescriptor(
              connection.getSocketFileDescriptor(), lifecycle));
      RemoteParentSocketContext alias =
          new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);

      SocketChannelInst.ReadAdvice.read(
          channel, ByteBuffer.allocate(1), 0, 0, null, LOCAL, REMOTE, 26);
      assertSame(connection, SSLStorage.getConnectionForChannel(channel));
      assertEquals(26, alias.peek());

      SocketChannelInst.ReadAdvice.read(
          channel, ByteBuffer.allocate(1), 0, -1, null, LOCAL, REMOTE, 26);
      assertNull(SSLStorage.getConnectionForChannel(channel));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(-1, alias.peek());
    }
  }

  @Test
  void readThrowableRetiresAStagedChannelAlias() throws IOException {
    try (SocketChannel channel = SocketChannel.open()) {
      Connection connection = connection(27);
      assertSame(connection, SSLStorage.associateConnectionWithChannel(channel, connection));
      Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
      assertNotNull(lifecycle);
      RemoteParentSocketContext alias =
          new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);

      SocketChannelInst.ReadAdvice.read(
          channel,
          ByteBuffer.allocate(1),
          0,
          0,
          new IOException("expected read failure"),
          LOCAL,
          REMOTE,
          27);

      assertNull(SSLStorage.getConnectionForChannel(channel));
      assertEquals(-1, alias.peek());
    }
  }

  @Test
  void scalarReadReassignsAClearedPooledBuffer() {
    Object firstChannel = new Object();
    Object secondChannel = new Object();
    ByteBuffer read = ByteBuffer.allocate(8);
    long firstPosition = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 1);
    SocketChannelInst.ReadAdvice.read(
        firstChannel, read, firstPosition, 1, null, LOCAL, REMOTE, 11);
    Connection first = SSLStorage.getConnectionForReadBuffer(read);
    assertNotNull(first);

    read.clear();
    long secondPosition = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 2);
    SocketChannelInst.ReadAdvice.read(
        secondChannel, read, secondPosition, 1, null, LOCAL, REMOTE, 12);

    Connection second = SSLStorage.getConnectionForReadBuffer(read);
    assertNotNull(second);
    assertEquals(12, second.getSocketFileDescriptor());
    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(second);
  }

  @Test
  void scalarReadDoesNotReassignABufferWithRetainedBytes() {
    Object firstChannel = new Object();
    Object secondChannel = new Object();
    ByteBuffer read = ByteBuffer.allocate(8);
    long firstPosition = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 1);
    SocketChannelInst.ReadAdvice.read(
        firstChannel, read, firstPosition, 1, null, LOCAL, REMOTE, 13);
    Connection first = SSLStorage.getConnectionForReadBuffer(read);
    assertNotNull(first);

    long secondPosition = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 2);
    SocketChannelInst.ReadAdvice.read(
        secondChannel, read, secondPosition, 1, null, LOCAL, REMOTE, 14);

    assertNull(SSLStorage.getConnectionForReadBuffer(read));
    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(connection(14));
  }

  @Test
  void scalarReadUsesTheFillStateCapturedAtEntry() {
    Object firstChannel = new Object();
    Object secondChannel = new Object();
    ByteBuffer read = ByteBuffer.allocate(8);
    long firstState = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 1);
    read.limit(4);
    SocketChannelInst.ReadAdvice.read(firstChannel, read, firstState, 1, null, LOCAL, REMOTE, 17);
    Connection first = SSLStorage.getConnectionForReadBuffer(read);
    assertNotNull(first);

    read.clear();
    read.limit(4);
    long secondState = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 2);
    read.limit(read.capacity());
    SocketChannelInst.ReadAdvice.read(secondChannel, read, secondState, 1, null, LOCAL, REMOTE, 18);

    assertNull(SSLStorage.getConnectionForReadBuffer(read));
    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(connection(18));
  }

  @Test
  void scatterReadPublishesOnlyBuffersThatAdvancedInTheSelectedRange() {
    Object channel = new Object();
    ByteBuffer skipped = ByteBuffer.allocate(8);
    ByteBuffer first = ByteBuffer.allocate(8);
    ByteBuffer second = ByteBuffer.allocate(8);
    ByteBuffer[] buffers = {skipped, first, second};
    Object[] saved = SocketChannelInst.ReadAdviceArray.read(buffers, 1, 2);
    first.put(new byte[] {1, 2});
    second.put((byte) 3);

    SocketChannelInst.ReadAdviceArray.read(channel, buffers, saved, 3, null, LOCAL, REMOTE, 9);

    assertNull(SSLStorage.getConnectionForReadBuffer(skipped));
    Connection firstConnection = SSLStorage.getConnectionForReadBuffer(first);
    Connection secondConnection = SSLStorage.getConnectionForReadBuffer(second);
    assertNotNull(firstConnection);
    assertNotNull(secondConnection);
    assertEquals(9, firstConnection.getSocketFileDescriptor());
    assertEquals(9, secondConnection.getSocketFileDescriptor());
    SSLStorage.cleanupConnection(firstConnection);
  }

  @Test
  void scatterReadReassignsClearedPooledBuffers() {
    Object firstChannel = new Object();
    Object secondChannel = new Object();
    ByteBuffer firstBuffer = ByteBuffer.allocate(8);
    ByteBuffer secondBuffer = ByteBuffer.allocate(8);
    ByteBuffer[] buffers = {firstBuffer, secondBuffer};
    Object[] firstSaved = SocketChannelInst.ReadAdviceArray.read(buffers, 0, 2);
    firstBuffer.put((byte) 1);
    secondBuffer.put((byte) 2);
    SocketChannelInst.ReadAdviceArray.read(
        firstChannel, buffers, firstSaved, 2, null, LOCAL, REMOTE, 15);
    Connection first = SSLStorage.getConnectionForReadBuffer(firstBuffer);
    assertNotNull(first);

    firstBuffer.clear();
    secondBuffer.clear();
    Object[] secondSaved = SocketChannelInst.ReadAdviceArray.read(buffers, 0, 2);
    firstBuffer.put((byte) 3);
    secondBuffer.put((byte) 4);
    SocketChannelInst.ReadAdviceArray.read(
        secondChannel, buffers, secondSaved, 2, null, LOCAL, REMOTE, 16);

    Connection second = SSLStorage.getConnectionForReadBuffer(firstBuffer);
    assertNotNull(second);
    assertEquals(16, second.getSocketFileDescriptor());
    assertEquals(16, SSLStorage.getConnectionForReadBuffer(secondBuffer).getSocketFileDescriptor());
    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(second);
  }

  @Test
  void scatterReadRejectsReplacedBuffersAndInconsistentTotals() {
    ByteBuffer original = ByteBuffer.allocate(8);
    ByteBuffer[] replaced = {original};
    Object[] replacedSaved = SocketChannelInst.ReadAdviceArray.read(replaced, 0, 1);
    replaced[0] = ByteBuffer.allocate(8);
    replaced[0].put((byte) 1);
    SocketChannelInst.ReadAdviceArray.read(
        null, replaced, replacedSaved, 1, null, LOCAL, REMOTE, 10);
    assertNull(SSLStorage.getConnectionForReadBuffer(replaced[0]));
    assertNull(SSLStorage.getConnectionForReadBuffer(original));

    ByteBuffer inconsistent = ByteBuffer.allocate(8);
    ByteBuffer[] buffers = {inconsistent};
    Object[] saved = SocketChannelInst.ReadAdviceArray.read(buffers, 0, 1);
    inconsistent.put((byte) 1);
    SocketChannelInst.ReadAdviceArray.read(null, buffers, saved, 2, null, LOCAL, REMOTE, 10);
    assertNull(SSLStorage.getConnectionForReadBuffer(inconsistent));
  }

  @Test
  void scalarReadPublishesTheExactSocketChannelConnection() throws IOException {
    try (SocketChannel channel = SocketChannel.open()) {
      ByteBuffer read = ByteBuffer.allocate(8);
      long initialPosition = SocketChannelInst.ReadAdvice.read(read);
      read.put((byte) 1);

      SocketChannelInst.ReadAdvice.read(channel, read, initialPosition, 1, null, LOCAL, REMOTE, 19);

      Connection connection = SSLStorage.getConnectionForSocketChannel(channel);
      assertNotNull(connection);
      assertEquals(19, connection.getSocketFileDescriptor());
      SSLStorage.cleanupConnection(channel, connection);
      assertNull(SSLStorage.getConnectionForSocketChannel(channel));
    }
  }

  @Test
  void tryCloseRetiresTheConnectionEvenWhenPhysicalCloseIsDeferred() throws IOException {
    try (SocketChannel channel = SocketChannel.open()) {
      Connection connection = connection(20);
      assertSame(connection, SSLStorage.associateConnectionWithSocketChannel(channel, connection));
      Object lifecycle = SSLStorage.remoteParentSocketLifecycle(connection);
      assertTrue(lifecycle instanceof Lifecycle);
      assertTrue(
          ThreadInfo.setRemoteParentSocketFileDescriptor(
              connection.getSocketFileDescriptor(), (Lifecycle) lifecycle));
      RemoteParentSocketContext alias =
          new RemoteParentSocketContext(
              connection.getSocketFileDescriptor(), (Lifecycle) lifecycle);

      SocketChannelInst.TryCloseAdvice.cleanup(
          channel,
          SocketChannelInst.TryCloseAdvice.capture(
              channel, LOCAL, REMOTE, connection.getSocketFileDescriptor()));

      assertNull(SSLStorage.getConnectionForSocketChannel(channel));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(-1, alias.peek());
    }
  }

  @Test
  void terminalKillClosesTheChannelStateWithoutATupleCapture() throws IOException {
    try (SocketChannel channel = SocketChannel.open()) {
      Connection connection = connection(22);
      assertSame(connection, SSLStorage.associateConnectionWithChannel(channel, connection));
      Object lifecycle = SSLStorage.remoteParentSocketLifecycle(connection);
      assertTrue(lifecycle instanceof Lifecycle);
      assertTrue(
          ThreadInfo.setRemoteParentSocketFileDescriptor(
              connection.getSocketFileDescriptor(), (Lifecycle) lifecycle));
      RemoteParentSocketContext alias =
          new RemoteParentSocketContext(
              connection.getSocketFileDescriptor(), (Lifecycle) lifecycle);

      SocketChannelInst.KillAdvice.cleanup(channel, null);

      assertNull(SSLStorage.getConnectionForChannel(channel));
      assertNull(SSLStorage.associateConnectionWithChannel(channel, connection));
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
      assertEquals(-1, alias.peek());
    }
  }

  @Test
  void tryCloseWaitsForAnInFlightLifecycleLeaseThenRetiresTheConnection() throws Exception {
    try (SocketChannel channel = SocketChannel.open()) {
      Connection connection = connection(23);
      assertSame(connection, SSLStorage.associateConnectionWithChannel(channel, connection));
      Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
      assertNotNull(lifecycle);
      Lifecycle.Lease lease = lifecycle.acquireLookupLease();
      assertNotNull(lease);
      CountDownLatch closeFinished = new CountDownLatch(1);
      AtomicReference<Throwable> failure = new AtomicReference<>();
      Thread closer =
          new Thread(
              () -> {
                try {
                  Object[] closeState =
                      SocketChannelInst.TryCloseAdvice.capture(
                          channel, LOCAL, REMOTE, connection.getSocketFileDescriptor());
                  SocketChannelInst.TryCloseAdvice.cleanup(channel, closeState);
                } catch (Throwable thrown) {
                  failure.compareAndSet(null, thrown);
                } finally {
                  closeFinished.countDown();
                }
              });
      closer.start();

      assertTrue(waitForInactive(lifecycle));
      assertFalse(closeFinished.await(250, TimeUnit.MILLISECONDS));
      lease.close();
      assertTrue(closeFinished.await(5, TimeUnit.SECONDS));
      assertNull(failure.get());
      assertFalse(lifecycle.active());
      assertNull(SSLStorage.getConnectionForSocketChannel(channel));
    }
  }

  @Test
  void tryCloseFailureFailsClosedAfterItsPrecloseFence() throws IOException {
    try (SocketChannel channel = SocketChannel.open()) {
      Connection connection = connection(24);
      assertSame(connection, SSLStorage.associateConnectionWithChannel(channel, connection));
      Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
      assertNotNull(lifecycle);
      RemoteParentSocketContext alias =
          new RemoteParentSocketContext(connection.getSocketFileDescriptor(), lifecycle);

      Object[] closeState =
          SocketChannelInst.TryCloseAdvice.capture(
              channel, LOCAL, REMOTE, connection.getSocketFileDescriptor());
      SocketChannelInst.TryCloseAdvice.cleanup(channel, closeState);

      assertNull(SSLStorage.getConnectionForSocketChannel(channel));
      assertEquals(-1, alias.peek());
    }
  }

  @Test
  void concurrentTryCloseEntriesWaitForAnInFlightLeaseBeforeEitherCanRetire() throws Exception {
    try (SocketChannel channel = SocketChannel.open()) {
      Connection connection = connection(25);
      assertSame(connection, SSLStorage.associateConnectionWithChannel(channel, connection));
      Lifecycle lifecycle = (Lifecycle) SSLStorage.remoteParentSocketLifecycle(connection);
      assertNotNull(lifecycle);
      Lifecycle.Lease lease = lifecycle.acquireLookupLease();
      assertNotNull(lease);
      CountDownLatch firstStarted = new CountDownLatch(1);
      CountDownLatch secondStarted = new CountDownLatch(1);
      CountDownLatch firstCaptured = new CountDownLatch(1);
      CountDownLatch secondCaptured = new CountDownLatch(1);
      CountDownLatch firstFinished = new CountDownLatch(1);
      CountDownLatch secondFinished = new CountDownLatch(1);
      AtomicReference<Throwable> failure = new AtomicReference<>();
      Thread first =
          new Thread(
              () -> {
                try {
                  firstStarted.countDown();
                  Object[] closeState =
                      SocketChannelInst.TryCloseAdvice.capture(
                          channel, LOCAL, REMOTE, connection.getSocketFileDescriptor());
                  firstCaptured.countDown();
                  SocketChannelInst.TryCloseAdvice.cleanup(channel, closeState);
                } catch (Throwable thrown) {
                  failure.compareAndSet(null, thrown);
                } finally {
                  firstFinished.countDown();
                }
              });
      Thread second =
          new Thread(
              () -> {
                try {
                  secondStarted.countDown();
                  Object[] closeState =
                      SocketChannelInst.TryCloseAdvice.capture(
                          channel, LOCAL, REMOTE, connection.getSocketFileDescriptor());
                  secondCaptured.countDown();
                  SocketChannelInst.TryCloseAdvice.cleanup(channel, closeState);
                } catch (Throwable thrown) {
                  failure.compareAndSet(null, thrown);
                } finally {
                  secondFinished.countDown();
                }
              });
      first.start();
      assertTrue(firstStarted.await(5, TimeUnit.SECONDS));
      assertTrue(waitForInactive(lifecycle));
      second.start();
      assertTrue(secondStarted.await(5, TimeUnit.SECONDS));

      assertFalse(firstCaptured.await(250, TimeUnit.MILLISECONDS));
      assertFalse(secondCaptured.await(250, TimeUnit.MILLISECONDS));
      assertFalse(lifecycle.active());
      assertNull(lifecycle.acquireLookupLease());

      lease.close();
      assertTrue(firstCaptured.await(5, TimeUnit.SECONDS));
      assertTrue(secondCaptured.await(5, TimeUnit.SECONDS));
      assertTrue(firstFinished.await(5, TimeUnit.SECONDS));
      assertTrue(secondFinished.await(5, TimeUnit.SECONDS));
      assertNull(failure.get());
      assertFalse(lifecycle.active());
      assertNull(SSLStorage.getConnectionForSocketChannel(channel));
    }
  }

  @Test
  void scalarReadSkipsPublicationAfterTerminalChannelClose() throws IOException {
    try (SocketChannel channel = SocketChannel.open()) {
      Connection connection = connection(21);
      assertSame(connection, SSLStorage.associateConnectionWithSocketChannel(channel, connection));
      SSLStorage.cleanupConnection(channel, connection);

      ByteBuffer read = ByteBuffer.allocate(8);
      long initialPosition = SocketChannelInst.ReadAdvice.read(read);
      read.put((byte) 1);
      SocketChannelInst.ReadAdvice.read(channel, read, initialPosition, 1, null, LOCAL, REMOTE, 21);

      assertNull(SSLStorage.getConnectionForReadBuffer(read));
    }
  }

  private static Connection connection(int fileDescriptor) {
    return new Connection(
        LOCAL.getAddress(), LOCAL.getPort(), REMOTE.getAddress(), REMOTE.getPort(), fileDescriptor);
  }

  private static boolean waitForInactive(Lifecycle lifecycle) {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (lifecycle.active() && System.nanoTime() - deadline < 0) {
      Thread.yield();
    }
    return !lifecycle.active();
  }
}
