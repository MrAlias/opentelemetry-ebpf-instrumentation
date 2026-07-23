/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

class SocketChannelInstTest {
  private static final InetSocketAddress LOCAL = new InetSocketAddress("127.0.0.1", 1234);
  private static final InetSocketAddress REMOTE = new InetSocketAddress("127.0.0.2", 5678);

  @Test
  void scalarReadPublishesOnlyAReportedPositionAdvance() {
    ByteBuffer read = ByteBuffer.allocate(8);
    long initialPosition = SocketChannelInst.ReadAdvice.read(read);
    read.put(new byte[] {1, 2});

    SocketChannelInst.ReadAdvice.read(read, initialPosition, 2, null, LOCAL, REMOTE, 7);

    Connection connection = SSLStorage.getConnectionForReadBuffer(read);
    assertNotNull(connection);
    assertEquals(7, connection.getSocketFileDescriptor());
    SSLStorage.cleanupConnection(connection);
  }

  @Test
  void scalarReadRejectsZeroEofExceptionAndInconsistentAdvance() {
    ByteBuffer zero = ByteBuffer.allocate(8);
    SocketChannelInst.ReadAdvice.read(zero, 0, 0, null, LOCAL, REMOTE, 8);
    assertNull(SSLStorage.getConnectionForReadBuffer(zero));

    ByteBuffer eof = ByteBuffer.allocate(8);
    SocketChannelInst.ReadAdvice.read(eof, 0, -1, null, LOCAL, REMOTE, 8);
    assertNull(SSLStorage.getConnectionForReadBuffer(eof));

    ByteBuffer failed = ByteBuffer.allocate(8);
    failed.put((byte) 1);
    SocketChannelInst.ReadAdvice.read(
        failed, 0, 1, new IOException("read failed"), LOCAL, REMOTE, 8);
    assertNull(SSLStorage.getConnectionForReadBuffer(failed));

    ByteBuffer inconsistent = ByteBuffer.allocate(8);
    inconsistent.put((byte) 1);
    SocketChannelInst.ReadAdvice.read(inconsistent, 0, 2, null, LOCAL, REMOTE, 8);
    assertNull(SSLStorage.getConnectionForReadBuffer(inconsistent));
  }

  @Test
  void scalarReadReassignsAClearedPooledBuffer() {
    ByteBuffer read = ByteBuffer.allocate(8);
    long firstPosition = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 1);
    SocketChannelInst.ReadAdvice.read(read, firstPosition, 1, null, LOCAL, REMOTE, 11);
    Connection first = SSLStorage.getConnectionForReadBuffer(read);
    assertNotNull(first);

    read.clear();
    long secondPosition = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 2);
    SocketChannelInst.ReadAdvice.read(read, secondPosition, 1, null, LOCAL, REMOTE, 12);

    Connection second = SSLStorage.getConnectionForReadBuffer(read);
    assertNotNull(second);
    assertEquals(12, second.getSocketFileDescriptor());
    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(second);
  }

  @Test
  void scalarReadDoesNotReassignABufferWithRetainedBytes() {
    ByteBuffer read = ByteBuffer.allocate(8);
    long firstPosition = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 1);
    SocketChannelInst.ReadAdvice.read(read, firstPosition, 1, null, LOCAL, REMOTE, 13);
    Connection first = SSLStorage.getConnectionForReadBuffer(read);
    assertNotNull(first);

    long secondPosition = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 2);
    SocketChannelInst.ReadAdvice.read(read, secondPosition, 1, null, LOCAL, REMOTE, 14);

    assertNull(SSLStorage.getConnectionForReadBuffer(read));
    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(connection(14));
  }

  @Test
  void scalarReadUsesTheFillStateCapturedAtEntry() {
    ByteBuffer read = ByteBuffer.allocate(8);
    long firstState = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 1);
    read.limit(4);
    SocketChannelInst.ReadAdvice.read(read, firstState, 1, null, LOCAL, REMOTE, 17);
    Connection first = SSLStorage.getConnectionForReadBuffer(read);
    assertNotNull(first);

    read.clear();
    read.limit(4);
    long secondState = SocketChannelInst.ReadAdvice.read(read);
    read.put((byte) 2);
    read.limit(read.capacity());
    SocketChannelInst.ReadAdvice.read(read, secondState, 1, null, LOCAL, REMOTE, 18);

    assertNull(SSLStorage.getConnectionForReadBuffer(read));
    SSLStorage.cleanupConnection(first);
    SSLStorage.cleanupConnection(connection(18));
  }

  @Test
  void scatterReadPublishesOnlyBuffersThatAdvancedInTheSelectedRange() {
    ByteBuffer skipped = ByteBuffer.allocate(8);
    ByteBuffer first = ByteBuffer.allocate(8);
    ByteBuffer second = ByteBuffer.allocate(8);
    ByteBuffer[] buffers = {skipped, first, second};
    Object[] saved = SocketChannelInst.ReadAdviceArray.read(buffers, 1, 2);
    first.put(new byte[] {1, 2});
    second.put((byte) 3);

    SocketChannelInst.ReadAdviceArray.read(buffers, saved, 3, null, LOCAL, REMOTE, 9);

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
    ByteBuffer firstBuffer = ByteBuffer.allocate(8);
    ByteBuffer secondBuffer = ByteBuffer.allocate(8);
    ByteBuffer[] buffers = {firstBuffer, secondBuffer};
    Object[] firstSaved = SocketChannelInst.ReadAdviceArray.read(buffers, 0, 2);
    firstBuffer.put((byte) 1);
    secondBuffer.put((byte) 2);
    SocketChannelInst.ReadAdviceArray.read(buffers, firstSaved, 2, null, LOCAL, REMOTE, 15);
    Connection first = SSLStorage.getConnectionForReadBuffer(firstBuffer);
    assertNotNull(first);

    firstBuffer.clear();
    secondBuffer.clear();
    Object[] secondSaved = SocketChannelInst.ReadAdviceArray.read(buffers, 0, 2);
    firstBuffer.put((byte) 3);
    secondBuffer.put((byte) 4);
    SocketChannelInst.ReadAdviceArray.read(buffers, secondSaved, 2, null, LOCAL, REMOTE, 16);

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
    SocketChannelInst.ReadAdviceArray.read(replaced, replacedSaved, 1, null, LOCAL, REMOTE, 10);
    assertNull(SSLStorage.getConnectionForReadBuffer(replaced[0]));
    assertNull(SSLStorage.getConnectionForReadBuffer(original));

    ByteBuffer inconsistent = ByteBuffer.allocate(8);
    ByteBuffer[] buffers = {inconsistent};
    Object[] saved = SocketChannelInst.ReadAdviceArray.read(buffers, 0, 1);
    inconsistent.put((byte) 1);
    SocketChannelInst.ReadAdviceArray.read(buffers, saved, 2, null, LOCAL, REMOTE, 10);
    assertNull(SSLStorage.getConnectionForReadBuffer(inconsistent));
  }

  private static Connection connection(int fileDescriptor) {
    return new Connection(
        LOCAL.getAddress(), LOCAL.getPort(), REMOTE.getAddress(), REMOTE.getPort(), fileDescriptor);
  }
}
