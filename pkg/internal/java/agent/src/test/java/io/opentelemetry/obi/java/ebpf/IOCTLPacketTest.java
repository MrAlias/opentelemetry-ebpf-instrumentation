/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.data.Connection;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

// Memory Layout of Pointer p (after pos.write(new byte[] {42}))
// ═══════════════════════════════════════════════════════════════

// Offset    Size    Value    Description
// ───────────────────────────────────────────────────────────────
//   0        1B      0x01     OperationType.SEND.code
//                           ┌─────────────────────────────┐
//   1       36B      ...    |ConnectionInfo (36 bytes)    │
//                           │ (socket connection data)    │
//                           └─────────────────────────────┘
//  37        4B      0x01     Buffer length (int = 1)
//  41        8B      0x00     Native data-signal nonce
//                           ┌─────────────────────────────┐
//  49        1B      0x2A   |Data byte: 42                │ Actual payload
//                           └─────────────────────────────┘

// Total size: 1 + 36 + 4 + 8 + 1 = 50 bytes

// Test assertions:
// ───────────────────────────────────────────────────────────────
// p.getByte(0)           → 1    (OperationType.SEND)
// p.getInt(1 + 36)       → 1    (Buffer length at offset 37)
// p.getLong(1 + 36 + 4)  → 0    (Nonce initialized for native code)
// p.getByte(packetPrefixSize) → 42 (Data byte at offset 49)

class IOCTLPacketTest {

  @Test
  void operationCodesRemainStableAndAppendHttp1ReceiveOperations() {
    assertEquals(1, OperationType.SEND.code);
    assertEquals(2, OperationType.RECEIVE.code);
    assertEquals(3, OperationType.THREAD.code);
    assertEquals(4, OperationType.VT_MOUNT.code);
    assertEquals(5, OperationType.VT_UNMOUNT.code);
    assertEquals(6, OperationType.TASK_CAPTURE.code);
    assertEquals(7, OperationType.TASK_CANCEL.code);
    assertEquals(8, OperationType.TASK_LINK.code);
    assertEquals(9, OperationType.TASK_RELAY_CAPTURE.code);
    assertEquals(10, OperationType.PROCESS_REGISTER.code);
    assertEquals(11, OperationType.VT_TERMINATE.code);
    assertEquals(12, OperationType.TASK_UNLINK.code);
    assertEquals(13, OperationType.TLS_CONNECTION.code);
    assertEquals(14, OperationType.HTTP1_RECEIVE_START.code);
    assertEquals(15, OperationType.HTTP1_RECEIVE_CONTINUE.code);
    assertEquals(16, OperationType.HTTP1_RECEIVE_RESET.code);
  }

  @Test
  void legacyReceivePacketPrefixRemainsExactly49Bytes() throws Exception {
    InetAddress local = InetAddress.getByAddress(new byte[] {10, 11, 12, 13});
    InetAddress remote = InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 44});
    Connection connection = new Connection(local, 0x1234, remote, 0x5678, 7);
    NativeMemory mem = new NativeMemory(IOCTLPacket.packetPrefixSize, true);

    int newOff =
        IOCTLPacket.writePacketPrefix(mem, 0, OperationType.RECEIVE, connection, 0x10203040);

    byte[] expected = new byte[49];
    expected[0] = 2;
    writeIpv4Mapped(expected, 1, remote.getAddress());
    writeIpv4Mapped(expected, 17, local.getAddress());
    ByteBuffer fields = ByteBuffer.wrap(expected).order(ByteOrder.nativeOrder());
    fields.putShort(33, (short) 0x5678);
    fields.putShort(35, (short) 0x1234);
    fields.putInt(37, 0x10203040);
    fields.putLong(41, 0L);

    assertEquals(36, IOCTLPacket.connectionInfoSize);
    assertEquals(37, IOCTLPacket.tlsConnectionMarkerSize);
    assertEquals(37, IOCTLPacket.bufferLengthOffset);
    assertEquals(41, IOCTLPacket.dataSignalOffset);
    assertEquals(49, IOCTLPacket.packetPrefixSize);
    assertEquals(49, newOff);
    assertArrayEquals(expected, packetBytes(mem, expected.length));
  }

  @Test
  void legacySendPacketPrefixRemainsExactly49Bytes() throws Exception {
    InetAddress local = InetAddress.getByAddress(new byte[] {10, 11, 12, 13});
    InetAddress remote = InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 44});
    Connection connection = new Connection(local, 0x1234, remote, 0x5678, 7);
    NativeMemory mem = new NativeMemory(IOCTLPacket.packetPrefixSize, true);

    int newOff = IOCTLPacket.writePacketPrefix(mem, 0, OperationType.SEND, connection, 0x10203040);

    byte[] expected = new byte[49];
    expected[0] = 1;
    writeIpv4Mapped(expected, 1, local.getAddress());
    writeIpv4Mapped(expected, 17, remote.getAddress());
    ByteBuffer fields = ByteBuffer.wrap(expected).order(ByteOrder.nativeOrder());
    fields.putShort(33, (short) 0x1234);
    fields.putShort(35, (short) 0x5678);
    fields.putInt(37, 0x10203040);
    fields.putLong(41, 0L);

    assertEquals(49, IOCTLPacket.packetPrefixSize);
    assertEquals(49, newOff);
    assertArrayEquals(expected, packetBytes(mem, expected.length));
  }

  @Test
  void writesExactHttp1StartPacketAndPayload() throws Exception {
    InetAddress local = InetAddress.getByAddress(new byte[] {10, 11, 12, 13});
    InetAddress remote = InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 44});
    Connection connection = new Connection(local, 0x1234, remote, 0x5678, 7);
    byte[] payload = {0x47, 0x45, 0x54};
    NativeMemory mem = new NativeMemory(IOCTLPacket.http1PacketPrefixSize + payload.length, true);

    int payloadOff =
        IOCTLPacket.writeHttp1PacketPrefix(
            mem,
            0,
            OperationType.HTTP1_RECEIVE_START,
            connection,
            payload.length,
            0x0102030405060708L,
            0x1112131415161718L);
    int newOff = IOCTLPacket.writePacketBuffer(mem, payloadOff, payload);

    byte[] expected = new byte[65 + payload.length];
    expected[0] = 14;
    writeIpv4Mapped(expected, 1, remote.getAddress());
    writeIpv4Mapped(expected, 17, local.getAddress());
    ByteBuffer fields = ByteBuffer.wrap(expected).order(ByteOrder.nativeOrder());
    fields.putShort(33, (short) 0x5678);
    fields.putShort(35, (short) 0x1234);
    fields.putInt(37, payload.length);
    fields.putLong(41, 0L);
    fields.putLong(49, 0x0102030405060708L);
    fields.putLong(57, 0x1112131415161718L);
    System.arraycopy(payload, 0, expected, 65, payload.length);

    assertEquals(49, IOCTLPacket.http1LifecycleOffset);
    assertEquals(57, IOCTLPacket.http1RequestSequenceOffset);
    assertEquals(65, IOCTLPacket.http1PacketPrefixSize);
    assertEquals(65, payloadOff);
    assertEquals(expected.length, newOff);
    assertArrayEquals(expected, packetBytes(mem, expected.length));
  }

  @Test
  void writesExactHttp1ContinuePacketWithEmptyConnection() {
    byte[] payload = {(byte) 0xa0, (byte) 0xb1};
    NativeMemory mem = new NativeMemory(IOCTLPacket.http1PacketPrefixSize + payload.length, true);

    int payloadOff =
        IOCTLPacket.writeHttp1PacketPrefix(
            mem,
            0,
            OperationType.HTTP1_RECEIVE_CONTINUE,
            (Socket) null,
            payload.length,
            0xf1f2f3f4f5f6f7f8L,
            0x2122232425262728L);
    int newOff = IOCTLPacket.writePacketBuffer(mem, payloadOff, payload);

    byte[] expected = new byte[65 + payload.length];
    expected[0] = 15;
    ByteBuffer fields = ByteBuffer.wrap(expected).order(ByteOrder.nativeOrder());
    fields.putInt(37, payload.length);
    fields.putLong(41, 0L);
    fields.putLong(49, 0xf1f2f3f4f5f6f7f8L);
    fields.putLong(57, 0x2122232425262728L);
    System.arraycopy(payload, 0, expected, 65, payload.length);

    assertEquals(65, payloadOff);
    assertEquals(expected.length, newOff);
    assertArrayEquals(expected, packetBytes(mem, expected.length));
  }

  @Test
  void writesExactHttp1ResetPacketWithoutPayload() throws Exception {
    InetAddress local = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    InetAddress remote = InetAddress.getByAddress(new byte[] {127, 0, 0, 2});
    Connection connection = new Connection(local, 1234, remote, 5678, 7);
    NativeMemory mem = new NativeMemory(IOCTLPacket.http1PacketPrefixSize, true);

    int newOff =
        IOCTLPacket.writeHttp1PacketPrefix(
            mem,
            0,
            OperationType.HTTP1_RECEIVE_RESET,
            connection,
            0,
            0x3132333435363738L,
            0x4142434445464748L);

    byte[] expected = new byte[65];
    expected[0] = 16;
    writeIpv4Mapped(expected, 1, remote.getAddress());
    writeIpv4Mapped(expected, 17, local.getAddress());
    ByteBuffer fields = ByteBuffer.wrap(expected).order(ByteOrder.nativeOrder());
    fields.putShort(33, (short) 5678);
    fields.putShort(35, (short) 1234);
    fields.putInt(37, 0);
    fields.putLong(41, 0L);
    fields.putLong(49, 0x3132333435363738L);
    fields.putLong(57, 0x4142434445464748L);

    assertEquals(expected.length, newOff);
    assertArrayEquals(expected, packetBytes(mem, expected.length));
  }

  @Test
  void rejectsInvalidHttp1PacketBeforeWritingAnyBytes() {
    byte[] sentinel = new byte[IOCTLPacket.http1PacketPrefixSize];
    Arrays.fill(sentinel, (byte) 0x5a);
    NativeMemory mem = new NativeMemory(sentinel.length, true);
    mem.write(0, sentinel, 0, sentinel.length);

    assertThrows(
        IllegalArgumentException.class,
        () -> IOCTLPacket.writeHttp1PacketPrefix(mem, 0, null, (Connection) null, 1, 1L, 1L));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            IOCTLPacket.writeHttp1PacketPrefix(
                mem, 0, OperationType.RECEIVE, (Connection) null, 1, 1L, 1L));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            IOCTLPacket.writeHttp1PacketPrefix(
                mem, 0, OperationType.HTTP1_RECEIVE_START, (Connection) null, 0, 1L, 1L));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            IOCTLPacket.writeHttp1PacketPrefix(
                mem, 0, OperationType.HTTP1_RECEIVE_CONTINUE, (Connection) null, -1, 1L, 1L));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            IOCTLPacket.writeHttp1PacketPrefix(
                mem, 0, OperationType.HTTP1_RECEIVE_RESET, (Connection) null, 1, 1L, 1L));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            IOCTLPacket.writeHttp1PacketPrefix(
                mem, 0, OperationType.HTTP1_RECEIVE_START, (Connection) null, 1, 0L, 1L));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            IOCTLPacket.writeHttp1PacketPrefix(
                mem, 0, OperationType.HTTP1_RECEIVE_START, (Connection) null, 1, 1L, 0L));

    assertArrayEquals(sentinel, packetBytes(mem, sentinel.length));
  }

  @Test
  void testWritePacketPrefixWithNullSocket() {
    NativeMemory mem = new NativeMemory(64, true);
    int off = 0;
    OperationType type = OperationType.SEND;
    int bufLen = 10;

    int newOff = IOCTLPacket.writePacketPrefix(mem, off, type, (java.net.Socket) null, bufLen);

    assertEquals(IOCTLPacket.packetPrefixSize, newOff);
    assertEquals(type.code, mem.getByte(0));
    assertEquals(bufLen, mem.getInt(IOCTLPacket.bufferLengthOffset));
    assertEquals(0L, mem.getLong(IOCTLPacket.dataSignalOffset));
  }

  @Test
  void testWritePacketPrefixWithNullConnection() {
    NativeMemory mem = new NativeMemory(64, true);
    int off = 0;
    OperationType type = OperationType.RECEIVE;
    int bufLen = 20;

    int newOff = IOCTLPacket.writePacketPrefix(mem, off, type, (Connection) null, bufLen);

    assertEquals(IOCTLPacket.packetPrefixSize, newOff);
    assertEquals(type.code, mem.getByte(0));
    assertEquals(bufLen, mem.getInt(IOCTLPacket.bufferLengthOffset));
    assertEquals(0L, mem.getLong(IOCTLPacket.dataSignalOffset));
  }

  @Test
  void testWritePacketPrefixWithConnection() {
    NativeMemory mem = new NativeMemory(64, true);
    int off = 0;
    OperationType type = OperationType.RECEIVE;
    int bufLen = 20;

    int newOff = IOCTLPacket.writePacketPrefix(mem, off, type, (Connection) null, bufLen);

    assertEquals(IOCTLPacket.packetPrefixSize, newOff);
    assertEquals(type.code, mem.getByte(0));
    assertEquals(bufLen, mem.getInt(IOCTLPacket.bufferLengthOffset));
    assertEquals(0L, mem.getLong(IOCTLPacket.dataSignalOffset));
  }

  @Test
  void testWritePacketBuffer() {
    NativeMemory mem = new NativeMemory(32, true);
    int off = 5;
    byte[] buf = {1, 2, 3, 4};

    int newOff = IOCTLPacket.writePacketBuffer(mem, off, buf);

    assertEquals(off + buf.length, newOff);
    for (int i = 0; i < buf.length; i++) {
      assertEquals(buf[i], mem.getByte(off + i));
    }
  }

  @Test
  void testWriteTlsConnectionMarker() throws Exception {
    NativeMemory mem = new NativeMemory(IOCTLPacket.tlsConnectionMarkerSize, true);
    InetAddress local = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    InetAddress remote = InetAddress.getByAddress(new byte[] {127, 0, 0, 2});
    Connection connection = new Connection(local, 1234, remote, 5678, 7);

    int newOff = IOCTLPacket.writeTlsConnectionMarker(mem, 0, connection);

    assertEquals(IOCTLPacket.tlsConnectionMarkerSize, newOff);
    assertEquals(OperationType.TLS_CONNECTION.code, mem.getByte(0));
    for (int i = 0; i < 4; i++) {
      assertEquals(remote.getAddress()[i], mem.getByte(1 + 12 + i));
      assertEquals(local.getAddress()[i], mem.getByte(1 + 16 + 12 + i));
    }
    assertEquals((short) connection.getRemotePort(), mem.getShort(1 + 32));
    assertEquals((short) connection.getLocalPort(), mem.getShort(1 + 34));
  }

  private static byte[] packetBytes(NativeMemory mem, int length) {
    byte[] bytes = new byte[length];
    ByteBuffer source = mem.getBuffer().duplicate();
    ((java.nio.Buffer) source).position(0);
    source.get(bytes);
    return bytes;
  }

  private static void writeIpv4Mapped(byte[] destination, int offset, byte[] address) {
    destination[offset + 10] = (byte) 0xff;
    destination[offset + 11] = (byte) 0xff;
    System.arraycopy(address, 0, destination, offset + 12, address.length);
  }
}
