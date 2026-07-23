/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.data.Connection;
import java.net.InetAddress;
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
}
