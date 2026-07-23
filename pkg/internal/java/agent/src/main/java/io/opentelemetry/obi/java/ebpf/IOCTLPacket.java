/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.instrumentations.data.Connection;
import java.net.Socket;

public class IOCTLPacket {
  public static final int connectionInfoSize = 36;
  public static final int tlsConnectionMarkerSize = 1 + connectionInfoSize;
  public static final int bufferLengthOffset = tlsConnectionMarkerSize;
  public static final int dataSignalOffset = bufferLengthOffset + Integer.BYTES;
  public static int packetPrefixSize = dataSignalOffset + Long.BYTES;

  public static int writePacketPrefix(
      NativeMemory mem, int off, OperationType type, Socket socket, int bufLen) {
    mem.setByte(off, type.code);
    off++;
    if (socket == null) {
      off = ConnectionInfo.writeEmptyConnectionInfo(mem, off);
    } else {
      if (type == OperationType.SEND) {
        off = ConnectionInfo.writeSendConnectionInfo(mem, off, socket);
      } else {
        off = ConnectionInfo.writeRecvConnectionInfo(mem, off, socket);
      }
    }
    mem.setInt(off, bufLen);
    off += 4;
    mem.setLong(off, 0L);
    off += Long.BYTES;

    return off;
  }

  public static int writePacketPrefix(
      NativeMemory mem, int off, OperationType type, Connection conn, int bufLen) {
    mem.setByte(off, type.code);
    off++;
    if (conn == null) {
      off = ConnectionInfo.writeEmptyConnectionInfo(mem, off);
    } else {
      if (type == OperationType.SEND) {
        off = ConnectionInfo.writeSendConnectionInfo(mem, off, conn);
      } else {
        off = ConnectionInfo.writeRecvConnectionInfo(mem, off, conn);
      }
    }
    mem.setInt(off, bufLen);
    off += 4;
    mem.setLong(off, 0L);
    off += Long.BYTES;

    return off;
  }

  public static int writePacketBuffer(NativeMemory mem, int wOff, byte[] buf, int index, int len) {
    mem.write(wOff, buf, index, len);
    wOff += len;

    return wOff;
  }

  public static int writePacketBuffer(NativeMemory mem, int off, byte[] buf) {
    return writePacketBuffer(mem, off, buf, 0, buf.length);
  }

  public static int writeTlsConnectionMarker(NativeMemory mem, int off, Connection conn) {
    mem.setByte(off, OperationType.TLS_CONNECTION.code);
    return ConnectionInfo.writeRecvConnectionInfo(mem, off + 1, conn);
  }

  public static int writePacket(NativeMemory mem, int off, OperationType type, long parentId) {
    mem.setByte(off, type.code);
    off++;
    off = ThreadInfo.writeThreadContext(mem, off, parentId);
    return off;
  }
}
