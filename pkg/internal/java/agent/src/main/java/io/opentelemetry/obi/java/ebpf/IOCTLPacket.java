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
  public static final int http1LifecycleOffset = dataSignalOffset + Long.BYTES;
  public static final int http1RequestSequenceOffset = http1LifecycleOffset + Long.BYTES;
  public static final int http1PacketPrefixSize = http1RequestSequenceOffset + Long.BYTES;

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

  public static int writeHttp1PacketPrefix(
      NativeMemory mem,
      int off,
      OperationType type,
      Socket socket,
      int bufLen,
      long lifecycleId,
      long requestSequence) {
    validateHttp1Packet(type, bufLen, lifecycleId, requestSequence);
    off = writePacketPrefix(mem, off, type, socket, bufLen);
    return writeHttp1Identity(mem, off, lifecycleId, requestSequence);
  }

  public static int writeHttp1PacketPrefix(
      NativeMemory mem,
      int off,
      OperationType type,
      Connection conn,
      int bufLen,
      long lifecycleId,
      long requestSequence) {
    validateHttp1Packet(type, bufLen, lifecycleId, requestSequence);
    off = writePacketPrefix(mem, off, type, conn, bufLen);
    return writeHttp1Identity(mem, off, lifecycleId, requestSequence);
  }

  private static int writeHttp1Identity(
      NativeMemory mem, int off, long lifecycleId, long requestSequence) {
    mem.setLong(off, lifecycleId);
    off += Long.BYTES;
    mem.setLong(off, requestSequence);
    return off + Long.BYTES;
  }

  private static void validateHttp1Packet(
      OperationType type, int bufLen, long lifecycleId, long requestSequence) {
    if (type == null) {
      throw new IllegalArgumentException("HTTP/1 receive operation must be specified");
    }
    if (lifecycleId == 0L) {
      throw new IllegalArgumentException("HTTP/1 receive lifecycle must be nonzero");
    }
    if (requestSequence == 0L) {
      throw new IllegalArgumentException("HTTP/1 request sequence must be nonzero");
    }
    if (type == OperationType.HTTP1_RECEIVE_START || type == OperationType.HTTP1_RECEIVE_CONTINUE) {
      if (bufLen <= 0) {
        throw new IllegalArgumentException("HTTP/1 receive fragment must be nonempty");
      }
      return;
    }
    if (type == OperationType.HTTP1_RECEIVE_RESET) {
      if (bufLen != 0) {
        throw new IllegalArgumentException("HTTP/1 receive reset must not have a payload");
      }
      return;
    }
    throw new IllegalArgumentException("not an HTTP/1 receive operation: " + type);
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
