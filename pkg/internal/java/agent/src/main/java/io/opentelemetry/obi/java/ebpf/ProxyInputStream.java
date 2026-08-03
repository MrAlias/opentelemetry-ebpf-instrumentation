/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import io.opentelemetry.obi.java.BootstrapNative;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

public class ProxyInputStream extends InputStream {
  private final InputStream delegate;
  private final Socket socket;

  public ProxyInputStream(InputStream delegate, Socket socket) {
    this.delegate = delegate;
    this.socket = socket;
  }

  @Override
  public int read() throws IOException {
    Object lifecycle = BootstrapNative.currentRemoteParentSocketLifecycle(socket);
    int value;
    try {
      value = delegate.read();
    } catch (IOException | RuntimeException | Error failure) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
      throw failure;
    }
    if (value < 0) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
      return value;
    }

    byte[] singleByte = {(byte) value};
    try {
      forwardRead(singleByte, 0, 1);
    } catch (RuntimeException | Error failure) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
      throw failure;
    }
    return value;
  }

  @Override
  public int read(byte[] b) throws IOException {
    Object lifecycle = BootstrapNative.currentRemoteParentSocketLifecycle(socket);
    int len;
    try {
      len = delegate.read(b);
    } catch (IOException | RuntimeException | Error failure) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
      throw failure;
    }
    if (len > 0) {
      try {
        forwardRead(b, 0, len);
      } catch (RuntimeException | Error failure) {
        invalidateRemoteParentSocketFileDescriptor(lifecycle);
        throw failure;
      }
    } else if (len < 0) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
    }
    return len;
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    Object lifecycle = BootstrapNative.currentRemoteParentSocketLifecycle(socket);
    int bytesRead;
    try {
      bytesRead = delegate.read(b, off, len);
    } catch (IOException | RuntimeException | Error failure) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
      throw failure;
    }
    if (bytesRead > 0) {
      try {
        forwardRead(b, off, bytesRead);
      } catch (RuntimeException | Error failure) {
        invalidateRemoteParentSocketFileDescriptor(lifecycle);
        throw failure;
      }
    } else if (bytesRead < 0) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
    }
    return bytesRead;
  }

  void forwardRead(byte[] b, int off, int len) {
    NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + len);
    writeReadPacket(p, socket, b, off, len);
    BootstrapNative.emitData(socket, p.getAddress(), true);
  }

  static int writeReadPacket(NativeMemory p, Socket socket, byte[] b, int off, int len) {
    int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.RECEIVE, socket, len);
    return IOCTLPacket.writePacketBuffer(p, wOff, b, off, len);
  }

  @Override
  public void close() throws IOException {
    Object lifecycle = BootstrapNative.beginRemoteParentSocketClose(socket);
    try {
      delegate.close();
    } finally {
      BootstrapNative.finishRemoteParentSocketClose(socket, lifecycle);
    }
  }

  private void invalidateRemoteParentSocketFileDescriptor(Object lifecycle) {
    if (socket != null) {
      BootstrapNative.invalidateRemoteParentSocketFileDescriptor(socket, lifecycle);
    } else {
      BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
    }
  }
}
