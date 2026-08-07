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
    Object lifecycle = prepareRemoteParentSocketLifecycle();
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
      forwardRead(singleByte, 0, 1, lifecycle);
    } catch (Throwable failure) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
    }
    return value;
  }

  @Override
  public int read(byte[] b) throws IOException {
    Object lifecycle = prepareRemoteParentSocketLifecycle();
    int len;
    try {
      len = delegate.read(b);
    } catch (IOException | RuntimeException | Error failure) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
      throw failure;
    }
    if (len > 0) {
      try {
        forwardRead(b, 0, len, lifecycle);
      } catch (Throwable failure) {
        invalidateRemoteParentSocketFileDescriptor(lifecycle);
      }
    } else if (len < 0) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
    }
    return len;
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    Object lifecycle = prepareRemoteParentSocketLifecycle();
    int bytesRead;
    try {
      bytesRead = delegate.read(b, off, len);
    } catch (IOException | RuntimeException | Error failure) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
      throw failure;
    }
    if (bytesRead > 0) {
      try {
        forwardRead(b, off, bytesRead, lifecycle);
      } catch (Throwable failure) {
        invalidateRemoteParentSocketFileDescriptor(lifecycle);
      }
    } else if (bytesRead < 0) {
      invalidateRemoteParentSocketFileDescriptor(lifecycle);
    }
    return bytesRead;
  }

  void forwardRead(byte[] b, int off, int len) {
    forwardRead(b, off, len, prepareRemoteParentSocketLifecycle());
  }

  void forwardRead(byte[] b, int off, int len, Object lifecycle) {
    BootstrapNative.emitTelemetryReceiveData(socket, lifecycle, b, off, len);
  }

  static int writeReadPacket(NativeMemory p, Socket socket, byte[] b, int off, int len) {
    int wOff = IOCTLPacket.writeTelemetryReceivePacketPrefix(p, 0, socket, len);
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
    try {
      if (socket != null) {
        BootstrapNative.invalidateRemoteParentSocketFileDescriptor(socket, lifecycle);
      } else {
        BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
      }
    } catch (Throwable failure) {
      // Preserve the application's EOF or delegate exception if cleanup itself fails.
    }
  }

  private Object prepareRemoteParentSocketLifecycle() {
    try {
      return BootstrapNative.prepareRemoteParentSocketLifecycle(socket);
    } catch (Throwable failure) {
      // Instrumentation must never prevent or replace the application read.
      return null;
    }
  }
}
