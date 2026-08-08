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
    Object readState = beginRemoteParentSocketRead();
    Object lifecycle = remoteParentSocketReadLifecycle(readState);
    try {
      int value;
      try {
        value = delegate.read();
      } catch (IOException | RuntimeException | Error failure) {
        abortRemoteParentSocketRead(readState);
        invalidateRemoteParentSocketFileDescriptor(lifecycle);
        throw failure;
      }
      if (value < 0) {
        abortRemoteParentSocketRead(readState);
        invalidateRemoteParentSocketFileDescriptor(lifecycle);
        return value;
      }

      byte[] singleByte = {(byte) value};
      if (claimRemoteParentSocketRead(readState, lifecycle)) {
        try {
          forwardRead(singleByte, 0, 1, lifecycle);
        } catch (Throwable failure) {
          invalidateRemoteParentSocketFileDescriptor(lifecycle);
        }
      }
      return value;
    } finally {
      endRemoteParentSocketRead(readState);
    }
  }

  @Override
  public int read(byte[] b) throws IOException {
    Object readState = beginRemoteParentSocketRead();
    Object lifecycle = remoteParentSocketReadLifecycle(readState);
    try {
      try {
        int len = delegate.read(b);
        if (len > 0 && claimRemoteParentSocketRead(readState, lifecycle)) {
          try {
            forwardRead(b, 0, len, lifecycle);
          } catch (Throwable failure) {
            invalidateRemoteParentSocketFileDescriptor(lifecycle);
          }
        } else if (len < 0) {
          abortRemoteParentSocketRead(readState);
          invalidateRemoteParentSocketFileDescriptor(lifecycle);
        } else if (len == 0) {
          abortRemoteParentSocketRead(readState);
        }
        return len;
      } catch (IOException | RuntimeException | Error failure) {
        abortRemoteParentSocketRead(readState);
        invalidateRemoteParentSocketFileDescriptor(lifecycle);
        throw failure;
      }
    } finally {
      endRemoteParentSocketRead(readState);
    }
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    Object readState = beginRemoteParentSocketRead();
    Object lifecycle = remoteParentSocketReadLifecycle(readState);
    try {
      try {
        int bytesRead = delegate.read(b, off, len);
        if (bytesRead > 0 && claimRemoteParentSocketRead(readState, lifecycle)) {
          try {
            forwardRead(b, off, bytesRead, lifecycle);
          } catch (Throwable failure) {
            invalidateRemoteParentSocketFileDescriptor(lifecycle);
          }
        } else if (bytesRead < 0) {
          abortRemoteParentSocketRead(readState);
          invalidateRemoteParentSocketFileDescriptor(lifecycle);
        } else if (bytesRead == 0) {
          abortRemoteParentSocketRead(readState);
        }
        return bytesRead;
      } catch (IOException | RuntimeException | Error failure) {
        abortRemoteParentSocketRead(readState);
        invalidateRemoteParentSocketFileDescriptor(lifecycle);
        throw failure;
      }
    } finally {
      endRemoteParentSocketRead(readState);
    }
  }

  void forwardRead(byte[] b, int off, int len) {
    Object readState = beginRemoteParentSocketRead();
    try {
      Object lifecycle = remoteParentSocketReadLifecycle(readState);
      if (claimRemoteParentSocketRead(readState, lifecycle)) {
        forwardRead(b, off, len, lifecycle);
      }
    } finally {
      endRemoteParentSocketRead(readState);
    }
  }

  void forwardRead(byte[] b, int off, int len, Object lifecycle) {
    BootstrapNative.emitRemoteParentSocketReceive(socket, lifecycle, b, off, len);
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

  private Object beginRemoteParentSocketRead() {
    try {
      return BootstrapNative.beginRemoteParentSocketRead(socket);
    } catch (Throwable failure) {
      // Instrumentation must never prevent or replace the application read.
      return null;
    }
  }

  private static Object remoteParentSocketReadLifecycle(Object readState) {
    try {
      return BootstrapNative.remoteParentSocketReadLifecycle(readState);
    } catch (Throwable failure) {
      return null;
    }
  }

  private boolean claimRemoteParentSocketRead(Object readState, Object lifecycle) {
    try {
      return BootstrapNative.claimRemoteParentSocketRead(readState, socket, lifecycle);
    } catch (Throwable failure) {
      return false;
    }
  }

  private static void abortRemoteParentSocketRead(Object readState) {
    try {
      BootstrapNative.abortRemoteParentSocketRead(readState);
    } catch (Throwable failure) {
      // Instrumentation cleanup must not replace the application's result or exception.
    }
  }

  private static void endRemoteParentSocketRead(Object readState) {
    try {
      BootstrapNative.endRemoteParentSocketRead(readState);
    } catch (Throwable failure) {
      // Instrumentation cleanup must not replace the application's result or exception.
    }
  }
}
