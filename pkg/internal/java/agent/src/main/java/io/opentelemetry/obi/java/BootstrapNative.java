/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import java.net.Socket;

/** Bootstrap-safe JNI entry points used by instrumented JDK classes. */
public final class BootstrapNative {
  public static final int IOCTL_CMD = 0x0b10b1;
  private static boolean nativeLibraryLoaded;

  private BootstrapNative() {}

  public static native int ioctl(int fd, int cmd, long argp);

  public static native int gettid();

  public static native int socketFileDescriptor(Socket socket);

  public static int emitData(Socket socket, long argp, boolean receive) {
    boolean delegated = false;
    try {
      int socketFileDescriptor = socketFileDescriptor(socket);
      delegated = true;
      return emitData(socketFileDescriptor, argp, receive);
    } finally {
      if (receive && !delegated) {
        ThreadInfo.clearRemoteParentSocketFileDescriptor();
      }
    }
  }

  public static int emitData(int socketFileDescriptor, long argp, boolean receive) {
    boolean keepSocketFileDescriptor = false;
    try {
      if (socketFileDescriptor < 0) {
        return -1;
      }
      int result = emitDataOnSocket(socketFileDescriptor, argp);
      if (receive && result == 1) {
        ThreadInfo.setRemoteParentSocketFileDescriptor(socketFileDescriptor);
        keepSocketFileDescriptor = true;
      }
      return result;
    } finally {
      if (receive && !keepSocketFileDescriptor) {
        ThreadInfo.clearRemoteParentSocketFileDescriptor();
      }
    }
  }

  private static native int emitDataOnSocket(int socketFileDescriptor, long argp);

  public static native int emitVirtualThreadOp(byte operation, long value);

  public static native int emitTaskContextOp(byte operation, long value, long token);

  public static native int configureRemoteParentTransport(
      int transport,
      String unixSocketPath,
      int timeoutMillis,
      long serverUid,
      long processIncarnation);

  public static native int takeRemoteParent(int socketFileDescriptor, byte[] response);

  public static native int discardRemoteParent(int socketFileDescriptor, byte[] response);

  public static native void closeRemoteParentTransport();

  static synchronized void loadNativeLibrary(String path) {
    if (nativeLibraryLoaded) {
      return;
    }
    System.load(path);
    nativeLibraryLoaded = true;
  }

  static synchronized boolean isNativeLibraryLoaded() {
    return nativeLibraryLoaded;
  }
}
