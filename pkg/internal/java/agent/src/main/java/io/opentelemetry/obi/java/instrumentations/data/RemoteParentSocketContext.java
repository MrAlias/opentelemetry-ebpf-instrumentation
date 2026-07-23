/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import java.util.concurrent.atomic.AtomicInteger;

/** One-shot accepted-socket ownership shared by an exact task handoff. */
public final class RemoteParentSocketContext {
  private final AtomicInteger socketFileDescriptor;

  public RemoteParentSocketContext(int socketFileDescriptor) {
    if (socketFileDescriptor < 0) {
      throw new IllegalArgumentException("socket file descriptor must be non-negative");
    }
    this.socketFileDescriptor = new AtomicInteger(socketFileDescriptor);
  }

  public int peek() {
    return socketFileDescriptor.get();
  }

  public int take() {
    return socketFileDescriptor.getAndSet(-1);
  }
}
