/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

/** Submission-time task ownership bound to an opaque eBPF handoff token. */
public final class TaskContext {
  private final long parentThreadId;
  private final long handoffToken;
  private final RemoteParentSocketContext remoteParentSocketContext;
  private final RemoteParentSocketContext.Lifecycle remoteParentSocketLifecycle;

  public TaskContext(long parentThreadId, long handoffToken) {
    this(parentThreadId, handoffToken, null, null);
  }

  public TaskContext(
      long parentThreadId, long handoffToken, RemoteParentSocketContext remoteParentSocketContext) {
    this(
        parentThreadId,
        handoffToken,
        remoteParentSocketContext,
        remoteParentSocketContext == null ? null : remoteParentSocketContext.lifecycle());
  }

  public TaskContext(
      long parentThreadId,
      long handoffToken,
      RemoteParentSocketContext remoteParentSocketContext,
      RemoteParentSocketContext.Lifecycle remoteParentSocketLifecycle) {
    this.parentThreadId = parentThreadId;
    this.handoffToken = handoffToken;
    this.remoteParentSocketContext = remoteParentSocketContext;
    this.remoteParentSocketLifecycle = remoteParentSocketLifecycle;
  }

  public long getParentThreadId() {
    return parentThreadId;
  }

  public long getHandoffToken() {
    return handoffToken;
  }

  public RemoteParentSocketContext getRemoteParentSocketContext() {
    return remoteParentSocketContext;
  }

  public RemoteParentSocketContext.Lifecycle getRemoteParentSocketLifecycle() {
    return remoteParentSocketLifecycle;
  }
}
