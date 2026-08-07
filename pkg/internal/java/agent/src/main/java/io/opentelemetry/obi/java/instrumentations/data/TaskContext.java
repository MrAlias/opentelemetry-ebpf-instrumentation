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
  private final RemoteParentSocketContext.ReceiveContext remoteParentReceiveContext;
  private final long remoteParentBridgeEpoch;

  public TaskContext(long parentThreadId, long handoffToken) {
    this(parentThreadId, handoffToken, null, null, null);
  }

  public TaskContext(
      long parentThreadId, long handoffToken, RemoteParentSocketContext remoteParentSocketContext) {
    this(
        parentThreadId,
        handoffToken,
        remoteParentSocketContext,
        remoteParentSocketContext == null ? null : remoteParentSocketContext.lifecycle(),
        null);
  }

  public TaskContext(
      long parentThreadId,
      long handoffToken,
      RemoteParentSocketContext remoteParentSocketContext,
      RemoteParentSocketContext.Lifecycle remoteParentSocketLifecycle) {
    this(
        parentThreadId, handoffToken, remoteParentSocketContext, remoteParentSocketLifecycle, null);
  }

  public TaskContext(
      long parentThreadId,
      long handoffToken,
      RemoteParentSocketContext remoteParentSocketContext,
      RemoteParentSocketContext.Lifecycle remoteParentSocketLifecycle,
      RemoteParentSocketContext.ReceiveContext remoteParentReceiveContext) {
    this(
        parentThreadId,
        handoffToken,
        remoteParentSocketContext,
        remoteParentSocketLifecycle,
        remoteParentReceiveContext,
        remoteParentReceiveContext == null ? 0L : remoteParentReceiveContext.bridgeEpoch());
  }

  public TaskContext(
      long parentThreadId,
      long handoffToken,
      RemoteParentSocketContext remoteParentSocketContext,
      RemoteParentSocketContext.Lifecycle remoteParentSocketLifecycle,
      RemoteParentSocketContext.ReceiveContext remoteParentReceiveContext,
      long remoteParentBridgeEpoch) {
    this.parentThreadId = parentThreadId;
    this.handoffToken = handoffToken;
    this.remoteParentSocketContext = remoteParentSocketContext;
    this.remoteParentSocketLifecycle = remoteParentSocketLifecycle;
    this.remoteParentReceiveContext = remoteParentReceiveContext;
    this.remoteParentBridgeEpoch = remoteParentBridgeEpoch;
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

  public RemoteParentSocketContext.ReceiveContext getRemoteParentReceiveContext() {
    return remoteParentReceiveContext;
  }

  /** Provider epoch bound to the exact receive handoff, or zero for ordinary ancestry only. */
  public long getRemoteParentBridgeEpoch() {
    return remoteParentBridgeEpoch;
  }
}
