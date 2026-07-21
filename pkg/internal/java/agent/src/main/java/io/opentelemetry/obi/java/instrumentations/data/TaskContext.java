/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

/** Submission-time task ownership bound to an opaque eBPF handoff token. */
public final class TaskContext {
  private final long parentThreadId;
  private final long handoffToken;

  public TaskContext(long parentThreadId, long handoffToken) {
    this.parentThreadId = parentThreadId;
    this.handoffToken = handoffToken;
  }

  public long getParentThreadId() {
    return parentThreadId;
  }

  public long getHandoffToken() {
    return handoffToken;
  }
}
