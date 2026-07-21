/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

public final class WeakIdentityTaskMapTestAccess {
  private WeakIdentityTaskMapTestAccess() {}

  public static void clearAndObserve(TaskContext context) {
    WeakIdentityTaskMap tasks = new WeakIdentityTaskMap(2);
    Object task = new Object();
    tasks.track(task, context, 7);
    tasks.clearTaskReferenceForTest(task, 7);
    tasks.get(task, 7, false);
  }
}
