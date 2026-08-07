/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.lang.ref.WeakReference;
import java.net.Socket;
import org.junit.jupiter.api.Test;

class RemoteParentSocketContextTest {
  @Test
  void lifecycleIdsAreNonzeroAndDistinct() {
    RemoteParentSocketContext.Lifecycle first = new RemoteParentSocketContext.Lifecycle();
    RemoteParentSocketContext.Lifecycle second = new RemoteParentSocketContext.Lifecycle();

    assertNotEquals(0L, first.id());
    assertNotEquals(0L, second.id());
    assertNotEquals(first.id(), second.id());
  }

  @Test
  void socketLifecycleFailsClosedWhenItsWeakOwnerReferenceHasCleared() {
    RemoteParentSocketContext.Lifecycle lifecycle =
        new RemoteParentSocketContext.Lifecycle(new WeakReference<Socket>(null));
    RemoteParentSocketContext context = new RemoteParentSocketContext(61, lifecycle);

    assertFalse(lifecycle.active());
    assertEquals(-1, context.peek());
    assertEquals(-1, context.take());
  }
}
