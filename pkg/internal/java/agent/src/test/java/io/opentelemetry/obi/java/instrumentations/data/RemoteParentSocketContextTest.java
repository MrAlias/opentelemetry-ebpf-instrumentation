/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.lang.ref.WeakReference;
import java.net.Socket;
import org.junit.jupiter.api.Test;

class RemoteParentSocketContextTest {
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
