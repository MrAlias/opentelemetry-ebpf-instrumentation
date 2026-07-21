/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.ContextKey;
import java.util.concurrent.atomic.AtomicBoolean;

final class ObiContextCandidate {
  static final ContextKey<ObiContextCandidate> KEY =
      ContextKey.named("obi-remote-parent-candidate");

  private Span span;
  private BridgeAccess bridge;
  private final AtomicBoolean resolved = new AtomicBoolean();

  ObiContextCandidate(Span span, BridgeAccess bridge) {
    this.span = span;
    this.bridge = bridge;
  }

  void recordSelection(Span selected) {
    if (!resolved.compareAndSet(false, true)) {
      return;
    }

    Span candidate = span;
    BridgeAccess access = bridge;
    span = null;
    bridge = null;
    if (selected != candidate) {
      access.recordStandardParentWon();
    }
  }
}
