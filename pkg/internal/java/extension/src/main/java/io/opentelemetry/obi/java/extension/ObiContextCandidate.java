/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.context.ContextKey;
import java.util.concurrent.atomic.AtomicBoolean;

final class ObiContextCandidate {
  static final ContextKey<ObiContextCandidate> KEY =
      ContextKey.named("obi-remote-parent-candidate");

  private final SpanContext activeSpanContext;
  private final Resolution resolution;
  private final boolean selectionEligible;

  ObiContextCandidate(Span span, BridgeAccess bridge) {
    this(span.getSpanContext(), new Resolution(bridge), true);
  }

  private ObiContextCandidate(
      SpanContext activeSpanContext, Resolution resolution, boolean selectionEligible) {
    this.activeSpanContext = activeSpanContext;
    this.resolution = resolution;
    this.selectionEligible = selectionEligible;
  }

  ObiContextCandidate followSelection(Span previous, Span selected) {
    if (!isActiveSpan(previous) || selected == previous || !selected.getSpanContext().isValid()) {
      return null;
    }
    return rebind(selected);
  }

  ObiContextCandidate rebind(Span span) {
    return new ObiContextCandidate(span.getSpanContext(), resolution, false);
  }

  boolean isActiveSpan(Span span) {
    return activeSpanContext.equals(span.getSpanContext());
  }

  BridgeAccess claimSelection() {
    return selectionEligible ? resolution.claim() : null;
  }

  private static final class Resolution {
    private final BridgeAccess bridge;
    private final AtomicBoolean pending = new AtomicBoolean(true);

    private Resolution(BridgeAccess bridge) {
      this.bridge = bridge;
    }

    private BridgeAccess claim() {
      return pending.compareAndSet(true, false) ? bridge : null;
    }
  }
}
