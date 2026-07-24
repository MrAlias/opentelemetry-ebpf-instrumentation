/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.TraceFlags;
import io.opentelemetry.api.trace.TraceState;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import io.opentelemetry.context.propagation.TextMapSetter;
import java.util.Collection;
import java.util.Collections;

public final class ObiRemoteParentPropagator implements TextMapPropagator {
  private final boolean enabled;
  private final BridgeAccess bridge;

  ObiRemoteParentPropagator(boolean enabled, BridgeAccess bridge) {
    this.enabled = enabled;
    this.bridge = bridge;
  }

  @Override
  public Collection<String> fields() {
    return Collections.emptyList();
  }

  @Override
  public <C> void inject(Context context, C carrier, TextMapSetter<C> setter) {}

  @Override
  public <C> Context extract(Context context, C carrier, TextMapGetter<C> getter) {
    Context input = context == null ? Context.root() : context;
    if (!enabled) {
      return input;
    }

    Span selected = Span.fromContext(input);
    if (selected.getSpanContext().isValid()) {
      ObiContextCandidate candidate = input.get(ObiContextCandidate.KEY);
      if (candidate == null) {
        bridge.discardRemoteParent(BridgeAccess.DISCARD_STANDARD_PARENT);
        return input;
      }
      if (candidate.isActiveSpan(selected)) {
        return input;
      }

      Context rebound = input.with(ObiContextCandidate.KEY, candidate.rebind(selected));
      bridge.discardRemoteParent(BridgeAccess.DISCARD_STANDARD_PARENT);
      return rebound;
    }

    BridgeResult result = bridge.takeRemoteParent();
    if (result.status != BridgeResult.STATUS_VALID) {
      return input;
    }
    if (result.traceId == null || result.parentSpanId == null) {
      bridge.recordExtractionFailure(BridgeAccess.EXTRACTION_MISSING_FIELDS);
      return input;
    }

    try {
      SpanContext remoteParent =
          SpanContext.createFromRemoteParent(
              result.traceId,
              result.parentSpanId,
              TraceFlags.fromByte((byte) result.traceFlags),
              TraceState.getDefault());
      if (!remoteParent.isValid()) {
        bridge.recordExtractionFailure(BridgeAccess.EXTRACTION_INVALID_CONTEXT);
        return input;
      }
      Span candidate = Span.wrap(remoteParent);
      return input
          .with(candidate)
          .with(ObiContextCandidate.KEY, new ObiContextCandidate(candidate, bridge));
    } catch (Throwable ignored) {
      bridge.recordExtractionFailure(BridgeAccess.EXTRACTION_ERROR);
      return input;
    }
  }
}
