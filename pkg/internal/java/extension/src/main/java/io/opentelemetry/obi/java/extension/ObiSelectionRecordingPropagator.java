/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import io.opentelemetry.context.propagation.TextMapSetter;
import java.util.Collection;

final class ObiSelectionRecordingPropagator implements TextMapPropagator {
  private final TextMapPropagator delegate;

  ObiSelectionRecordingPropagator(TextMapPropagator delegate) {
    this.delegate = delegate;
  }

  @Override
  public Collection<String> fields() {
    return delegate.fields();
  }

  @Override
  public <C> void inject(Context context, C carrier, TextMapSetter<C> setter) {
    delegate.inject(context, carrier, setter);
  }

  @Override
  public <C> Context extract(Context context, C carrier, TextMapGetter<C> getter) {
    Context input = context == null ? Context.root() : context;
    ObiContextCandidate previous = input.get(ObiContextCandidate.KEY);
    Context extracted = delegate.extract(input, carrier, getter);
    ObiContextCandidate candidate = extracted.get(ObiContextCandidate.KEY);
    if (candidate != null && candidate != previous) {
      candidate.recordSelection(Span.fromContext(extracted));
    }
    return extracted;
  }
}
