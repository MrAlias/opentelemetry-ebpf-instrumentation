/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpHeaders;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.BaseSubscriber;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.context.Context;

class ReactorNettyContextTest {
  @Test
  @SuppressWarnings("unchecked")
  void subscriptionsRetainTheirOwnContextAcrossSchedulerHandoffs() throws Exception {
    NativeMemory first = new NativeMemory(49, true);
    NativeMemory second = new NativeMemory(49, true);
    Mono<NativeMemory> publisher =
        Mono.deferContextual(
                context -> {
                  assertEquals("kept", context.get("application"));
                  try {
                    return Mono.just(ReactorNettyContext.context(context));
                  } catch (Exception error) {
                    return Mono.error(error);
                  }
                })
            .subscribeOn(Schedulers.single());
    ResultSubscriber one = new ResultSubscriber();
    ResultSubscriber two = new ResultSubscriber();
    publisher.subscribe(
        (CoreSubscriber<NativeMemory>)
            ReactorNettyContext.subscriber(one, one.currentContext(), first, CoreSubscriber.class));
    publisher.subscribe(
        (CoreSubscriber<NativeMemory>)
            ReactorNettyContext.subscriber(
                two, two.currentContext(), second, CoreSubscriber.class));
    assertSame(first, one.result.get(5, TimeUnit.SECONDS));
    assertSame(second, two.result.get(5, TimeUnit.SECONDS));
  }

  private static class ResultSubscriber extends BaseSubscriber<NativeMemory> {
    final CompletableFuture<NativeMemory> result = new CompletableFuture<>();

    @Override
    public Context currentContext() {
      return Context.of("application", "kept");
    }

    @Override
    protected void hookOnNext(NativeMemory value) {
      result.complete(value);
    }

    @Override
    protected void hookOnError(Throwable error) {
      result.completeExceptionally(error);
    }
  }

  @Test
  void insertsOnlyOneHeaderAndPreservesApplicationContext() throws Exception {
    String generated = "00-11111111111111111111111111111111-2222222222222222-01";
    String supplied = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00";
    HttpHeaders headers = new DefaultHttpHeaders();
    ReactorNettyContext.injectHeader(headers, generated);
    ReactorNettyContext.injectHeader(headers, supplied);
    assertEquals(java.util.Collections.singletonList(generated), headers.getAll("traceparent"));

    headers.clear().set("TraceParent", supplied);
    ReactorNettyContext.injectHeader(headers, generated);
    assertEquals(java.util.Collections.singletonList(supplied), headers.getAll("traceparent"));
  }
}
