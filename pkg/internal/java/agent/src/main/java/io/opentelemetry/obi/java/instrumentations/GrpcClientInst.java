/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.GrpcClientContext;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class GrpcClientInst {
  private static final String CALLS = "io.grpc.stub.ClientCalls";
  private static final String RETRIABLE = "io.grpc.internal.RetriableStream";
  private static final String DELAYED_CALL = "io.grpc.internal.DelayedClientCall";
  private static final String CALL = "io.grpc.internal.ClientCallImpl";
  private static final String HEADERS = "io.grpc.netty.shaded.io.grpc.netty.Utils";
  private static final String ENCODER =
      "io.grpc.netty.shaded.io.netty.handler.codec.http2.DefaultHttp2ConnectionEncoder";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.namedOneOf(CALLS, CALL, DELAYED_CALL, RETRIABLE, HEADERS, ENCODER);
  }

  public static boolean matches(Class<?> clazz) {
    String name = clazz.getName();
    return CALLS.equals(name)
        || RETRIABLE.equals(name)
        || CALL.equals(name)
        || DELAYED_CALL.equals(name)
        || HEADERS.equals(name)
        || ENCODER.equals(name);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, loader, module, domain) -> {
      if (type.getName().equals(CALLS)) {
        return builder.visit(
            Advice.to(BlockingAdvice.class)
                .on(ElementMatchers.named("blockingUnaryCall").and(ElementMatchers.isStatic())));
      }
      if (type.getName().equals(CALL) || type.getName().equals(DELAYED_CALL)) {
        return builder.visit(
            Advice.to(StartAdvice.class)
                .on(ElementMatchers.named("start").and(ElementMatchers.takesArguments(2))));
      }
      if (type.getName().equals(RETRIABLE)) {
        return builder.visit(
            Advice.to(CopyAdvice.class)
                .on(ElementMatchers.named("updateHeaders").and(ElementMatchers.takesArguments(2))));
      }
      if (type.getName().equals(HEADERS)) {
        return builder.visit(
            Advice.to(MetadataAdvice.class)
                .on(
                    ElementMatchers.named("convertClientHeaders")
                        .and(ElementMatchers.takesArguments(6))));
      }
      return builder.visit(
          Advice.to(HeadersAdvice.class)
              .on(ElementMatchers.named("writeHeaders").and(ElementMatchers.takesArguments(6))));
    };
  }

  public static class BlockingAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static GrpcClientContext enter() {
      return GrpcClientContext.enter();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter GrpcClientContext previous) {
      GrpcClientContext.exit(previous);
    }
  }

  public static class StartAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Argument(1) Object headers) {
      GrpcClientContext.capture(headers);
    }
  }

  public static class CopyAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(@Advice.Argument(0) Object original, @Advice.Return Object copy) {
      GrpcClientContext.copy(original, copy);
    }
  }

  public static class MetadataAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static GrpcClientContext enter(@Advice.Argument(0) Object metadata) throws Exception {
      return GrpcClientContext.prepare(metadata);
    }

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(@Advice.Enter GrpcClientContext call, @Advice.Return Object headers) {
      GrpcClientContext.bind(headers, call);
    }
  }

  public static class HeadersAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(
        @Advice.Argument(0) Object ctx,
        @Advice.Argument(1) int streamId,
        @Advice.Argument(2) Object headers)
        throws Exception {
      GrpcClientContext.publish(ctx, streamId, headers);
    }
  }
}
