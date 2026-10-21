/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.*;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.utility.JavaModule;
import org.junit.jupiter.api.Test;

class GrpcClientInstTest {
  @Test
  void transformsShadedTlsEngineWithAdditionalUnwrapOverloads() throws Exception {
    Class<?> type =
        Class.forName(
            "io.grpc.netty.shaded.io.netty.handler.ssl.ReferenceCountedOpenSslEngine",
            false,
            getClass().getClassLoader());
    assertNotNull(
        SSLEngineInst.transformer()
            .transform(
                new ByteBuddy().redefine(type),
                new TypeDescription.ForLoadedType(type),
                type.getClassLoader(),
                JavaModule.ofType(type),
                type.getProtectionDomain())
            .make()
            .getBytes());
  }

  @Test
  void transformsPinnedGrpcJavaWithoutChangingClassFormat() throws Exception {
    for (String name :
        new String[] {
          "io.grpc.stub.ClientCalls",
          "io.grpc.internal.ClientCallImpl",
          "io.grpc.internal.DelayedClientCall",
          "io.grpc.internal.RetriableStream",
          "io.grpc.netty.shaded.io.grpc.netty.Utils",
          "io.grpc.netty.shaded.io.netty.handler.codec.http2.DefaultHttp2ConnectionEncoder"
        }) {
      Class<?> type = Class.forName(name);
      assertTrue(GrpcClientInst.matches(type));
      assertTrue(GrpcClientInst.type().matches(new TypeDescription.ForLoadedType(type)));
      assertNotNull(
          GrpcClientInst.transformer()
              .transform(
                  new ByteBuddy().redefine(type),
                  new TypeDescription.ForLoadedType(type),
                  type.getClassLoader(),
                  JavaModule.ofType(type),
                  type.getProtectionDomain())
              .make()
              .getBytes());
    }
    assertFalse(GrpcClientInst.matches(Object.class));
  }
}
