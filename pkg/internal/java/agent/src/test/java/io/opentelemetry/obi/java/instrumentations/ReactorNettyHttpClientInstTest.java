/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.utility.JavaModule;
import org.junit.jupiter.api.Test;
import reactor.netty.http.client.HttpClient;

class ReactorNettyHttpClientInstTest {
  @Test
  void bindsAdviceToActualReactorClassesWithoutChangingClassFormat() throws Exception {
    for (String name :
        new String[] {
          "reactor.core.publisher.Mono",
          "reactor.core.publisher.Flux",
          "reactor.netty.http.client.HttpClientOperations"
        }) {
      Class<?> target = Class.forName(name);
      TypeDescription type = new TypeDescription.ForLoadedType(target);
      assertTrue(ReactorNettyHttpClientInst.matches(target));
      assertTrue(ReactorNettyHttpClientInst.type().matches(type));
      ReactorNettyHttpClientInst.transformer()
          .transform(
              new ByteBuddy().redefine(target),
              type,
              target.getClassLoader(),
              JavaModule.ofType(target),
              target.getProtectionDomain())
          .make();
    }
    assertFalse(ReactorNettyHttpClientInst.matches(HttpClient.class));
    assertFalse(ReactorNettyHttpClientInst.matches(Object.class));
  }
}
