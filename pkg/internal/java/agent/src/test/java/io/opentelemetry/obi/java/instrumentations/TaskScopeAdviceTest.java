/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import net.bytebuddy.asm.Advice;
import org.junit.jupiter.api.Test;

class TaskScopeAdviceTest {
  @Test
  void taskExecutionExitsClearScopesOnEveryOutcome() throws Exception {
    assertScopeExit(RunnableInst.RunnableAdvice.class, "exit");
    assertScopeExit(CallableInst.CallableAdvice.class, "exit");
    assertScopeExit(JavaForkJoinTaskInst.ForkJoinTaskAdvice.class, "exitJobSubmit");
    assertScopeExit(NettyExecutorInst.TaskAdvice.class, "exit");
    assertScopeExit(JavaExecutorInst.SetExecuteRunnableStateAdvice.class, "exitJobSubmit");
    assertScopeExit(JavaExecutorInst.SetCallableStateAdvice.class, "exitJobSubmit");
  }

  private static void assertScopeExit(Class<?> adviceClass, String methodName) throws Exception {
    Method method =
        java.util.Arrays.stream(adviceClass.getDeclaredMethods())
            .filter(candidate -> candidate.getName().equals(methodName))
            .filter(candidate -> candidate.isAnnotationPresent(Advice.OnMethodExit.class))
            .findFirst()
            .orElseThrow(NoSuchMethodException::new);
    Advice.OnMethodExit exit = method.getAnnotation(Advice.OnMethodExit.class);
    assertNotNull(exit);
    assertEquals(Throwable.class, exit.onThrowable());

    assertTrue(
        java.util.Arrays.stream(method.getParameterAnnotations())
            .flatMap(java.util.Arrays::stream)
            .anyMatch(annotation -> annotation.annotationType() == Advice.Enter.class));
  }
}
