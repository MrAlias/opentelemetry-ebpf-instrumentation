/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class RunnableInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(Runnable.class);
  }

  public static boolean matches(Class<?> clazz) {
    return Runnable.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder.visit(
            Advice.to(RunnableAdvice.class)
                .on(ElementMatchers.named("run").and(ElementMatchers.takesArguments(0))));
  }

  @SuppressWarnings("unused")
  public static final class RunnableAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static boolean enter(@Advice.This Runnable task) {
      // Loom scheduler internals are handled by the mount hook. User tasks
      // still need exact platform-to-virtual and virtual-to-platform handoffs.
      if (ThreadInfo.loomTask(task)) {
        return false;
      }
      TaskContext taskContext = SSLStorage.takeTaskContext(task);
      if (taskContext != null) {
        long parentId = taskContext.getParentThreadId();
        long threadId = BootstrapNative.gettid();
        if (SSLStorage.bootDebugOn().equals(true)) {
          System.err.println(
              "[RunnableAdvice] task = "
                  + task.hashCode()
                  + ", parent = "
                  + parentId
                  + ", thread = "
                  + threadId);
        }
        if (parentId != threadId || taskContext.getHandoffToken() != 0L) {
          return ThreadInfo.enterTaskParentThreadContext(
              threadId,
              parentId,
              taskContext.getHandoffToken(),
              taskContext.getRemoteParentSocketContext(),
              taskContext.getRemoteParentSocketLifecycle(),
              taskContext.getRemoteParentReceiveContext(),
              taskContext.getRemoteParentBridgeEpoch());
        }
        ThreadInfo.cancelTaskContext(taskContext);
      }
      return false;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter boolean linked) {
      if (linked) {
        ThreadInfo.restoreTaskParentThreadContext();
      }
    }
  }
}
