/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

/** Instruments the JDK virtual-thread lifecycle without blocking a carrier thread. */
public class VirtualThreadInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.named("java.lang.VirtualThread");
  }

  public static boolean matches(Class<?> clazz) {
    return "java.lang.VirtualThread".equals(clazz.getName());
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(StartAdvice.class)
                    .on(ElementMatchers.named("start").and(ElementMatchers.takesArguments(1))))
            .visit(Advice.to(MountAdvice.class).on(ElementMatchers.named("mount")))
            .visit(Advice.to(UnmountAdvice.class).on(ElementMatchers.named("unmount")))
            .visit(
                Advice.to(RunAdvice.class)
                    .on(
                        ElementMatchers.named("run")
                            .and(ElementMatchers.takesArgument(0, Runnable.class))))
            .visit(Advice.to(AfterDoneAdvice.class).on(ElementMatchers.named("afterDone")));
  }

  @SuppressWarnings("unused")
  public static final class StartAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.This Object virtualThread) {
      SSLStorage.captureVirtualThread(virtualThread);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.This Object virtualThread, @Advice.Thrown Throwable throwable) {
      if (throwable != null) {
        SSLStorage.untrackTask(virtualThread);
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class MountAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(@Advice.This Thread virtualThread) {
      ThreadInfo.onVirtualThreadMount(virtualThread.getId());
      SSLStorage.enterVirtualThreadScope(virtualThread);
    }
  }

  @SuppressWarnings("unused")
  public static final class UnmountAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit() {
      ThreadInfo.onVirtualThreadUnmount();
    }
  }

  @SuppressWarnings("unused")
  public static final class RunAdvice {
    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.This Thread virtualThread) {
      SSLStorage.exitVirtualThreadScope(virtualThread);
      ThreadInfo.onVirtualThreadTerminate(virtualThread.getId());
    }
  }

  @SuppressWarnings("unused")
  public static final class AfterDoneAdvice {
    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.This Object virtualThread) {
      SSLStorage.untrackTask(virtualThread);
    }
  }
}
