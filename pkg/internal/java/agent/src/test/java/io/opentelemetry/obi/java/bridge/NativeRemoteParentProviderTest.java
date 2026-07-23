/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class NativeRemoteParentProviderTest {
  @AfterEach
  void resetThreadInfo() throws Exception {
    ThreadInfo.setRemoteParentEnabled(false);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    setTaskContextEmitter(null);
  }

  @Test
  void circuitBreaksTransportOverload() {
    assertTrue(NativeRemoteParentProvider.requiresReconfiguration(RemoteParentStatus.UNKNOWN));
    assertTrue(NativeRemoteParentProvider.requiresReconfiguration(RemoteParentStatus.OVERLOAD));
  }

  @Test
  void keepsOrdinaryLookupOutcomesOnTheReadyTransport() {
    assertFalse(NativeRemoteParentProvider.requiresReconfiguration(RemoteParentStatus.VALID));
    assertFalse(NativeRemoteParentProvider.requiresReconfiguration(RemoteParentStatus.MISSING));
    assertFalse(NativeRemoteParentProvider.requiresReconfiguration(RemoteParentStatus.STALE));
    assertFalse(
        NativeRemoteParentProvider.requiresReconfiguration(RemoteParentStatus.ALREADY_CONSUMED));
  }

  @Test
  void registersBeforeEveryConfigurationAttempt() throws Exception {
    AtomicInteger configurationAttempts = new AtomicInteger();
    AtomicInteger registrations = new AtomicInteger();
    List<String> events = new ArrayList<>();
    NativeRemoteParentProvider provider =
        new NativeRemoteParentProvider(
            RemoteParentTransport.AUTO,
            "/tmp/obi-java.sock",
            50,
            0,
            (transport, path, timeout, uid, processIncarnation) -> {
              events.add("configure");
              return configurationAttempts.getAndIncrement() == 0
                  ? RemoteParentStatus.UNSUPPORTED
                  : RemoteParentStatus.VALID;
            },
            () -> {
              events.add("register");
              registrations.incrementAndGet();
              return true;
            });

    assertEquals(1, configurationAttempts.get());
    assertEquals(1, registrations.get());
    assertEquals(Arrays.asList("register", "configure"), events);
    makeRetryEligible(provider);

    provider.takeRemoteParent();

    assertEquals(2, configurationAttempts.get());
    assertEquals(2, registrations.get());
    assertEquals(Arrays.asList("register", "configure", "register", "configure"), events);
    provider.close();
  }

  @Test
  void failedRegistrationSkipsConfigurationAndRecovers() throws Exception {
    AtomicInteger configurationAttempts = new AtomicInteger();
    AtomicInteger registrations = new AtomicInteger();
    NativeRemoteParentProvider provider =
        new NativeRemoteParentProvider(
            RemoteParentTransport.AUTO,
            "/tmp/obi-java.sock",
            50,
            0,
            (transport, path, timeout, uid, processIncarnation) -> {
              configurationAttempts.incrementAndGet();
              return RemoteParentStatus.VALID;
            },
            () -> registrations.incrementAndGet() > 1);

    assertFalse(provider.isReady());
    assertEquals(1, registrations.get());
    assertEquals(0, configurationAttempts.get());
    makeRetryEligible(provider);

    assertTrue(ensureReady(provider));

    assertTrue(provider.isReady());
    assertEquals(2, registrations.get());
    assertEquals(1, configurationAttempts.get());
    provider.close();
  }

  @Test
  void unauthorizedAfterRestartReregistersBeforeRecovery() throws Exception {
    AtomicInteger configurationAttempts = new AtomicInteger();
    AtomicInteger registrations = new AtomicInteger();
    NativeRemoteParentProvider provider =
        new NativeRemoteParentProvider(
            RemoteParentTransport.AUTO,
            "/tmp/obi-java.sock",
            50,
            0,
            (transport, path, timeout, uid, processIncarnation) -> {
              configurationAttempts.incrementAndGet();
              return RemoteParentStatus.VALID;
            },
            () -> {
              registrations.incrementAndGet();
              return true;
            });

    assertTrue(provider.isReady());
    assertEquals(1, registrations.get());
    assertEquals(1, configurationAttempts.get());

    markUnavailable(provider, RemoteParentStatus.UNAUTHORIZED);
    assertFalse(provider.isReady());
    makeRetryEligible(provider);

    assertTrue(ensureReady(provider));
    assertEquals(2, registrations.get());
    assertEquals(2, configurationAttempts.get());
    provider.close();
  }

  @Test
  void consumesSocketOwnershipWhenTransportIsUnavailable() throws Exception {
    NativeRemoteParentProvider provider =
        new NativeRemoteParentProvider(
            RemoteParentTransport.DISABLED,
            "/tmp/obi-java.sock",
            50,
            0,
            (transport, path, timeout, uid, processIncarnation) -> RemoteParentStatus.DISABLED,
            () -> true);

    TaskContext alias = captureSocketAlias(17);
    provider.takeRemoteParent();

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, alias.getRemoteParentSocketContext().peek());
    provider.close();
  }

  @Test
  void clearsSocketFileDescriptorWhenBufferPoolIsExhausted() throws Exception {
    NativeRemoteParentProvider provider = readyProvider();
    Field field = NativeRemoteParentProvider.class.getDeclaredField("buffers");
    field.setAccessible(true);
    @SuppressWarnings("unchecked")
    AtomicReferenceArray<byte[]> buffers = (AtomicReferenceArray<byte[]>) field.get(provider);
    for (int i = 0; i < buffers.length(); i++) {
      buffers.set(i, null);
    }

    TaskContext alias = captureSocketAlias(18);
    RemoteParentRecord record = provider.takeRemoteParent();

    assertEquals(RemoteParentStatus.OVERLOAD, record.getStatus());
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, alias.getRemoteParentSocketContext().peek());
    provider.close();
  }

  @Test
  void consumesSocketOwnershipAfterNativeTerminalPath() throws Exception {
    NativeRemoteParentProvider provider = readyProvider();

    TaskContext alias = captureSocketAlias(1_000_000);
    provider.discardRemoteParent();

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, alias.getRemoteParentSocketContext().peek());
    provider.close();
  }

  private static TaskContext captureSocketAlias(int socketFileDescriptor) throws Exception {
    setTaskContextEmitter((proxy, method, args) -> null);
    ThreadInfo.setRemoteParentEnabled(true);
    ThreadInfo.setRemoteParentSocketFileDescriptor(socketFileDescriptor);
    return ThreadInfo.captureTaskContext(101L);
  }

  private static void setTaskContextEmitter(java.lang.reflect.InvocationHandler handler)
      throws Exception {
    Class<?> emitter =
        Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo$TaskContextEmitter");
    Method setter = ThreadInfo.class.getDeclaredMethod("setTaskContextEmitterForTest", emitter);
    setter.setAccessible(true);
    Object value =
        handler == null
            ? null
            : Proxy.newProxyInstance(emitter.getClassLoader(), new Class<?>[] {emitter}, handler);
    setter.invoke(null, value);
  }

  private static NativeRemoteParentProvider readyProvider() {
    return new NativeRemoteParentProvider(
        RemoteParentTransport.GETSOCKOPT,
        "/tmp/obi-java.sock",
        50,
        0,
        (transport, path, timeout, uid, processIncarnation) -> RemoteParentStatus.VALID,
        () -> true);
  }

  private static void makeRetryEligible(NativeRemoteParentProvider provider) throws Exception {
    Field nextAttempt =
        NativeRemoteParentProvider.class.getDeclaredField("nextConfigurationAttemptNanos");
    nextAttempt.setAccessible(true);
    nextAttempt.setLong(provider, 0L);
  }

  private static void markUnavailable(NativeRemoteParentProvider provider, int status)
      throws Exception {
    Method method =
        NativeRemoteParentProvider.class.getDeclaredMethod("markUnavailable", int.class);
    method.setAccessible(true);
    method.invoke(provider, status);
  }

  private static boolean ensureReady(NativeRemoteParentProvider provider) throws Exception {
    Method method = NativeRemoteParentProvider.class.getDeclaredMethod("ensureReady");
    method.setAccessible(true);
    return (boolean) method.invoke(provider);
  }
}
