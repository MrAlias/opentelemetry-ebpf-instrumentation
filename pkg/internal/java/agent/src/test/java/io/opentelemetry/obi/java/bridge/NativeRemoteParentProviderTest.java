/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import org.junit.jupiter.api.Test;

class NativeRemoteParentProviderTest {
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
  void clearsSocketFileDescriptorWhenTransportIsUnavailable() {
    NativeRemoteParentProvider provider =
        new NativeRemoteParentProvider(
            RemoteParentTransport.DISABLED,
            "/tmp/obi-java.sock",
            50,
            0,
            (transport, path, timeout, uid, processIncarnation) -> RemoteParentStatus.DISABLED,
            () -> true);

    ThreadInfo.setRemoteParentSocketFileDescriptor(17);
    provider.takeRemoteParent();

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
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

    ThreadInfo.setRemoteParentSocketFileDescriptor(18);
    RemoteParentRecord record = provider.takeRemoteParent();

    assertEquals(RemoteParentStatus.OVERLOAD, record.getStatus());
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    provider.close();
  }

  @Test
  void clearsSocketFileDescriptorAfterNativeTerminalPath() {
    NativeRemoteParentProvider provider = readyProvider();

    ThreadInfo.setRemoteParentSocketFileDescriptor(1_000_000);
    provider.discardRemoteParent();

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    provider.close();
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
