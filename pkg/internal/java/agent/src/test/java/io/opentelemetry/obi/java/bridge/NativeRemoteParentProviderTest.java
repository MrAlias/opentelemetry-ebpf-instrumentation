/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.data.TaskContext;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class NativeRemoteParentProviderTest {
  @AfterEach
  void resetThreadInfo() throws Exception {
    ThreadInfo.setRemoteParentEnabled(false);
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    ThreadInfo.clearRemoteParentLookupSource();
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
  void ignoresStaleResponseWhenNativeCallFails() {
    byte[] staleResponse = validResponse();

    RemoteParentRecord transportError =
        NativeRemoteParentProvider.recordFromNativeResponse(
            RemoteParentStatus.TRANSPORT_ERROR, staleResponse);
    assertEquals(RemoteParentStatus.TRANSPORT_ERROR, transportError.getStatus());
    assertNull(transportError.getTraceIdHex());
    assertNull(transportError.getParentSpanIdHex());

    RemoteParentRecord missing =
        NativeRemoteParentProvider.recordFromNativeResponse(
            RemoteParentStatus.MISSING, staleResponse);
    assertEquals(RemoteParentStatus.MISSING, missing.getStatus());
    assertNull(missing.getTraceIdHex());
    assertNull(missing.getParentSpanIdHex());
  }

  @Test
  void requiresValidResponseForSuccessfulNativeCall() {
    assertEquals(
        RemoteParentStatus.VALID,
        NativeRemoteParentProvider.recordFromNativeResponse(
                RemoteParentStatus.VALID, validResponse())
            .getStatus());
    assertEquals(
        RemoteParentStatus.MALFORMED,
        NativeRemoteParentProvider.recordFromNativeResponse(
                RemoteParentStatus.VALID, new byte[RemoteParentRecord.RECORD_SIZE])
            .getStatus());
    assertEquals(
        RemoteParentStatus.MALFORMED,
        NativeRemoteParentProvider.recordFromNativeResponse(
                RemoteParentStatus.UNKNOWN, validResponse())
            .getStatus());
    assertEquals(
        RemoteParentStatus.MALFORMED,
        NativeRemoteParentProvider.recordFromNativeResponse(
                RemoteParentStatus.DISABLED + 1, validResponse())
            .getStatus());
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
              int status =
                  configurationAttempts.getAndIncrement() == 0
                      ? RemoteParentStatus.UNSUPPORTED
                      : RemoteParentStatus.VALID;
              return configurationResult(transport, status);
            },
            () -> {
              events.add("register");
              registrations.incrementAndGet();
              return true;
            });

    assertEquals(1, configurationAttempts.get());
    assertEquals(1, registrations.get());
    assertEquals(Arrays.asList("register", "configure"), events);
    assertEquals(
        RemoteParentStatus.UNSUPPORTED,
        RemoteParentTransportConfiguration.status(provider.transportConfiguration()));
    makeRetryEligible(provider);

    provider.takeRemoteParent();

    assertEquals(2, configurationAttempts.get());
    assertEquals(2, registrations.get());
    assertEquals(Arrays.asList("register", "configure", "register", "configure"), events);
    assertEquals(
        RemoteParentTransport.GETSOCKOPT,
        RemoteParentTransportConfiguration.selected(provider.transportConfiguration()));
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
              return configurationResult(transport, RemoteParentStatus.VALID);
            },
            () -> registrations.incrementAndGet() > 1);

    assertFalse(provider.isReady());
    assertEquals(1, registrations.get());
    assertEquals(0, configurationAttempts.get());
    assertEquals(
        RemoteParentStatus.UNAUTHORIZED,
        RemoteParentTransportConfiguration.status(provider.transportConfiguration()));
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
              return configurationResult(transport, RemoteParentStatus.VALID);
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
    assertEquals(
        RemoteParentStatus.VALID,
        RemoteParentTransportConfiguration.status(provider.transportConfiguration()));
    makeRetryEligible(provider);

    assertTrue(ensureReady(provider));
    assertEquals(2, registrations.get());
    assertEquals(2, configurationAttempts.get());
    provider.close();
  }

  @Test
  void publishesOnlyCompleteTransportConfigurationsDuringRecovery() throws Exception {
    AtomicInteger attempts = new AtomicInteger();
    NativeRemoteParentProvider provider =
        new NativeRemoteParentProvider(
            RemoteParentTransport.AUTO,
            "/tmp/obi-java.sock",
            50,
            0,
            (transport, path, timeout, uid, processIncarnation) ->
                attempts.getAndIncrement() == 0 ? 0x4f02000101010001L : 0x4f02010403020001L,
            () -> true);
    AtomicBoolean reading = new AtomicBoolean(true);
    AtomicReference<Long> unexpected = new AtomicReference<>();
    CountDownLatch primaryObserved = new CountDownLatch(1);
    CountDownLatch fallbackObserved = new CountDownLatch(1);
    Thread reader =
        new Thread(
            () -> {
              while (reading.get()) {
                long configuration = provider.transportConfiguration();
                if (configuration == 0x4f02000101010001L) {
                  primaryObserved.countDown();
                } else if (configuration == 0x4f02010403020001L) {
                  fallbackObserved.countDown();
                } else {
                  unexpected.compareAndSet(null, configuration);
                }
              }
            });
    reader.setDaemon(true);
    reader.start();

    try {
      assertTrue(primaryObserved.await(5, TimeUnit.SECONDS));
      markUnavailable(provider, RemoteParentStatus.UNAUTHORIZED);
      makeRetryEligible(provider);
      assertTrue(ensureReady(provider));
      assertTrue(fallbackObserved.await(5, TimeUnit.SECONDS));
    } finally {
      reading.set(false);
      reader.join(TimeUnit.SECONDS.toMillis(5));
      provider.close();
    }
    assertFalse(reader.isAlive());
    assertNull(unexpected.get());
    assertEquals(2, attempts.get());
    assertEquals(0x4f02010403020001L, provider.transportConfiguration());
  }

  @Test
  void diagnosticLoggingCannotInterruptInstallationOrRecovery() throws Exception {
    Logger providerLogger = Logger.getLogger(NativeRemoteParentProvider.class.getName());
    Level previousLevel = providerLogger.getLevel();
    AtomicReference<Throwable> loggingFailure =
        new AtomicReference<>(new IllegalStateException("broken application log handler"));
    Handler throwingHandler =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            Throwable failure = loggingFailure.get();
            if (failure instanceof Error) {
              throw (Error) failure;
            }
            throw (RuntimeException) failure;
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    throwingHandler.setLevel(Level.ALL);
    providerLogger.setLevel(Level.ALL);
    providerLogger.addHandler(throwingHandler);
    NativeRemoteParentProvider provider = null;
    try {
      AtomicInteger attempts = new AtomicInteger();
      provider =
          new NativeRemoteParentProvider(
              RemoteParentTransport.AUTO,
              "/tmp/obi-java.sock",
              50,
              0,
              (transport, path, timeout, uid, processIncarnation) ->
                  attempts.getAndIncrement() == 0 ? 0x4f02000101010001L : 0x4f02010403020001L,
              () -> true);

      assertTrue(provider.isReady());
      loggingFailure.set(new AssertionError("broken application log handler"));
      markUnavailable(provider, RemoteParentStatus.UNAUTHORIZED);
      makeRetryEligible(provider);

      assertTrue(ensureReady(provider));
      assertEquals(2, attempts.get());
      assertEquals(0x4f02010403020001L, provider.transportConfiguration());
    } finally {
      providerLogger.removeHandler(throwingHandler);
      providerLogger.setLevel(previousLevel);
      if (provider != null) {
        provider.close();
      }
    }
  }

  @Test
  void fallsBackToLegacyConfigurationWhenV2SymbolIsUnavailable() {
    AtomicInteger legacyCalls = new AtomicInteger();

    long configuration =
        NativeRemoteParentProvider.configureNativeTransport(
            RemoteParentTransport.AUTO,
            () -> {
              throw new UnsatisfiedLinkError("missing V2 symbol");
            },
            () -> {
              legacyCalls.incrementAndGet();
              return RemoteParentStatus.VALID;
            });

    assertEquals(1, legacyCalls.get());
    assertEquals(1, RemoteParentTransportConfiguration.version(configuration));
    assertEquals(
        RemoteParentStatus.VALID, RemoteParentTransportConfiguration.status(configuration));
    assertEquals(
        RemoteParentTransportConfiguration.NONE,
        RemoteParentTransportConfiguration.selected(configuration));
  }

  @Test
  void consumesSocketOwnershipWhenTransportIsUnavailable() throws Exception {
    NativeRemoteParentProvider provider =
        new NativeRemoteParentProvider(
            RemoteParentTransport.DISABLED,
            "/tmp/obi-java.sock",
            50,
            0,
            (transport, path, timeout, uid, processIncarnation) ->
                configurationResult(transport, RemoteParentStatus.DISABLED),
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

  @Test
  void primaryLookupKeepsSocketCloseFencedUntilItsNativeCallReturns() throws Exception {
    CountDownLatch nativeEntered = new CountDownLatch(1);
    CountDownLatch releaseNative = new CountDownLatch(1);
    CountDownLatch lookupFinished = new CountDownLatch(1);
    CountDownLatch closeFinished = new CountDownLatch(1);
    AtomicInteger observedSocketFileDescriptor = new AtomicInteger(-1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    AtomicReference<Object> closeLifecycle = new AtomicReference<>();
    NativeRemoteParentProvider provider =
        readyProvider(
            (take, taskScoped, socketFileDescriptor, response) -> {
              observedSocketFileDescriptor.set(socketFileDescriptor);
              nativeEntered.countDown();
              awaitUninterruptibly(releaseNative);
              return RemoteParentStatus.MISSING;
            });

    Socket socket = new Socket();
    try {
      Lifecycle lifecycle = (Lifecycle) SSLStorage.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(lifecycle);
      Thread lookup =
          new Thread(
              () -> {
                try {
                  assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(96, lifecycle));
                  assertEquals(RemoteParentStatus.MISSING, provider.takeRemoteParent().getStatus());
                } catch (Throwable thrown) {
                  failure.compareAndSet(null, thrown);
                } finally {
                  lookupFinished.countDown();
                }
              });
      lookup.start();
      assertTrue(nativeEntered.await(5, TimeUnit.SECONDS));

      Thread closer =
          new Thread(
              () -> {
                try {
                  closeLifecycle.set(BootstrapNative.beginRemoteParentSocketClose(socket));
                } catch (Throwable thrown) {
                  failure.compareAndSet(null, thrown);
                } finally {
                  closeFinished.countDown();
                }
              });
      closer.start();
      assertTrue(waitForInactive(lifecycle));
      assertFalse(closeFinished.await(250, TimeUnit.MILLISECONDS));

      releaseNative.countDown();
      assertTrue(lookupFinished.await(5, TimeUnit.SECONDS));
      assertTrue(closeFinished.await(5, TimeUnit.SECONDS));
      assertEquals(96, observedSocketFileDescriptor.get());
      assertNull(failure.get());
    } finally {
      releaseNative.countDown();
      Object lifecycle = closeLifecycle.get();
      if (lifecycle != null) {
        BootstrapNative.finishRemoteParentSocketClose(socket, lifecycle);
      }
      socket.close();
      provider.close();
    }
  }

  @Test
  void unixFallbackRejectsAnInvalidatedSocketContextBeforeCallingTheBroker() throws Exception {
    AtomicInteger calls = new AtomicInteger();
    NativeRemoteParentProvider provider =
        readyProvider(
            RemoteParentTransport.UNIX,
            (take, taskScoped, socketFileDescriptor, response) -> {
              calls.incrementAndGet();
              return RemoteParentStatus.MISSING;
            });

    try (Socket socket = new Socket()) {
      Lifecycle lifecycle = (Lifecycle) SSLStorage.prepareRemoteParentSocketLifecycle(socket);
      assertNotNull(lifecycle);
      assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(97, lifecycle));
      lifecycle.invalidate();

      assertEquals(RemoteParentStatus.MISSING, provider.takeRemoteParent().getStatus());
      assertEquals(0, calls.get());
    } finally {
      provider.close();
    }
  }

  @Test
  void routesLookupsOnlyToTheExplicitExecutionSource() throws Exception {
    List<Boolean> taskLookups = new ArrayList<>();
    NativeRemoteParentProvider provider =
        readyProvider(
            (take, taskScoped, socketFileDescriptor, response) -> {
              taskLookups.add(taskScoped);
              return RemoteParentStatus.MISSING;
            });

    setTaskContextEmitter((proxy, method, args) -> null);
    ThreadInfo.setRemoteParentEnabled(true);
    boolean entered = false;
    boolean receiving = false;
    try {
      provider.takeRemoteParent();

      entered = ThreadInfo.enterTaskParentThreadContext(900L, 101L, 42L);
      assertTrue(entered);
      provider.takeRemoteParent();

      ThreadInfo.markRemoteParentDirectLookup();
      provider.takeRemoteParent();
      provider.takeRemoteParent();

      ThreadInfo.beginRemoteParentReceiveScope();
      receiving = true;
      assertEquals(RemoteParentStatus.MISSING, provider.takeRemoteParent().getStatus());
      ThreadInfo.markRemoteParentDirectLookup();
      provider.takeRemoteParent();

      assertEquals(Arrays.asList(false, true, false, false, false), taskLookups);
    } finally {
      if (receiving) {
        ThreadInfo.endRemoteParentReceiveScope();
      }
      if (entered) {
        ThreadInfo.restoreTaskParentThreadContext();
      }
      provider.close();
    }
  }

  @Test
  void unixDirectOverrideSurvivesRetriesInsideAnExactTask() throws Exception {
    List<Boolean> taskLookups = new ArrayList<>();
    NativeRemoteParentProvider provider =
        readyProvider(
            RemoteParentTransport.UNIX,
            (take, taskScoped, socketFileDescriptor, response) -> {
              taskLookups.add(taskScoped);
              return RemoteParentStatus.MISSING;
            });

    setTaskContextEmitter((proxy, method, args) -> null);
    ThreadInfo.setRemoteParentEnabled(true);
    boolean entered = false;
    try {
      entered = ThreadInfo.enterTaskParentThreadContext(900L, 101L, 42L);
      assertTrue(entered);
      ThreadInfo.markRemoteParentDirectLookup();

      assertEquals(RemoteParentStatus.MISSING, provider.takeRemoteParent().getStatus());
      assertEquals(RemoteParentStatus.MISSING, provider.takeRemoteParent().getStatus());
      assertEquals(Arrays.asList(false, false), taskLookups);
    } finally {
      if (entered) {
        ThreadInfo.restoreTaskParentThreadContext();
      }
      provider.close();
    }
  }

  @Test
  void blockedLookupNeverCallsTheUnixBroker() {
    AtomicInteger calls = new AtomicInteger();
    NativeRemoteParentProvider provider =
        readyProvider(
            RemoteParentTransport.UNIX,
            (take, taskScoped, socketFileDescriptor, response) -> {
              calls.incrementAndGet();
              return RemoteParentStatus.VALID;
            });

    try {
      ThreadInfo.setRemoteParentSocketFileDescriptor(98);
      ThreadInfo.beginRemoteParentReceiveAttempt();

      assertEquals(RemoteParentStatus.MISSING, provider.takeRemoteParent().getStatus());
      assertEquals(0, calls.get());
      assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    } finally {
      provider.close();
    }
  }

  @Test
  void invalidatedDescriptorlessLifecycleBlocksDirectAndTaskUnixLookups() throws Exception {
    AtomicInteger calls = new AtomicInteger();
    NativeRemoteParentProvider provider =
        readyProvider(
            RemoteParentTransport.UNIX,
            (take, taskScoped, socketFileDescriptor, response) -> {
              calls.incrementAndGet();
              return RemoteParentStatus.VALID;
            });
    Lifecycle direct = new Lifecycle();

    setTaskContextEmitter((proxy, method, args) -> null);
    ThreadInfo.setRemoteParentEnabled(true);
    boolean entered = false;
    try {
      ThreadInfo.markRemoteParentDirectLookup(direct);
      direct.invalidate();
      assertEquals(RemoteParentStatus.MISSING, provider.takeRemoteParent().getStatus());

      Lifecycle task = new Lifecycle();
      entered = ThreadInfo.enterTaskParentThreadContext(900L, 101L, 42L, null, task);
      assertTrue(entered);
      task.invalidate();
      assertEquals(RemoteParentStatus.MISSING, provider.takeRemoteParent().getStatus());
      assertEquals(0, calls.get());
    } finally {
      if (entered) {
        ThreadInfo.restoreTaskParentThreadContext();
      }
      provider.close();
    }
  }

  @Test
  void descriptorlessUnixLookupHoldsTheLifecycleLeaseUntilNativeReturns() throws Exception {
    CountDownLatch nativeEntered = new CountDownLatch(1);
    CountDownLatch releaseNative = new CountDownLatch(1);
    CountDownLatch lookupFinished = new CountDownLatch(1);
    CountDownLatch invalidationFinished = new CountDownLatch(1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Lifecycle lifecycle = new Lifecycle();
    NativeRemoteParentProvider provider =
        readyProvider(
            RemoteParentTransport.UNIX,
            (take, taskScoped, socketFileDescriptor, response) -> {
              nativeEntered.countDown();
              awaitUninterruptibly(releaseNative);
              return RemoteParentStatus.MISSING;
            });
    ThreadInfo.markRemoteParentDirectLookup(lifecycle);

    Thread lookup =
        new Thread(
            () -> {
              try {
                ThreadInfo.markRemoteParentDirectLookup(lifecycle);
                provider.takeRemoteParent();
              } catch (Throwable thrown) {
                failure.set(thrown);
              } finally {
                lookupFinished.countDown();
              }
            });
    Thread invalidator =
        new Thread(
            () -> {
              lifecycle.invalidate();
              invalidationFinished.countDown();
            });

    try {
      lookup.start();
      assertTrue(nativeEntered.await(5, TimeUnit.SECONDS));
      invalidator.start();
      assertFalse(invalidationFinished.await(250, TimeUnit.MILLISECONDS));

      releaseNative.countDown();
      assertTrue(lookupFinished.await(5, TimeUnit.SECONDS));
      assertTrue(invalidationFinished.await(5, TimeUnit.SECONDS));
      assertNull(failure.get());
    } finally {
      releaseNative.countDown();
      lookup.join(TimeUnit.SECONDS.toMillis(5));
      invalidator.join(TimeUnit.SECONDS.toMillis(5));
      provider.close();
    }
  }

  private static TaskContext captureSocketAlias(int socketFileDescriptor) throws Exception {
    setTaskContextEmitter((proxy, method, args) -> null);
    ThreadInfo.setRemoteParentEnabled(true);
    Lifecycle lifecycle = new Lifecycle();
    ThreadInfo.setRemoteParentSocketFileDescriptor(socketFileDescriptor, lifecycle);
    ThreadInfo.markRemoteParentDirectLookup(lifecycle);
    return ThreadInfo.captureTaskContext(101L, lifecycle);
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
    return readyProvider(
        (take, taskScoped, socketFileDescriptor, response) -> {
          if (taskScoped) {
            return take
                ? BootstrapNative.takeRemoteParentTask(socketFileDescriptor, response)
                : BootstrapNative.discardRemoteParentTask(socketFileDescriptor, response);
          }
          return take
              ? BootstrapNative.takeRemoteParent(socketFileDescriptor, response)
              : BootstrapNative.discardRemoteParent(socketFileDescriptor, response);
        });
  }

  private static NativeRemoteParentProvider readyProvider(
      NativeRemoteParentProvider.SocketCaller socketCaller) {
    return readyProvider(RemoteParentTransport.GETSOCKOPT, socketCaller);
  }

  private static NativeRemoteParentProvider readyProvider(
      int requestedTransport, NativeRemoteParentProvider.SocketCaller socketCaller) {
    return new NativeRemoteParentProvider(
        requestedTransport,
        "/tmp/obi-java.sock",
        50,
        0,
        (transport, path, timeout, uid, processIncarnation) ->
            configurationResult(transport, RemoteParentStatus.VALID),
        () -> true,
        socketCaller);
  }

  private static void awaitUninterruptibly(CountDownLatch latch) {
    boolean interrupted = false;
    while (true) {
      try {
        latch.await();
        break;
      } catch (InterruptedException ignored) {
        interrupted = true;
      }
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
  }

  private static boolean waitForInactive(Lifecycle lifecycle) {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (lifecycle.active() && System.nanoTime() - deadline < 0) {
      Thread.yield();
    }
    return !lifecycle.active();
  }

  private static byte[] validResponse() {
    byte[] response = new byte[RemoteParentRecord.RECORD_SIZE];
    response[0] = 'O';
    response[1] = 'B';
    response[2] = 'I';
    response[3] = 'J';
    response[4] = (byte) RemoteParentRecord.ABI_VERSION;
    response[6] = RemoteParentRecord.RECORD_SIZE;
    response[8] = RemoteParentStatus.VALID;
    response[9] = 1;
    response[16] = 1;
    response[32] = 1;
    response[40] = 1;
    response[48] = 1;
    return response;
  }

  private static long configurationResult(int requested, int status) {
    if (status == RemoteParentStatus.VALID) {
      if (requested == RemoteParentTransport.AUTO) {
        return 0x4f02000101010001L;
      }
      if (requested == RemoteParentTransport.GETSOCKOPT) {
        return 0x4f02000101010101L;
      }
      if (requested == RemoteParentTransport.UNIX) {
        return 0x4f02010002020201L;
      }
    }
    if (status == RemoteParentStatus.DISABLED && requested == RemoteParentTransport.DISABLED) {
      return RemoteParentTransportConfiguration.disabled();
    }
    if (status == RemoteParentStatus.UNSUPPORTED && requested == RemoteParentTransport.AUTO) {
      return 0x4f02000401ff0004L;
    }
    return RemoteParentTransportConfiguration.failure(requested, status);
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
