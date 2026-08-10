/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.example.obi.java21.probe;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/** Java 21 runtime probe for exact mixed virtual-thread and platform-thread handoffs. */
public final class OfficialAgentJava21ConcurrencyProbe {
  private static final int VIRTUAL_TASKS = 16;
  private static final int PLATFORM_TASKS = 4;
  private static final int RELAY_TASKS = 4;
  private static final int RELAY_VIRTUAL_TASKS = 2;
  private static final int CARRIERS = 4;
  private static final int PLATFORM_WORKERS = 4;
  private static final int FIRST_SOCKET_FILE_DESCRIPTOR = 200;
  private static final int EVENT_MAP_CAPACITY =
      Math.max(
          (VIRTUAL_TASKS * 2) + RELAY_VIRTUAL_TASKS, VIRTUAL_TASKS + PLATFORM_TASKS + RELAY_TASKS);
  private static final long TIMEOUT_SECONDS = 10L;
  private static final String VIRTUAL = "VIRTUAL";
  private static final String PLATFORM = "PLATFORM";
  private static final String CARRIER = "CARRIER";
  private static final String HEADER = "x-obi-probe-id";

  private static final TextMapGetter<String> ID_GETTER =
      new TextMapGetter<String>() {
        @Override
        public Iterable<String> keys(String carrier) {
          return Collections.singletonList(HEADER);
        }

        @Override
        public String get(String carrier, String key) {
          return HEADER.equalsIgnoreCase(key) ? carrier : null;
        }
      };

  private static final ThreadLocal<TaskLabel> ACTIVE_SUBMISSION = new ThreadLocal<TaskLabel>();
  private static final ConcurrentMap<Long, TaskCapture> CAPTURES =
      new ConcurrentHashMap<Long, TaskCapture>(EVENT_MAP_CAPACITY);
  private static final ConcurrentMap<Long, TaskCapture> PENDING =
      new ConcurrentHashMap<Long, TaskCapture>(EVENT_MAP_CAPACITY);
  private static final ConcurrentMap<String, TaskCompletion> COMPLETIONS =
      new ConcurrentHashMap<String, TaskCompletion>(EVENT_MAP_CAPACITY);
  private static final ConcurrentMap<Long, TaskCapture> TERMINAL_CANCELLATIONS =
      new ConcurrentHashMap<Long, TaskCapture>(EVENT_MAP_CAPACITY);
  private static final ConcurrentLinkedQueue<TaskEvent> TASK_EVENTS =
      new ConcurrentLinkedQueue<TaskEvent>();
  private static final AtomicLong EVENT_SEQUENCE = new AtomicLong();
  private static final AtomicReference<Throwable> EVENT_FAILURE = new AtomicReference<Throwable>();

  private static final Set<Long> KNOWN_VIRTUAL_THREADS =
      Collections.newSetFromMap(new ConcurrentHashMap<Long, Boolean>(EVENT_MAP_CAPACITY));
  private static final ConcurrentMap<Long, String> VIRTUAL_THREAD_IDS =
      new ConcurrentHashMap<Long, String>(EVENT_MAP_CAPACITY);
  private static final ConcurrentMap<Long, Long> MOUNTED_VIRTUAL_BY_NATIVE =
      new ConcurrentHashMap<Long, Long>(EVENT_MAP_CAPACITY);
  private static final ConcurrentMap<Long, AtomicInteger> VIRTUAL_MOUNTS =
      new ConcurrentHashMap<Long, AtomicInteger>(EVENT_MAP_CAPACITY);
  private static final ConcurrentMap<Long, AtomicInteger> VIRTUAL_UNMOUNTS =
      new ConcurrentHashMap<Long, AtomicInteger>(EVENT_MAP_CAPACITY);
  private static final ConcurrentMap<Long, AtomicInteger> VIRTUAL_TERMINATIONS =
      new ConcurrentHashMap<Long, AtomicInteger>(EVENT_MAP_CAPACITY);
  private static final ConcurrentMap<Long, AtomicLong> FIRST_VIRTUAL_MOUNT_SEQUENCE =
      new ConcurrentHashMap<Long, AtomicLong>(EVENT_MAP_CAPACITY);

  private static volatile Method getTid;
  private static volatile Field carrierThreadField;

  private OfficialAgentJava21ConcurrencyProbe() {}

  public static void main(String[] args) throws Exception {
    require(javaFeatureVersion() == 21, "Java 21 is required");
    // The test emitter runs inline from VirtualThread.mount, where map initialization must not
    // yield.
    initializeConcurrentEventMaps();
    HelperFixture fixture = HelperFixture.install();
    List<ExactNettyConnection> connections = new ArrayList<ExactNettyConnection>();
    try {
      installVirtualThreadReflection();
      // Force official-agent autoconfiguration before worker baselines are captured.
      GlobalOpenTelemetry.get().getPropagators().getTextMapPropagator();
      DeterministicVirtualScheduler scheduler = new DeterministicVirtualScheduler(CARRIERS);
      DeterministicPlatformExecutor platform = new DeterministicPlatformExecutor(PLATFORM_WORKERS);
      try {
        platform.warmup();
        Map<String, WorkerBaseline> baselines = captureWorkerBaselines(scheduler, platform);
        List<PlatformSubmission> reusablePlatformTasks = reusablePlatformTasks();

        EventBoundary firstStart = EventBoundary.current();
        WaveResult first =
            runWave(1, true, scheduler, platform, reusablePlatformTasks, connections);
        EventBoundary firstEnd = EventBoundary.current();
        verifyFirstWaveEvents(first, firstStart, firstEnd);
        verifyVirtualLifecycle(first);
        verifyWorkerCleanup(1, scheduler, platform, baselines);
        closeConnections(connections);

        EventBoundary secondStart = EventBoundary.current();
        WaveResult second =
            runWave(2, false, scheduler, platform, reusablePlatformTasks, connections);
        EventBoundary secondEnd = EventBoundary.current();
        verifySecondWaveEvents(secondStart, secondEnd);
        verifyVirtualLifecycle(second);
        verifyReuse(first, second, scheduler, platform);
        verifyWorkerCleanup(2, scheduler, platform, baselines);

        Throwable eventFailure = EVENT_FAILURE.get();
        if (eventFailure != null) {
          throw new IllegalStateException("Java 21 task-event ledger failed", eventFailure);
        }
        require(PENDING.isEmpty(), "Java 21 task captures remained pending: " + PENDING.keySet());
        require(MOUNTED_VIRTUAL_BY_NATIVE.isEmpty(), "a carrier retained a mounted virtual thread");
        require(
            CAPTURES.size() == VIRTUAL_TASKS + PLATFORM_TASKS + RELAY_TASKS,
            "capture total mismatch");
        require(
            COMPLETIONS.size() == VIRTUAL_TASKS + PLATFORM_TASKS + RELAY_TASKS,
            "link total mismatch");
        require(scheduler.failure() == null, "virtual scheduler failed: " + scheduler.failure());
        require(platform.failure() == null, "platform executor failed: " + platform.failure());

        System.out.println(
            "OBI_JAVA21_PROBE\tpassed\tvirtual=34\tplatform=10\tcaptures=24\tlinks=24"
                + "\trelays=4\tcarriers=4\tworkers=4");
      } finally {
        try {
          platform.close();
        } finally {
          scheduler.close();
        }
      }
    } finally {
      try {
        closeConnections(connections);
      } finally {
        fixture.close();
      }
    }
  }

  private static void initializeConcurrentEventMaps() {
    Long sentinel = Long.valueOf(Long.MIN_VALUE);
    TaskLabel label = new TaskLabel("EVENT_MAP_WARMUP", false, -1L, -1L, null);
    TaskCapture capture = new TaskCapture(label, "EVENT_MAP_WARMUP", -1L, -1L, -1L);
    TaskCompletion completion = new TaskCompletion(capture, -1L, -1L, -1L, -1L);

    initializeConcurrentMap(CAPTURES, sentinel, capture);
    initializeConcurrentMap(PENDING, sentinel, capture);
    initializeConcurrentMap(COMPLETIONS, label.id, completion);
    initializeConcurrentMap(TERMINAL_CANCELLATIONS, sentinel, capture);
    initializeConcurrentMap(MOUNTED_VIRTUAL_BY_NATIVE, sentinel, sentinel);
    initializeConcurrentMap(VIRTUAL_MOUNTS, sentinel, new AtomicInteger());
    initializeConcurrentMap(VIRTUAL_UNMOUNTS, sentinel, new AtomicInteger());
    initializeConcurrentMap(VIRTUAL_TERMINATIONS, sentinel, new AtomicInteger());
    initializeConcurrentMap(FIRST_VIRTUAL_MOUNT_SEQUENCE, sentinel, new AtomicLong());
  }

  private static <K, V> void initializeConcurrentMap(ConcurrentMap<K, V> map, K key, V value) {
    require(map.putIfAbsent(key, value) == null, "event-map warmup collision");
    require(map.remove(key, value), "event-map warmup cleanup failed");
  }

  private static List<PlatformSubmission> reusablePlatformTasks() {
    List<PlatformSubmission> result = new ArrayList<PlatformSubmission>();
    for (int index = 0; index < PLATFORM_TASKS; index++) {
      result.add(new PlatformSubmission(index));
    }
    return result;
  }

  private static WaveResult runWave(
      int wave,
      boolean exact,
      DeterministicVirtualScheduler scheduler,
      DeterministicPlatformExecutor platform,
      List<PlatformSubmission> reusablePlatformTasks,
      List<ExactNettyConnection> connections)
      throws Exception {
    System.out.println("OBI_JAVA21_WAVE\t" + wave + "\tSTART");
    WaveControl control = new WaveControl();
    AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
    List<TaskDescriptor> virtual = new ArrayList<TaskDescriptor>();
    List<TaskDescriptor> platformTasks = new ArrayList<TaskDescriptor>();
    RelayControl relayControl = exact ? new RelayControl(failure) : null;
    long schedulerStart = scheduler.completedContinuations();
    long platformStart = platform.completedTasks();
    boolean completed = false;
    try {
      for (int index = 0; index < VIRTUAL_TASKS; index++) {
        String id = id(wave, true, index);
        ProbeTask task = new ProbeTask(id, wave, true, index, control, failure);
        Thread thread = newVirtualThread(scheduler, "obi-java21-" + id, task);
        task.setVirtualThread(thread);
        registerVirtualThread(thread, id);
        virtual.add(new TaskDescriptor(task, thread, null));
      }
      for (int index = 0; index < PLATFORM_TASKS; index++) {
        String id = id(wave, false, index);
        ProbeTask task =
            new ProbeTask(
                id, wave, false, index, control, failure, relayControl, scheduler, platform);
        PlatformSubmission submission = reusablePlatformTasks.get(index);
        submission.prepare(task);
        platformTasks.add(new TaskDescriptor(task, null, submission));
      }

      List<TaskDescriptor> all = new ArrayList<TaskDescriptor>();
      all.addAll(virtual);
      all.addAll(platformTasks);
      for (TaskDescriptor descriptor : all) {
        if (exact) {
          ExactNettyConnection connection =
              new ExactNettyConnection(descriptor.task.expectedSocketFileDescriptor());
          connections.add(connection);
          descriptor.connection = connection;
          descriptor.task.expectedLifecycleIdentity = connection.lifecycleIdentity();
          System.out.println(
              "OBI_JAVA21_OWNER\t"
                  + descriptor.task.id
                  + "\t"
                  + wave
                  + "\t"
                  + descriptor.task.kind()
                  + "\t"
                  + descriptor.task.expectedSocketFileDescriptor()
                  + "\t"
                  + descriptor.task.expectedLifecycleIdentity
                  + "\t"
                  + descriptor.task.expectedTraceId()
                  + "\t"
                  + descriptor.task.expectedParentSpanId()
                  + "\t"
                  + descriptor.taskIdentity());
          connection.stage(
              new CheckedRunnable() {
                @Override
                public void run() throws Exception {
                  submit(descriptor, scheduler, platform, true);
                }
              });
        } else {
          System.out.println(
              "OBI_JAVA21_OWNER\t"
                  + descriptor.task.id
                  + "\t"
                  + wave
                  + "\t"
                  + descriptor.task.kind()
                  + "\t-1\t0\t-\t-\t"
                  + descriptor.taskIdentity());
          submit(descriptor, scheduler, platform, false);
        }
      }

      await(control.initiallyParked, "wave " + wave + " initial virtual parks");
      scheduler.awaitContinuations(
          schedulerStart + VIRTUAL_TASKS, "wave " + wave + " initial virtual unmounts");
      control.migrationReleased.set(true);
      for (TaskDescriptor descriptor : virtual) {
        LockSupport.unpark(descriptor.virtualThread);
      }
      await(control.migrated, "wave " + wave + " virtual migrations");
      await(control.ready, "wave " + wave + " task readiness");
      scheduler.awaitContinuations(
          schedulerStart + (VIRTUAL_TASKS * 2L), "wave " + wave + " release-gate unmounts");
      System.out.println("OBI_JAVA21_WAVE\t" + wave + "\tRELEASE");
      control.release.countDown();

      await(control.finished, "wave " + wave + " task completion");
      List<RelayDescriptor> relays = Collections.emptyList();
      if (relayControl != null) {
        await(relayControl.finished, "wave " + wave + " downstream relay completion");
        relays = relayControl.descriptors();
      }
      for (TaskDescriptor descriptor : virtual) {
        descriptor.virtualThread.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
        require(
            !descriptor.virtualThread.isAlive(),
            "virtual task did not terminate: " + descriptor.task.id);
      }
      for (RelayDescriptor relay : relays) {
        if (relay.virtualThread != null) {
          relay.virtualThread.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
          require(!relay.virtualThread.isAlive(), "relay did not terminate: " + relay.task.id);
        }
      }
      scheduler.awaitContinuations(
          schedulerStart + (VIRTUAL_TASKS * 3L) + (exact ? RELAY_VIRTUAL_TASKS : 0L),
          "wave " + wave + " terminal unmounts");
      platform.awaitCompleted(
          platformStart + PLATFORM_TASKS + (exact ? RELAY_TASKS - RELAY_VIRTUAL_TASKS : 0L),
          "wave " + wave + " platform tasks");
      Throwable problem = failure.get();
      if (problem != null) {
        throw new IllegalStateException("wave " + wave + " task failed", problem);
      }
      require(scheduler.failure() == null, "wave " + wave + " scheduler failure");
      require(platform.failure() == null, "wave " + wave + " platform failure");

      for (TaskDescriptor descriptor : all) {
        Object tracked = descriptor.trackedTask();
        require(taskContext(tracked) == null, descriptor.task.id + " retained a task context");
      }
      for (RelayDescriptor relay : relays) {
        require(
            taskContext(relay.trackedTask()) == null, relay.task.id + " retained a task context");
      }
      System.out.println("OBI_JAVA21_WAVE\t" + wave + "\tEND");
      completed = true;
      return new WaveResult(wave, virtual, platformTasks, relays);
    } finally {
      if (!completed) {
        control.migrationReleased.set(true);
        control.release.countDown();
        for (TaskDescriptor descriptor : virtual) {
          descriptor.virtualThread.interrupt();
          LockSupport.unpark(descriptor.virtualThread);
        }
      }
    }
  }

  private static void submit(
      TaskDescriptor descriptor,
      DeterministicVirtualScheduler scheduler,
      DeterministicPlatformExecutor platform,
      boolean expectCapture)
      throws Exception {
    require(ACTIVE_SUBMISSION.get() == null, "nested Java 21 task submission label");
    TaskLabel label =
        new TaskLabel(
            descriptor.task.id,
            descriptor.task.virtual,
            descriptor.virtualThread == null ? 0L : descriptor.virtualThread.getId(),
            nativeThreadId(),
            expectCapture ? "TASK_CAPTURE" : null);
    descriptor.label = label;
    ACTIVE_SUBMISSION.set(label);
    try {
      if (descriptor.virtualThread != null) {
        descriptor.virtualThread.start();
      } else {
        platform.execute(descriptor.platformSubmission);
      }
    } finally {
      ACTIVE_SUBMISSION.remove();
    }
  }

  private static void registerVirtualThread(Thread thread, String id) {
    Long threadId = Long.valueOf(thread.getId());
    require(KNOWN_VIRTUAL_THREADS.add(threadId), "duplicate virtual thread id " + threadId);
    require(
        VIRTUAL_THREAD_IDS.putIfAbsent(threadId, id) == null,
        "duplicate virtual thread label " + threadId);
  }

  private static void verifyFirstWaveEvents(
      WaveResult wave, EventBoundary start, EventBoundary end) {
    Throwable failure = EVENT_FAILURE.get();
    if (failure != null) {
      throw new IllegalStateException("Java 21 first-wave event ledger failed", failure);
    }
    require(end.taskCaptures - start.taskCaptures == 20L, "first-wave capture count mismatch");
    require(
        end.taskRelayCaptures - start.taskRelayCaptures == RELAY_TASKS,
        "first-wave relay capture count mismatch");
    require(end.taskLinks - start.taskLinks == 24L, "first-wave link count mismatch");
    require(end.taskCancels - start.taskCancels == 24L, "first-wave terminal cancellation count");
    require(end.taskUnlinks == start.taskUnlinks, "first-wave task unlink");
    require(PENDING.isEmpty(), "first-wave captures remained pending");

    List<TaskDescriptor> descriptors = wave.all();
    Collections.sort(
        descriptors,
        new Comparator<TaskDescriptor>() {
          @Override
          public int compare(TaskDescriptor left, TaskDescriptor right) {
            return left.task.id.compareTo(right.task.id);
          }
        });
    for (TaskDescriptor descriptor : descriptors) {
      TaskCompletion completion = COMPLETIONS.get(descriptor.task.id);
      require(completion != null, "missing task edge for " + descriptor.task.id);
      TaskCapture capture = completion.capture;
      require("TASK_CAPTURE".equals(capture.operation), "wrong capture operation");
      require(capture.token != 0L, "zero task capture token");
      require(
          capture.captureNativeThreadId == descriptor.label.sourceNativeThreadId,
          "capture TID changed");
      require(
          completion.linkParentThreadId == capture.captureNativeThreadId, "link parent mismatch");
      require(
          completion.linkChildThreadId == descriptor.task.firstExecutionNativeThreadId,
          "link child mismatch");
      require(
          completion.linkChildJavaThreadId == descriptor.task.taskJavaThreadId,
          "link Java thread mismatch");
      require(capture.sequence < completion.sequence, "link preceded capture");
      require(
          TERMINAL_CANCELLATIONS.get(Long.valueOf(capture.token)) == capture,
          "missing terminal task cancellation for " + descriptor.task.id);
      if (descriptor.task.virtual) {
        AtomicLong mount =
            FIRST_VIRTUAL_MOUNT_SEQUENCE.get(Long.valueOf(descriptor.task.taskJavaThreadId));
        require(
            mount != null && mount.get() < completion.sequence,
            "virtual mount did not precede link");
      }
      System.out.println(
          "OBI_JAVA21_EDGE\t"
              + descriptor.task.id
              + "\t"
              + capture.operation
              + "\t"
              + capture.token
              + "\t"
              + capture.captureNativeThreadId
              + "\t"
              + completion.linkParentThreadId
              + "\t"
              + completion.linkChildThreadId
              + "\t"
              + capture.sequence
              + "\t"
              + completion.sequence
              + "\t"
              + completion.linkChildJavaThreadId);
    }
    for (RelayDescriptor descriptor : wave.relays) {
      TaskCompletion completion = COMPLETIONS.get(descriptor.task.id);
      require(completion != null, "missing relay edge for " + descriptor.task.id);
      TaskCapture capture = completion.capture;
      require("TASK_RELAY_CAPTURE".equals(capture.operation), "wrong relay capture operation");
      require(capture.token != 0L, "zero relay capture token");
      require(
          capture.captureNativeThreadId == descriptor.task.parent.bodyCarrier.nativeThreadId,
          "relay capture TID changed");
      require(
          completion.linkParentThreadId == capture.captureNativeThreadId,
          "relay link parent mismatch");
      require(
          completion.linkChildThreadId == descriptor.task.firstExecutionNativeThreadId,
          "relay link child mismatch");
      require(
          completion.linkChildJavaThreadId == descriptor.task.taskJavaThreadId,
          "relay link Java thread mismatch");
      TaskCompletion parentCompletion = COMPLETIONS.get(descriptor.task.parent.id);
      require(parentCompletion != null, "missing relay parent edge " + descriptor.task.parent.id);
      require(
          parentCompletion.linkChildThreadId == capture.captureNativeThreadId,
          "relay capture did not originate on its parent execution");
      require(
          parentCompletion.sequence < capture.sequence,
          "relay capture preceded its parent task link");
      require(capture.sequence < completion.sequence, "relay link preceded capture");
      require(
          TERMINAL_CANCELLATIONS.get(Long.valueOf(capture.token)) == capture,
          "missing terminal relay cancellation for " + descriptor.task.id);
      if (descriptor.virtualThread != null) {
        AtomicLong mount =
            FIRST_VIRTUAL_MOUNT_SEQUENCE.get(Long.valueOf(descriptor.task.taskJavaThreadId));
        require(
            mount != null && mount.get() < completion.sequence,
            "relay virtual mount did not precede link");
      }
      System.out.println(
          "OBI_JAVA21_EDGE\t"
              + descriptor.task.id
              + "\t"
              + capture.operation
              + "\t"
              + capture.token
              + "\t"
              + capture.captureNativeThreadId
              + "\t"
              + completion.linkParentThreadId
              + "\t"
              + completion.linkChildThreadId
              + "\t"
              + capture.sequence
              + "\t"
              + completion.sequence
              + "\t"
              + completion.linkChildJavaThreadId);
    }
  }

  private static void verifySecondWaveEvents(EventBoundary start, EventBoundary end) {
    Throwable failure = EVENT_FAILURE.get();
    if (failure != null) {
      throw new IllegalStateException("Java 21 reuse-wave event ledger failed", failure);
    }
    require(end.taskCaptures == start.taskCaptures, "reuse wave captured strict task context");
    require(
        end.taskRelayCaptures == start.taskRelayCaptures,
        "reuse wave captured strict relay context");
    require(end.taskLinks == start.taskLinks, "reuse wave linked strict task context");
    require(end.taskCancels == start.taskCancels, "reuse wave cancelled strict task context");
    require(end.taskUnlinks == start.taskUnlinks, "reuse wave unlinked strict task context");
  }

  private static void verifyVirtualLifecycle(WaveResult wave) {
    for (TaskDescriptor descriptor : wave.virtual) {
      verifyVirtualLifecycle(descriptor.task.id, descriptor.virtualThread, 3);
    }
    for (RelayDescriptor descriptor : wave.relays) {
      if (descriptor.virtualThread != null) {
        verifyVirtualLifecycle(descriptor.task.id, descriptor.virtualThread, 1);
      }
    }
    require(MOUNTED_VIRTUAL_BY_NATIVE.isEmpty(), "wave retained a mounted virtual thread");
  }

  private static void verifyVirtualLifecycle(String id, Thread thread, int minimumMounts) {
    long threadId = thread.getId();
    int mounts = counter(VIRTUAL_MOUNTS, threadId);
    int unmounts = counter(VIRTUAL_UNMOUNTS, threadId);
    int terminations = counter(VIRTUAL_TERMINATIONS, threadId);
    require(mounts >= minimumMounts, id + " did not mount for every forced phase");
    require(unmounts == mounts, id + " mount/unmount count mismatch");
    require(terminations == 1, id + " termination count mismatch");
    System.out.println(
        "OBI_JAVA21_VIRTUAL\t" + id + "\t" + mounts + "\t" + unmounts + "\t" + terminations);
  }

  private static void verifyReuse(
      WaveResult first,
      WaveResult second,
      DeterministicVirtualScheduler scheduler,
      DeterministicPlatformExecutor platform) {
    require(first.virtualCarrierThreads().size() == CARRIERS, "first wave carrier count mismatch");
    require(second.virtualCarrierThreads().size() == CARRIERS, "reuse carrier count mismatch");
    require(
        first.virtualCarrierThreads().equals(second.virtualCarrierThreads()),
        "reuse wave did not use the same carrier set");
    require(first.platformThreads().size() == PLATFORM_WORKERS, "first platform worker mismatch");
    require(second.platformThreads().size() == PLATFORM_WORKERS, "reuse platform worker mismatch");
    require(
        first.platformThreads().equals(second.platformThreads()),
        "reuse wave did not use the same platform workers");
    for (int index = 0; index < PLATFORM_TASKS; index++) {
      require(
          first.platform.get(index).platformSubmission
              == second.platform.get(index).platformSubmission,
          "reuse wave changed platform task identity " + index);
    }
    require(
        first.virtualCarrierThreads().equals(scheduler.javaThreadIds()),
        "wave did not exercise every deterministic carrier");
    require(
        first.platformThreads().equals(platform.javaThreadIds()),
        "wave did not exercise every deterministic platform worker");
  }

  private static Map<String, WorkerBaseline> captureWorkerBaselines(
      DeterministicVirtualScheduler scheduler, DeterministicPlatformExecutor platform)
      throws Exception {
    final Map<String, WorkerBaseline> baselines = new ConcurrentHashMap<String, WorkerBaseline>();
    for (int index = 0; index < CARRIERS; index++) {
      final int worker = index;
      scheduler.runDirect(
          worker,
          new CheckedRunnable() {
            @Override
            public void run() throws Exception {
              captureWorkerBaseline(baselines, CARRIER, worker);
            }
          });
    }
    for (int index = 0; index < PLATFORM_WORKERS; index++) {
      final int worker = index;
      platform.runDirect(
          worker,
          new CheckedRunnable() {
            @Override
            public void run() throws Exception {
              captureWorkerBaseline(baselines, PLATFORM, worker);
            }
          });
    }
    require(baselines.size() == CARRIERS + PLATFORM_WORKERS, "worker baseline count mismatch");
    return baselines;
  }

  private static void captureWorkerBaseline(
      Map<String, WorkerBaseline> baselines, String kind, int index) throws Exception {
    Authority authority = Authority.current();
    assertTransportAuthorityAbsent(authority, kind + " baseline " + index);
    WorkerBaseline baseline =
        new WorkerBaseline(Thread.currentThread().getId(), nativeThreadId(), authority);
    require(
        baselines.put(workerKey(kind, index), baseline) == null,
        "duplicate worker baseline " + kind + '/' + index);
    System.out.println(
        "OBI_JAVA21_BASELINE\t"
            + kind
            + "\t"
            + index
            + "\t"
            + baseline.javaThreadId
            + "\t"
            + baseline.nativeThreadId);
  }

  private static void verifyWorkerCleanup(
      int wave,
      DeterministicVirtualScheduler scheduler,
      DeterministicPlatformExecutor platform,
      final Map<String, WorkerBaseline> baselines)
      throws Exception {
    for (int index = 0; index < CARRIERS; index++) {
      final int worker = index;
      scheduler.runDirect(
          worker,
          new CheckedRunnable() {
            @Override
            public void run() throws Exception {
              verifyWorkerCleanup(wave, CARRIER, worker, baselines);
            }
          });
    }
    for (int index = 0; index < PLATFORM_WORKERS; index++) {
      final int worker = index;
      platform.runDirect(
          worker,
          new CheckedRunnable() {
            @Override
            public void run() throws Exception {
              verifyWorkerCleanup(wave, PLATFORM, worker, baselines);
            }
          });
    }
  }

  private static void verifyWorkerCleanup(
      int wave, String kind, int index, Map<String, WorkerBaseline> baselines) throws Exception {
    Authority authority = Authority.current();
    WorkerBaseline baseline = baselines.get(workerKey(kind, index));
    require(baseline != null, "missing worker baseline " + kind + '/' + index);
    assertTransportAuthorityAbsent(authority, kind + " cleanup " + index);
    require(Thread.currentThread().getId() == baseline.javaThreadId, "cleanup Java worker changed");
    require(nativeThreadId() == baseline.nativeThreadId, "cleanup native worker changed");
    require(authority.source == baseline.lookupSource, "lookup source baseline changed");
    require(
        Objects.equals(authority.lookupOverride, baseline.lookupOverride),
        "raw lookup override baseline changed");
    require(
        Objects.equals(authority.receiveEpochValue, baseline.receiveEpochValue),
        "receive epoch baseline changed");
    require(
        authority.sslStorageThreadLocalState.equals(baseline.sslStorageThreadLocalState),
        "SSLStorage baseline changed");
    System.out.println(
        "OBI_JAVA21_CLEANUP\t"
            + wave
            + "\t"
            + kind
            + "\t"
            + index
            + "\t"
            + baseline.javaThreadId
            + "\t"
            + baseline.nativeThreadId
            + "\t"
            + authority.source
            + "\t"
            + authority.directAuthority
            + "\tNONE\t"
            + authority.socketFileDescriptor
            + "\t"
            + authority.exactTaskRelayState
            + "\ttrue\t"
            + authority.socketContextPresent
            + "\t"
            + authority.receiveDepth
            + "\t"
            + (authority.sslStorageThreadLocalState.isEmpty()
                ? "NONE"
                : authority.sslStorageThreadLocalState));
  }

  private static void assertTransportAuthorityAbsent(Authority authority, String owner) {
    require(authority.source != 2, owner + " retained task lookup authority");
    require(!authority.directAuthority, owner + " retained direct receive authority");
    require(
        authority.lookupOverride == null || Byte.valueOf((byte) 3).equals(authority.lookupOverride),
        owner + " retained a raw lookup override");
    require(!authority.lifecyclePresent, owner + " retained a lifecycle");
    require(!authority.taskRelayState, owner + " retained a relay frame");
    require(!authority.exactTaskRelayState, owner + " retained exact relay state");
    require(
        !authority.taskRelayTransportReferencesPresent,
        owner + " retained relay transport references");
    require(!authority.socketContextPresent, owner + " retained a socket context");
    require(authority.receiveDepthValue == null, owner + " retained raw receive depth");
    require(authority.receiveDepth == 0, owner + " retained receive depth");
    require(authority.socketFileDescriptor == -1, owner + " retained a socket descriptor");
    require(
        authority.sslStorageThreadLocalState.isEmpty(),
        owner + " retained SSLStorage state " + authority.sslStorageThreadLocalState);
  }

  private static void recordEvent(String operation, long value, long token) {
    long sequence = EVENT_SEQUENCE.incrementAndGet();
    long nativeThread = -1L;
    try {
      nativeThread = nativeThreadId();
      long javaThread = Thread.currentThread().getId();
      TASK_EVENTS.add(new TaskEvent(operation, value, token, nativeThread, javaThread, sequence));
      if ("TASK_CAPTURE".equals(operation) || "TASK_RELAY_CAPTURE".equals(operation)) {
        TaskLabel label = ACTIVE_SUBMISSION.get();
        if (label != null) {
          require(
              label.expectedOperation != null,
              "reuse-wave submission captured strict context: " + label.id);
          require(
              label.expectedOperation.equals(operation),
              "labelled submission used the wrong capture operation: " + label.id);
          require(value != 0L && token == 0L, "invalid labelled capture token");
          require(nativeThread == label.sourceNativeThreadId, "capture ran on wrong source TID");
          TaskCapture capture = new TaskCapture(label, operation, value, nativeThread, sequence);
          require(
              CAPTURES.putIfAbsent(Long.valueOf(value), capture) == null,
              "duplicate capture token");
          require(
              PENDING.putIfAbsent(Long.valueOf(value), capture) == null, "duplicate pending token");
        }
        return;
      }
      if ("TASK_LINK".equals(operation)) {
        TaskCapture capture = CAPTURES.get(Long.valueOf(token));
        if (capture == null) {
          return;
        }
        require(PENDING.remove(Long.valueOf(token), capture), "duplicate task link");
        require(value == capture.captureNativeThreadId, "link parent did not match capture TID");
        TaskCompletion completion =
            new TaskCompletion(capture, value, nativeThread, javaThread, sequence);
        require(
            COMPLETIONS.putIfAbsent(capture.label.id, completion) == null,
            "duplicate task completion " + capture.label.id);
        return;
      }
      if ("TASK_CANCEL".equals(operation)) {
        Long cancelledToken = Long.valueOf(value);
        TaskCapture capture = CAPTURES.get(cancelledToken);
        if (capture == null) {
          return;
        }
        require(
            !PENDING.remove(cancelledToken, capture),
            "labelled task token was cancelled before link: " + value);
        require(
            COMPLETIONS.get(capture.label.id) != null,
            "labelled task token was cancelled before completion: " + value);
        require(
            TERMINAL_CANCELLATIONS.putIfAbsent(cancelledToken, capture) == null,
            "duplicate terminal task cancellation: " + value);
        return;
      }

      if ("VT_MOUNT".equals(operation)) {
        Long virtualId = Long.valueOf(value);
        if (!KNOWN_VIRTUAL_THREADS.contains(virtualId)) {
          return;
        }
        Long previous =
            MOUNTED_VIRTUAL_BY_NATIVE.putIfAbsent(Long.valueOf(nativeThread), virtualId);
        require(previous == null, "carrier mounted two known virtual threads");
        increment(VIRTUAL_MOUNTS, value);
        AtomicLong first = FIRST_VIRTUAL_MOUNT_SEQUENCE.get(virtualId);
        if (first == null) {
          AtomicLong candidate = new AtomicLong();
          AtomicLong raced = FIRST_VIRTUAL_MOUNT_SEQUENCE.putIfAbsent(virtualId, candidate);
          first = raced == null ? candidate : raced;
        }
        first.compareAndSet(0L, sequence);
        return;
      }
      if ("VT_TERMINATE".equals(operation)) {
        Long virtualId = Long.valueOf(value);
        if (!KNOWN_VIRTUAL_THREADS.contains(virtualId)) {
          return;
        }
        String id = VIRTUAL_THREAD_IDS.get(virtualId);
        require(id != null, "known virtual termination lacked an id");
        require(
            virtualId.equals(MOUNTED_VIRTUAL_BY_NATIVE.get(Long.valueOf(nativeThread))),
            "virtual termination occurred off its mounted carrier");
        require(
            Thread.currentThread().getId() == value,
            "virtual termination ran on the wrong Java thread");
        Authority authority = Authority.current();
        assertTransportAuthorityAbsent(authority, "virtual termination " + id);
        if (id.startsWith("W2")) {
          require(authority.source == 3, id + " lost its blocked lookup source at termination");
          require(
              Byte.valueOf((byte) 3).equals(authority.lookupOverride),
              id + " lost its blocked lookup override at termination");
        } else {
          require(authority.source == 1, id + " retained a lookup override at termination");
          require(authority.lookupOverride == null, id + " retained a raw lookup override");
        }
        increment(VIRTUAL_TERMINATIONS, value);
        System.out.println(
            "OBI_JAVA21_TERMINATION\t"
                + id
                + "\t"
                + value
                + "\t"
                + Thread.currentThread().getId()
                + "\t"
                + nativeThread
                + "\t"
                + authority.source
                + "\t"
                + authority.directAuthority
                + "\tNONE\t0\t"
                + authority.socketFileDescriptor
                + "\t"
                + authority.taskRelayState
                + "\t"
                + authority.exactTaskRelayState
                + "\t"
                + authority.taskRelayTransportReferencesPresent
                + "\t"
                + authority.socketContextPresent
                + "\t"
                + authority.receiveDepth
                + "\t"
                + (authority.sslStorageThreadLocalState.isEmpty()
                    ? "NONE"
                    : authority.sslStorageThreadLocalState));
        return;
      }
      if ("VT_UNMOUNT".equals(operation)) {
        Long virtualId = MOUNTED_VIRTUAL_BY_NATIVE.remove(Long.valueOf(nativeThread));
        if (virtualId != null) {
          increment(VIRTUAL_UNMOUNTS, virtualId.longValue());
        }
      }
    } catch (Throwable failure) {
      EVENT_FAILURE.compareAndSet(null, failure);
    }
  }

  private static void increment(ConcurrentMap<Long, AtomicInteger> counters, long id) {
    Long key = Long.valueOf(id);
    AtomicInteger counter = counters.get(key);
    if (counter == null) {
      AtomicInteger candidate = new AtomicInteger();
      AtomicInteger raced = counters.putIfAbsent(key, candidate);
      counter = raced == null ? candidate : raced;
    }
    counter.incrementAndGet();
  }

  private static int counter(ConcurrentMap<Long, AtomicInteger> counters, long id) {
    AtomicInteger counter = counters.get(Long.valueOf(id));
    return counter == null ? 0 : counter.get();
  }

  private static void installVirtualThreadReflection() throws Exception {
    Class<?> virtualThread = Class.forName("java.lang.VirtualThread");
    Field carrier = virtualThread.getDeclaredField("carrierThread");
    carrier.setAccessible(true);
    carrierThreadField = carrier;
  }

  private static Thread newVirtualThread(Executor scheduler, String name, Runnable task)
      throws Exception {
    Class<?> virtualThread = Class.forName("java.lang.VirtualThread");
    Constructor<?> constructor =
        virtualThread.getDeclaredConstructor(
            Executor.class, String.class, int.class, Runnable.class);
    constructor.setAccessible(true);
    return (Thread) constructor.newInstance(scheduler, name, Integer.valueOf(0), task);
  }

  private static Carrier currentCarrier() throws Exception {
    require(
        "java.lang.VirtualThread".equals(Thread.currentThread().getClass().getName()),
        "task was not running as a virtual thread");
    Field field = carrierThreadField;
    require(field != null, "virtual carrier reflection was not installed");
    Thread carrier = (Thread) field.get(Thread.currentThread());
    require(carrier != null, "mounted virtual thread did not expose a carrier");
    return new Carrier(carrier.getId(), nativeThreadId());
  }

  private static void extractAndStartSpan(ProbeTask task) {
    Context extracted =
        GlobalOpenTelemetry.getPropagators()
            .getTextMapPropagator()
            .extract(Context.root(), task.id, ID_GETTER);
    Span span =
        GlobalOpenTelemetry.getTracer("io.opentelemetry.obi.java21-concurrency-probe")
            .spanBuilder("probe-" + task.id)
            .setSpanKind(SpanKind.SERVER)
            .setParent(extracted)
            .startSpan();
    try {
      String traceId = span.getSpanContext().getTraceId();
      if (task.wave == 1) {
        require(task.expectedTraceId().equals(traceId), task.id + " received the wrong trace");
      } else {
        for (int index = 0; index < VIRTUAL_TASKS + PLATFORM_TASKS; index++) {
          require(!traceId(index).equals(traceId), task.id + " reused a first-wave trace");
        }
      }
      System.out.println(
          "OBI_JAVA21_SPAN\t"
              + task.id
              + "\t"
              + task.wave
              + "\t"
              + task.kind()
              + "\t"
              + traceId
              + "\t"
              + span.getSpanContext().getSpanId()
              + "\t"
              + Thread.currentThread().getId());
    } finally {
      span.end();
    }
  }

  private static String id(int wave, boolean virtual, int index) {
    return String.format(Locale.ROOT, "W%d%s%02d", wave, virtual ? "V" : "P", index);
  }

  private static String relayId(boolean virtual, int index) {
    return String.format(Locale.ROOT, "R1%s%02d", virtual ? "V" : "P", index);
  }

  private static int ordinal(boolean virtual, int index) {
    return virtual ? index : VIRTUAL_TASKS + index;
  }

  private static String traceId(int ordinal) {
    return String.format(Locale.ROOT, "%032x", Integer.valueOf(ordinal + 1));
  }

  private static String parentSpanId(int ordinal) {
    return String.format(Locale.ROOT, "%016x", Integer.valueOf(ordinal + 1));
  }

  private static String workerKey(String kind, int index) {
    return kind + ':' + index;
  }

  private static long nativeThreadId() {
    Method method = getTid;
    require(method != null, "BootstrapNative.gettid is unavailable");
    try {
      return ((Number) method.invoke(null)).longValue();
    } catch (ReflectiveOperationException failure) {
      throw new IllegalStateException("cannot resolve native thread id", failure);
    }
  }

  private static Object taskContext(Object task) throws Exception {
    Class<?> storage =
        Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
    return storage.getMethod("taskContext", Object.class).invoke(null, task);
  }

  private static void await(CountDownLatch latch, String name) throws InterruptedException {
    require(latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS), name + " timed out");
  }

  private static void closeConnections(List<ExactNettyConnection> connections) {
    for (int index = connections.size() - 1; index >= 0; index--) {
      connections.get(index).close();
    }
    connections.clear();
  }

  private static int javaFeatureVersion() {
    String version = System.getProperty("java.specification.version");
    if (version.startsWith("1.")) {
      return Integer.parseInt(version.substring(2));
    }
    int separator = version.indexOf('.');
    return Integer.parseInt(separator < 0 ? version : version.substring(0, separator));
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new IllegalStateException(message);
    }
  }

  private interface CheckedRunnable {
    void run() throws Exception;
  }

  private static final class ProbeTask implements Runnable {
    private final String id;
    private final int wave;
    private final boolean virtual;
    private final int index;
    private final WaveControl control;
    private final AtomicReference<Throwable> failure;
    private final RelayControl relayControl;
    private final DeterministicVirtualScheduler scheduler;
    private final DeterministicPlatformExecutor platform;
    private volatile Thread virtualThread;
    private volatile int expectedLifecycleIdentity;
    private volatile long taskJavaThreadId;
    private volatile long firstExecutionNativeThreadId;
    private volatile Carrier firstCarrier;
    private volatile Carrier remountCarrier;
    private volatile Carrier bodyCarrier;

    private ProbeTask(
        String id,
        int wave,
        boolean virtual,
        int index,
        WaveControl control,
        AtomicReference<Throwable> failure) {
      this(id, wave, virtual, index, control, failure, null, null, null);
    }

    private ProbeTask(
        String id,
        int wave,
        boolean virtual,
        int index,
        WaveControl control,
        AtomicReference<Throwable> failure,
        RelayControl relayControl,
        DeterministicVirtualScheduler scheduler,
        DeterministicPlatformExecutor platform) {
      this.id = id;
      this.wave = wave;
      this.virtual = virtual;
      this.index = index;
      this.control = control;
      this.failure = failure;
      this.relayControl = relayControl;
      this.scheduler = scheduler;
      this.platform = platform;
    }

    private void setVirtualThread(Thread virtualThread) {
      this.virtualThread = virtualThread;
    }

    private String kind() {
      return virtual ? VIRTUAL : PLATFORM;
    }

    private int globalOrdinal() {
      return ordinal(virtual, index);
    }

    private int expectedSocketFileDescriptor() {
      return FIRST_SOCKET_FILE_DESCRIPTOR + globalOrdinal();
    }

    private String expectedTraceId() {
      return traceId(globalOrdinal());
    }

    private String expectedParentSpanId() {
      return parentSpanId(globalOrdinal());
    }

    @Override
    public void run() {
      try {
        taskJavaThreadId = Thread.currentThread().getId();
        if (virtual) {
          require(
              virtualThread != null && taskJavaThreadId == virtualThread.getId(),
              id + " ran on the wrong virtual thread");
          firstCarrier = currentCarrier();
          firstExecutionNativeThreadId = firstCarrier.nativeThreadId;
          control.initiallyParked.countDown();
          while (!control.migrationReleased.get()) {
            LockSupport.park();
          }
          remountCarrier = currentCarrier();
          require(
              firstCarrier.javaThreadId != remountCarrier.javaThreadId,
              id + " did not migrate carriers");
          require(
              firstCarrier.nativeThreadId != remountCarrier.nativeThreadId,
              id + " did not migrate native carriers");
          control.migrated.countDown();
          control.ready.countDown();
          await(control.release, id + " release gate");
          bodyCarrier = currentCarrier();
          require(
              bodyCarrier.javaThreadId == remountCarrier.javaThreadId,
              id + " moved after its forced migration");
          require(
              bodyCarrier.nativeThreadId == remountCarrier.nativeThreadId,
              id + " changed native carrier after migration");
          System.out.println(
              "OBI_JAVA21_MIGRATION\t"
                  + id
                  + "\t"
                  + taskJavaThreadId
                  + "\t"
                  + firstCarrier.javaThreadId
                  + "\t"
                  + firstCarrier.nativeThreadId
                  + "\t"
                  + remountCarrier.javaThreadId
                  + "\t"
                  + remountCarrier.nativeThreadId
                  + "\t"
                  + bodyCarrier.javaThreadId
                  + "\t"
                  + bodyCarrier.nativeThreadId);
        } else {
          long nativeThread = nativeThreadId();
          firstCarrier = new Carrier(taskJavaThreadId, nativeThread);
          remountCarrier = firstCarrier;
          bodyCarrier = firstCarrier;
          firstExecutionNativeThreadId = nativeThread;
          control.ready.countDown();
          await(control.release, id + " release gate");
        }

        Authority before = Authority.current();
        assertBodyAuthority(before);
        System.out.println(
            "OBI_JAVA21_BODY\t"
                + id
                + "\t"
                + wave
                + "\t"
                + kind()
                + "\t"
                + taskJavaThreadId
                + "\t"
                + nativeThreadId()
                + "\t"
                + firstCarrier.javaThreadId
                + "\t"
                + firstCarrier.nativeThreadId
                + "\t"
                + bodyCarrier.javaThreadId
                + "\t"
                + bodyCarrier.nativeThreadId
                + "\t"
                + before.source
                + "\t"
                + (before.lifecycleActive ? "LIVE" : "NONE")
                + "\t"
                + before.lifecycleIdentity
                + "\t"
                + before.socketFileDescriptor);

        if (relayControl != null) {
          relayControl.submit(this, scheduler, platform);
          return;
        }
        extractAndStartSpan(this);
        Authority after = Authority.current();
        if (wave == 1) {
          require(after.source == 2, id + " lost task authority after extraction");
          require(after.lifecyclePresent && after.lifecycleActive, id + " lost its lifecycle");
          require(after.lifecycleIdentity == expectedLifecycleIdentity, id + " changed lifecycle");
          require(after.socketFileDescriptor == -1, id + " did not consume its descriptor");
          require(!after.socketContextPresent, id + " retained its socket context");
          require(after.taskRelayState, id + " lost relay state after extraction");
          require(after.exactTaskRelayState, id + " lost exact relay state after extraction");
          require(
              !after.taskRelayTransportReferencesPresent,
              id + " retained relay transport references after extraction");
        } else {
          require(after.source != 2, id + " acquired task authority after a miss");
          require(!after.lifecyclePresent, id + " acquired a lifecycle after a miss");
          require(after.socketFileDescriptor == -1, id + " acquired a descriptor after a miss");
          require(!after.socketContextPresent, id + " acquired a socket context after a miss");
          require(!after.exactTaskRelayState, id + " acquired exact relay state after a miss");
          require(
              !after.taskRelayTransportReferencesPresent,
              id + " acquired relay transport references after a miss");
        }
      } catch (Throwable problem) {
        failure.compareAndSet(null, problem);
      } finally {
        control.finished.countDown();
      }
    }

    private void assertBodyAuthority(Authority authority) {
      if (wave == 1) {
        require(authority.source == 2, id + " did not receive exact task lookup authority");
        require(!authority.directAuthority, id + " retained direct receive authority");
        require(authority.lifecyclePresent && authority.lifecycleActive, id + " lost lifecycle");
        require(
            authority.lifecycleIdentity == expectedLifecycleIdentity, id + " changed lifecycle");
        require(
            authority.socketFileDescriptor == expectedSocketFileDescriptor(),
            id + " received another task's descriptor");
        require(authority.socketContextPresent, id + " lost its socket context");
        require(authority.taskRelayState, id + " lost relay state");
        require(authority.exactTaskRelayState, id + " lost exact relay state");
      } else {
        require(authority.source != 2, id + " inherited task lookup authority");
        require(!authority.directAuthority, id + " inherited direct receive authority");
        require(!authority.lifecyclePresent, id + " inherited a lifecycle");
        require(authority.socketFileDescriptor == -1, id + " inherited a socket descriptor");
        require(!authority.socketContextPresent, id + " inherited a socket context");
        require(!authority.exactTaskRelayState, id + " inherited exact relay state");
        require(
            !authority.taskRelayTransportReferencesPresent,
            id + " inherited relay transport references");
      }
    }
  }

  private static final class RelayControl {
    private final AtomicReference<Throwable> failure;
    private final RelayDescriptor[] relays = new RelayDescriptor[RELAY_TASKS];
    private final CountDownLatch finished = new CountDownLatch(RELAY_TASKS);

    private RelayControl(AtomicReference<Throwable> failure) {
      this.failure = failure;
    }

    private void submit(
        ProbeTask parent,
        DeterministicVirtualScheduler scheduler,
        DeterministicPlatformExecutor platform)
        throws Exception {
      boolean completionExpected = false;
      try {
        require(
            parent.wave == 1 && !parent.virtual, "invalid downstream relay source " + parent.id);
        require(parent.index >= 0 && parent.index < RELAY_TASKS, "invalid relay index");
        boolean virtual = parent.index < RELAY_VIRTUAL_TASKS;
        String id = relayId(virtual, parent.index);
        RelayTask task = new RelayTask(id, virtual, parent, this);
        Thread virtualThread =
            virtual ? newVirtualThread(scheduler, "obi-java21-" + id, task) : null;
        task.setVirtualThread(virtualThread);
        if (virtualThread != null) {
          registerVirtualThread(virtualThread, id);
        }
        RelayDescriptor descriptor = new RelayDescriptor(task, virtualThread);
        synchronized (this) {
          require(relays[parent.index] == null, "duplicate downstream relay " + parent.id);
          relays[parent.index] = descriptor;
        }

        require(ACTIVE_SUBMISSION.get() == null, "nested downstream relay label " + id);
        TaskLabel label =
            new TaskLabel(
                id,
                virtual,
                virtualThread == null ? 0L : virtualThread.getId(),
                nativeThreadId(),
                "TASK_RELAY_CAPTURE");
        ACTIVE_SUBMISSION.set(label);
        try {
          if (virtualThread != null) {
            virtualThread.start();
          } else {
            platform.execute(task);
          }
          completionExpected = true;
        } finally {
          ACTIVE_SUBMISSION.remove();
        }
      } finally {
        if (!completionExpected) {
          finished.countDown();
        }
      }
    }

    private synchronized List<RelayDescriptor> descriptors() {
      List<RelayDescriptor> result = new ArrayList<RelayDescriptor>();
      for (int index = 0; index < relays.length; index++) {
        require(relays[index] != null, "missing downstream relay " + index);
        result.add(relays[index]);
      }
      return result;
    }
  }

  private static final class RelayTask implements Runnable {
    private final String id;
    private final boolean virtual;
    private final ProbeTask parent;
    private final RelayControl control;
    private volatile Thread virtualThread;
    private volatile long taskJavaThreadId;
    private volatile long firstExecutionNativeThreadId;

    private RelayTask(String id, boolean virtual, ProbeTask parent, RelayControl control) {
      this.id = id;
      this.virtual = virtual;
      this.parent = parent;
      this.control = control;
    }

    private void setVirtualThread(Thread virtualThread) {
      this.virtualThread = virtualThread;
    }

    private String kind() {
      return virtual ? VIRTUAL : PLATFORM;
    }

    @Override
    public void run() {
      try {
        taskJavaThreadId = Thread.currentThread().getId();
        if (virtual) {
          require(
              virtualThread != null && virtualThread.getId() == taskJavaThreadId,
              id + " ran on the wrong virtual thread");
          firstExecutionNativeThreadId = currentCarrier().nativeThreadId;
        } else {
          firstExecutionNativeThreadId = nativeThreadId();
        }
        require(taskJavaThreadId != parent.taskJavaThreadId, id + " did not change Java execution");
        require(
            firstExecutionNativeThreadId != parent.bodyCarrier.nativeThreadId,
            id + " did not change native execution");

        Authority before = Authority.current();
        require(before.source == 2, id + " did not receive relayed task authority");
        require(!before.directAuthority, id + " retained direct receive authority");
        require(before.lifecyclePresent && before.lifecycleActive, id + " lost lifecycle");
        require(
            before.lifecycleIdentity == parent.expectedLifecycleIdentity,
            id + " received another task's lifecycle");
        require(
            before.socketFileDescriptor == parent.expectedSocketFileDescriptor(),
            id + " received another task's descriptor");
        require(before.socketContextPresent, id + " lost its socket context");
        require(before.taskRelayState, id + " lost relay state");
        require(before.exactTaskRelayState, id + " lost exact relay state");
        require(
            !before.taskRelayTransportReferencesPresent,
            id + " retained stale relay transport references");
        System.out.println(
            "OBI_JAVA21_RELAY\t"
                + id
                + "\t"
                + parent.id
                + "\t"
                + kind()
                + "\t"
                + taskJavaThreadId
                + "\t"
                + firstExecutionNativeThreadId
                + "\t"
                + before.source
                + "\tLIVE\t"
                + before.lifecycleIdentity
                + "\t"
                + before.socketFileDescriptor
                + "\t"
                + before.taskRelayState
                + "\t"
                + before.exactTaskRelayState
                + "\t"
                + before.socketContextPresent
                + "\t"
                + System.identityHashCode(trackedTask()));

        extractAndStartSpan(parent);
        Authority after = Authority.current();
        require(after.source == 2, id + " lost relayed task authority after extraction");
        require(after.lifecyclePresent && after.lifecycleActive, id + " lost its lifecycle");
        require(
            after.lifecycleIdentity == parent.expectedLifecycleIdentity,
            id + " changed lifecycle after extraction");
        require(after.socketFileDescriptor == -1, id + " did not consume its descriptor");
        require(!after.socketContextPresent, id + " retained its socket context");
        require(after.taskRelayState, id + " lost relay state after extraction");
        require(after.exactTaskRelayState, id + " lost exact relay state after extraction");
        require(
            !after.taskRelayTransportReferencesPresent,
            id + " retained relay transport references after extraction");
      } catch (Throwable problem) {
        control.failure.compareAndSet(null, problem);
      } finally {
        control.finished.countDown();
      }
    }

    private Object trackedTask() {
      return virtualThread == null ? this : virtualThread;
    }
  }

  private static final class RelayDescriptor {
    private final RelayTask task;
    private final Thread virtualThread;

    private RelayDescriptor(RelayTask task, Thread virtualThread) {
      this.task = task;
      this.virtualThread = virtualThread;
    }

    private Object trackedTask() {
      return task.trackedTask();
    }
  }

  private static final class PlatformSubmission implements Runnable {
    private final int index;
    private ProbeTask task;

    private PlatformSubmission(int index) {
      this.index = index;
    }

    private synchronized void prepare(ProbeTask task) {
      require(this.task == null, "platform task " + index + " was still active");
      require(task != null && task.index == index, "platform task index changed");
      this.task = task;
    }

    @Override
    public void run() {
      ProbeTask current;
      synchronized (this) {
        current = task;
      }
      require(current != null, "platform task " + index + " ran without a delegate");
      try {
        current.run();
      } finally {
        synchronized (this) {
          require(task == current, "platform task " + index + " delegate changed while running");
          task = null;
        }
      }
    }
  }

  private static final class WaveControl {
    private final CountDownLatch initiallyParked = new CountDownLatch(VIRTUAL_TASKS);
    private final AtomicBoolean migrationReleased = new AtomicBoolean();
    private final CountDownLatch migrated = new CountDownLatch(VIRTUAL_TASKS);
    private final CountDownLatch ready = new CountDownLatch(VIRTUAL_TASKS + PLATFORM_TASKS);
    private final CountDownLatch release = new CountDownLatch(1);
    private final CountDownLatch finished = new CountDownLatch(VIRTUAL_TASKS + PLATFORM_TASKS);
  }

  private static final class TaskDescriptor {
    private final ProbeTask task;
    private final Thread virtualThread;
    private final PlatformSubmission platformSubmission;
    private volatile ExactNettyConnection connection;
    private volatile TaskLabel label;

    private TaskDescriptor(
        ProbeTask task, Thread virtualThread, PlatformSubmission platformSubmission) {
      this.task = task;
      this.virtualThread = virtualThread;
      this.platformSubmission = platformSubmission;
    }

    private Object trackedTask() {
      return virtualThread == null ? platformSubmission : virtualThread;
    }

    private int taskIdentity() {
      return System.identityHashCode(trackedTask());
    }
  }

  private static final class WaveResult {
    private final int wave;
    private final List<TaskDescriptor> virtual;
    private final List<TaskDescriptor> platform;
    private final List<RelayDescriptor> relays;

    private WaveResult(
        int wave,
        List<TaskDescriptor> virtual,
        List<TaskDescriptor> platform,
        List<RelayDescriptor> relays) {
      this.wave = wave;
      this.virtual = new ArrayList<TaskDescriptor>(virtual);
      this.platform = new ArrayList<TaskDescriptor>(platform);
      this.relays = new ArrayList<RelayDescriptor>(relays);
    }

    private List<TaskDescriptor> all() {
      List<TaskDescriptor> result = new ArrayList<TaskDescriptor>();
      result.addAll(virtual);
      result.addAll(platform);
      return result;
    }

    private Set<Long> virtualCarrierThreads() {
      Set<Long> result = Collections.newSetFromMap(new ConcurrentHashMap<Long, Boolean>());
      for (TaskDescriptor descriptor : virtual) {
        result.add(Long.valueOf(descriptor.task.firstCarrier.javaThreadId));
        result.add(Long.valueOf(descriptor.task.remountCarrier.javaThreadId));
        result.add(Long.valueOf(descriptor.task.bodyCarrier.javaThreadId));
      }
      return result;
    }

    private Set<Long> platformThreads() {
      Set<Long> result = Collections.newSetFromMap(new ConcurrentHashMap<Long, Boolean>());
      for (TaskDescriptor descriptor : platform) {
        result.add(Long.valueOf(descriptor.task.taskJavaThreadId));
      }
      return result;
    }
  }

  private static final class TaskLabel {
    private final String id;
    private final boolean virtual;
    private final long virtualJavaThreadId;
    private final long sourceNativeThreadId;
    private final String expectedOperation;

    private TaskLabel(
        String id,
        boolean virtual,
        long virtualJavaThreadId,
        long sourceNativeThreadId,
        String expectedOperation) {
      this.id = id;
      this.virtual = virtual;
      this.virtualJavaThreadId = virtualJavaThreadId;
      this.sourceNativeThreadId = sourceNativeThreadId;
      this.expectedOperation = expectedOperation;
    }
  }

  private static final class TaskCapture {
    private final TaskLabel label;
    private final String operation;
    private final long token;
    private final long captureNativeThreadId;
    private final long sequence;

    private TaskCapture(
        TaskLabel label, String operation, long token, long captureNativeThreadId, long sequence) {
      this.label = label;
      this.operation = operation;
      this.token = token;
      this.captureNativeThreadId = captureNativeThreadId;
      this.sequence = sequence;
    }
  }

  private static final class TaskCompletion {
    private final TaskCapture capture;
    private final long linkParentThreadId;
    private final long linkChildThreadId;
    private final long linkChildJavaThreadId;
    private final long sequence;

    private TaskCompletion(
        TaskCapture capture,
        long linkParentThreadId,
        long linkChildThreadId,
        long linkChildJavaThreadId,
        long sequence) {
      this.capture = capture;
      this.linkParentThreadId = linkParentThreadId;
      this.linkChildThreadId = linkChildThreadId;
      this.linkChildJavaThreadId = linkChildJavaThreadId;
      this.sequence = sequence;
    }
  }

  private static final class TaskEvent {
    private final String operation;
    private final long value;
    private final long token;
    private final long nativeThreadId;
    private final long javaThreadId;
    private final long sequence;

    private TaskEvent(
        String operation,
        long value,
        long token,
        long nativeThreadId,
        long javaThreadId,
        long sequence) {
      this.operation = operation;
      this.value = value;
      this.token = token;
      this.nativeThreadId = nativeThreadId;
      this.javaThreadId = javaThreadId;
      this.sequence = sequence;
    }
  }

  private static final class EventBoundary {
    private final long taskCaptures;
    private final long taskRelayCaptures;
    private final long taskLinks;
    private final long taskCancels;
    private final long taskUnlinks;

    private EventBoundary(
        long taskCaptures,
        long taskRelayCaptures,
        long taskLinks,
        long taskCancels,
        long taskUnlinks) {
      this.taskCaptures = taskCaptures;
      this.taskRelayCaptures = taskRelayCaptures;
      this.taskLinks = taskLinks;
      this.taskCancels = taskCancels;
      this.taskUnlinks = taskUnlinks;
    }

    private static EventBoundary current() {
      long capture = 0L;
      long relay = 0L;
      long link = 0L;
      long cancel = 0L;
      long unlink = 0L;
      for (TaskEvent event : TASK_EVENTS) {
        if ("TASK_CAPTURE".equals(event.operation)) {
          capture++;
        } else if ("TASK_RELAY_CAPTURE".equals(event.operation)) {
          relay++;
        } else if ("TASK_LINK".equals(event.operation)) {
          link++;
        } else if ("TASK_CANCEL".equals(event.operation)) {
          cancel++;
        } else if ("TASK_UNLINK".equals(event.operation)) {
          unlink++;
        }
      }
      return new EventBoundary(capture, relay, link, cancel, unlink);
    }
  }

  private static final class Carrier {
    private final long javaThreadId;
    private final long nativeThreadId;

    private Carrier(long javaThreadId, long nativeThreadId) {
      this.javaThreadId = javaThreadId;
      this.nativeThreadId = nativeThreadId;
    }
  }

  private static final class WorkerBaseline {
    private final long javaThreadId;
    private final long nativeThreadId;
    private final int lookupSource;
    private final Object lookupOverride;
    private final Object receiveEpochValue;
    private final String sslStorageThreadLocalState;

    private WorkerBaseline(long javaThreadId, long nativeThreadId, Authority authority) {
      this.javaThreadId = javaThreadId;
      this.nativeThreadId = nativeThreadId;
      this.lookupSource = authority.source;
      this.lookupOverride = authority.lookupOverride;
      this.receiveEpochValue = authority.receiveEpochValue;
      this.sslStorageThreadLocalState = authority.sslStorageThreadLocalState;
    }
  }

  private static final class Authority {
    private final int source;
    private final boolean directAuthority;
    private final Object lookupOverride;
    private final boolean lifecyclePresent;
    private final boolean lifecycleActive;
    private final int lifecycleIdentity;
    private final int socketFileDescriptor;
    private final boolean taskRelayState;
    private final boolean exactTaskRelayState;
    private final boolean taskRelayTransportReferencesPresent;
    private final boolean socketContextPresent;
    private final Object receiveDepthValue;
    private final int receiveDepth;
    private final Object receiveEpochValue;
    private final String sslStorageThreadLocalState;

    private Authority(
        int source,
        boolean directAuthority,
        Object lookupOverride,
        boolean lifecyclePresent,
        boolean lifecycleActive,
        int lifecycleIdentity,
        int socketFileDescriptor,
        boolean taskRelayState,
        boolean exactTaskRelayState,
        boolean taskRelayTransportReferencesPresent,
        boolean socketContextPresent,
        Object receiveDepthValue,
        int receiveDepth,
        Object receiveEpochValue,
        String sslStorageThreadLocalState) {
      this.source = source;
      this.directAuthority = directAuthority;
      this.lookupOverride = lookupOverride;
      this.lifecyclePresent = lifecyclePresent;
      this.lifecycleActive = lifecycleActive;
      this.lifecycleIdentity = lifecycleIdentity;
      this.socketFileDescriptor = socketFileDescriptor;
      this.taskRelayState = taskRelayState;
      this.exactTaskRelayState = exactTaskRelayState;
      this.taskRelayTransportReferencesPresent = taskRelayTransportReferencesPresent;
      this.socketContextPresent = socketContextPresent;
      this.receiveDepthValue = receiveDepthValue;
      this.receiveDepth = receiveDepth;
      this.receiveEpochValue = receiveEpochValue;
      this.sslStorageThreadLocalState = sslStorageThreadLocalState;
    }

    private static Authority current() throws Exception {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      int source =
          ((Integer) threadInfo.getMethod("remoteParentLookupSource").invoke(null)).intValue();
      boolean direct =
          ((Boolean) threadInfo.getMethod("hasRemoteParentDirectReceiveAuthority").invoke(null))
              .booleanValue();
      Object lookupOverride = threadLocalValue(threadInfo, "remoteParentLookupOverride");
      Object lifecycle = threadInfo.getMethod("remoteParentLookupLifecycle").invoke(null);
      boolean active =
          lifecycle != null
              && Boolean.TRUE.equals(lifecycle.getClass().getMethod("active").invoke(lifecycle));
      int socketFileDescriptor =
          ((Integer) threadInfo.getMethod("remoteParentSocketFileDescriptor").invoke(null))
              .intValue();
      Object relayState = threadLocalValue(threadInfo, "taskRelayState");
      TaskRelaySnapshot relay = TaskRelaySnapshot.capture(relayState);
      boolean socketContext = threadLocalValue(threadInfo, "remoteParentSocketContext") != null;
      Object receiveDepth = threadLocalValue(threadInfo, "remoteParentReceiveDepth");
      Object receiveEpoch = threadLocalValue(threadInfo, "remoteParentReceiveEpoch");
      return new Authority(
          source,
          direct,
          lookupOverride,
          lifecycle != null,
          active,
          lifecycle == null ? 0 : System.identityHashCode(lifecycle),
          socketFileDescriptor,
          relay.depth > 0,
          relay.exactState,
          relay.transportReferencesPresent,
          socketContext,
          receiveDepth,
          receiveDepth instanceof Number ? ((Number) receiveDepth).intValue() : 0,
          receiveEpoch,
          SslStorageThreadLocals.present());
    }

    private static Object threadLocalValue(Class<?> owner, String name) throws Exception {
      Field field = owner.getDeclaredField(name);
      field.setAccessible(true);
      return ((ThreadLocal<?>) field.get(null)).get();
    }
  }

  private static final class TaskRelaySnapshot {
    private final int depth;
    private final boolean exactState;
    private final boolean transportReferencesPresent;

    private TaskRelaySnapshot(int depth, boolean exactState, boolean transportReferencesPresent) {
      this.depth = depth;
      this.exactState = exactState;
      this.transportReferencesPresent = transportReferencesPresent;
    }

    private static TaskRelaySnapshot capture(Object state) throws Exception {
      if (state == null) {
        return new TaskRelaySnapshot(0, false, false);
      }
      int depth = intField(state, "depth");
      long[] previousParents = (long[]) fieldValue(state, "previousParents");
      long[] previousTokens = (long[]) fieldValue(state, "previousTokens");
      boolean[] previousExact = (boolean[]) fieldValue(state, "previousExact");
      byte[] previousOverrides = (byte[]) fieldValue(state, "previousLookupOverrides");
      long[] previousEpochs = (long[]) fieldValue(state, "previousReceiveEpochs");
      Object[] previousLifecycles = (Object[]) fieldValue(state, "previousLookupLifecycles");
      Object[] previousContexts = (Object[]) fieldValue(state, "previousSocketContexts");
      require(depth >= 0, "negative task relay depth");
      require(
          depth <= previousParents.length
              && depth <= previousTokens.length
              && depth <= previousExact.length
              && depth <= previousOverrides.length
              && depth <= previousEpochs.length
              && depth <= previousLifecycles.length
              && depth <= previousContexts.length,
          "task relay depth exceeded storage");
      boolean currentExact = booleanField(state, "currentExact");
      boolean exactState = currentExact;
      for (int index = 0; index < depth; index++) {
        exactState |= previousExact[index];
      }
      boolean references =
          hasReference(previousLifecycles)
              || hasReference(previousContexts)
              || fieldValue(state, "exitLookupLifecycle") != null
              || fieldValue(state, "exitSocketContext") != null;
      return new TaskRelaySnapshot(depth, exactState, references);
    }

    private static Object fieldValue(Object target, String name) throws Exception {
      Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      return field.get(target);
    }

    private static int intField(Object target, String name) throws Exception {
      Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      return field.getInt(target);
    }

    private static boolean booleanField(Object target, String name) throws Exception {
      Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      return field.getBoolean(target);
    }

    private static boolean hasReference(Object[] values) {
      for (Object value : values) {
        if (value != null) {
          return true;
        }
      }
      return false;
    }
  }

  private static final class SslStorageThreadLocals {
    private static final String[] NAMES = {
      "activeTaskSubmissions",
      "discardOldestQueues",
      "executorHookDepth",
      "executorTaskScopes",
      "virtualThreadTaskScope",
      "remoteParentUnwrapDepth",
      "nettyConnectionScopes",
      "nettyHandlerScopes",
      "unencrypted",
      "nettyConnection"
    };

    private static String present() throws Exception {
      Class<?> storage =
          Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
      StringBuilder result = new StringBuilder();
      for (String name : NAMES) {
        if (Authority.threadLocalValue(storage, name) != null) {
          if (result.length() > 0) {
            result.append(',');
          }
          result.append(name);
        }
      }
      return result.toString();
    }
  }

  private static final class ExactNettyConnection implements AutoCloseable {
    private final Class<?> storage;
    private final Class<?> connectionClass;
    private final Object channel = new Object();
    private final Object connection;
    private final Object lifecycle;
    private final int socketFileDescriptor;
    private boolean closed;

    private ExactNettyConnection(int socketFileDescriptor) throws Exception {
      this.socketFileDescriptor = socketFileDescriptor;
      storage =
          Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
      connectionClass =
          Class.forName("io.opentelemetry.obi.java.instrumentations.data.Connection", true, null);
      connection =
          connectionClass
              .getConstructor(InetAddress.class, int.class, InetAddress.class, int.class, int.class)
              .newInstance(
                  InetAddress.getByName("127.0.0.1"),
                  Integer.valueOf(20_000 + socketFileDescriptor),
                  InetAddress.getByName("127.0.0.2"),
                  Integer.valueOf(30_000 + socketFileDescriptor),
                  Integer.valueOf(socketFileDescriptor));
      require(
          storage
                  .getMethod("associateConnectionWithChannel", Object.class, connectionClass)
                  .invoke(null, channel, connection)
              == connection,
          "failed to register exact connection " + socketFileDescriptor);
      lifecycle =
          storage
              .getMethod("remoteParentSocketLifecycle", connectionClass)
              .invoke(null, connection);
      require(lifecycle != null, "exact lifecycle unavailable " + socketFileDescriptor);
    }

    private int lifecycleIdentity() {
      return System.identityHashCode(lifecycle);
    }

    private void stage(CheckedRunnable action) throws Exception {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      Class<?> lifecycleClass = lifecycle.getClass();
      boolean staged =
          ((Boolean)
                  threadInfo
                      .getMethod("setRemoteParentSocketFileDescriptor", int.class, lifecycleClass)
                      .invoke(null, Integer.valueOf(socketFileDescriptor), lifecycle))
              .booleanValue();
      require(staged, "failed to stage descriptor " + socketFileDescriptor);
      try {
        storage
            .getMethod("beginNettyHandlerScope", Object.class, boolean.class)
            .invoke(null, null, Boolean.TRUE);
        try {
          require(
              Boolean.TRUE.equals(
                  storage
                      .getMethod("setCurrentNettyConnection", Object.class)
                      .invoke(null, connection)),
              "failed to install exact connection scope " + socketFileDescriptor);
          threadInfo
              .getMethod("markRemoteParentDirectLookup", Object.class)
              .invoke(null, lifecycle);
          action.run();
        } finally {
          storage.getMethod("endNettyHandlerScope").invoke(null);
        }
      } finally {
        threadInfo.getMethod("clearRemoteParentSocketFileDescriptor").invoke(null);
        threadInfo.getMethod("clearRemoteParentLookupSource").invoke(null);
      }
    }

    @Override
    public void close() {
      if (closed) {
        return;
      }
      closed = true;
      try {
        storage
            .getMethod("cleanupConnection", Object.class, connectionClass)
            .invoke(null, channel, connection);
      } catch (ReflectiveOperationException failure) {
        throw new IllegalStateException("cannot close exact connection", failure);
      }
    }
  }

  private static final class HelperFixture implements AutoCloseable {
    private final Method setTaskEmitter;
    private final Method setRemoteParentEnabled;
    private final Method clearLookup;
    private final Method clearSocket;

    private HelperFixture(
        Method setTaskEmitter,
        Method setRemoteParentEnabled,
        Method clearLookup,
        Method clearSocket) {
      this.setTaskEmitter = setTaskEmitter;
      this.setRemoteParentEnabled = setRemoteParentEnabled;
      this.clearLookup = clearLookup;
      this.clearSocket = clearSocket;
    }

    private static HelperFixture install() throws Exception {
      Class<?> bootstrapNative =
          Class.forName("io.opentelemetry.obi.java.BootstrapNative", true, null);
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      Class<?> emitter =
          Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo$TaskContextEmitter", true, null);
      require(bootstrapNative.getClassLoader() == null, "BootstrapNative is not bootstrap loaded");
      require(threadInfo.getClassLoader() == null, "ThreadInfo is not bootstrap loaded");
      require(emitter.getClassLoader() == null, "task emitter is not bootstrap loaded");
      getTid = bootstrapNative.getMethod("gettid");

      Method setTaskEmitter = threadInfo.getDeclaredMethod("setTaskContextEmitterForTest", emitter);
      setTaskEmitter.setAccessible(true);
      Object recorder =
          Proxy.newProxyInstance(
              null,
              new Class<?>[] {emitter},
              (proxy, method, values) -> {
                if ("emit".equals(method.getName())) {
                  recordEvent(
                      String.valueOf(values[0]),
                      ((Number) values[1]).longValue(),
                      ((Number) values[2]).longValue());
                }
                return null;
              });
      setTaskEmitter.invoke(null, recorder);
      Method setRemoteParentEnabled = threadInfo.getMethod("setRemoteParentEnabled", boolean.class);
      Method clearLookup = threadInfo.getMethod("clearRemoteParentLookupSource");
      Method clearSocket = threadInfo.getMethod("clearRemoteParentSocketFileDescriptor");
      setRemoteParentEnabled.invoke(null, Boolean.TRUE);
      return new HelperFixture(setTaskEmitter, setRemoteParentEnabled, clearLookup, clearSocket);
    }

    @Override
    public void close() throws Exception {
      try {
        clearSocket.invoke(null);
        clearLookup.invoke(null);
        setRemoteParentEnabled.invoke(null, Boolean.FALSE);
      } finally {
        try {
          setTaskEmitter.invoke(null, new Object[] {null});
        } finally {
          getTid = null;
          carrierThreadField = null;
        }
      }
    }
  }

  private static final class DeterministicVirtualScheduler implements Executor, AutoCloseable {
    private static final SchedulerItem STOP = new SchedulerItem(null, null, true);

    private final List<BlockingQueue<SchedulerItem>> queues =
        new ArrayList<BlockingQueue<SchedulerItem>>();
    private final List<Thread> workers = new ArrayList<Thread>();
    private final List<Carrier> identities;
    private final CountDownLatch started;
    private final IdentityHashMap<Runnable, Integer> homes =
        new IdentityHashMap<Runnable, Integer>();
    private final IdentityHashMap<Runnable, Integer> executions =
        new IdentityHashMap<Runnable, Integer>();
    private final AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
    private final Object completionLock = new Object();
    private long completedContinuations;
    private int nextHome;
    private boolean closed;

    private DeterministicVirtualScheduler(int size) throws Exception {
      started = new CountDownLatch(size);
      identities = new ArrayList<Carrier>(Collections.nCopies(size, (Carrier) null));
      for (int index = 0; index < size; index++) {
        final int worker = index;
        BlockingQueue<SchedulerItem> queue = new LinkedBlockingQueue<SchedulerItem>();
        queues.add(queue);
        Thread thread =
            new Thread(
                new Runnable() {
                  @Override
                  public void run() {
                    workerLoop(worker);
                  }
                },
                "obi-java21-carrier-" + index);
        thread.setDaemon(true);
        workers.add(thread);
        thread.start();
      }
      await(started, "virtual carrier startup");
    }

    @Override
    public synchronized void execute(Runnable command) {
      if (closed) {
        throw new IllegalStateException("virtual scheduler is closed");
      }
      Integer home = homes.get(command);
      if (home == null) {
        home = Integer.valueOf(nextHome++ % queues.size());
        homes.put(command, home);
        executions.put(command, Integer.valueOf(0));
      }
      int count = executions.get(command).intValue();
      executions.put(command, Integer.valueOf(count + 1));
      int destination = count == 0 ? home.intValue() : (home.intValue() + 1) % queues.size();
      queues.get(destination).add(new SchedulerItem(command, null, false));
    }

    private void runDirect(int worker, CheckedRunnable action) throws Exception {
      require(worker >= 0 && worker < queues.size(), "invalid carrier index");
      DirectCall direct = new DirectCall(action);
      queues.get(worker).add(new SchedulerItem(null, direct, false));
      direct.await("carrier direct observation " + worker);
    }

    private void workerLoop(int index) {
      identities.set(index, new Carrier(Thread.currentThread().getId(), nativeThreadId()));
      started.countDown();
      try {
        for (; ; ) {
          SchedulerItem item = queues.get(index).take();
          if (item == STOP || item.stop) {
            return;
          }
          if (item.direct != null) {
            item.direct.run();
            continue;
          }
          try {
            item.continuation.run();
          } catch (Throwable problem) {
            failure.compareAndSet(null, problem);
          } finally {
            synchronized (completionLock) {
              completedContinuations++;
              completionLock.notifyAll();
            }
          }
        }
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        failure.compareAndSet(null, interrupted);
      } catch (Throwable problem) {
        failure.compareAndSet(null, problem);
      }
    }

    private long completedContinuations() {
      synchronized (completionLock) {
        return completedContinuations;
      }
    }

    private void awaitContinuations(long expected, String name) throws InterruptedException {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
      synchronized (completionLock) {
        while (completedContinuations < expected) {
          long remaining = deadline - System.nanoTime();
          require(remaining > 0L, name + " timed out");
          TimeUnit.NANOSECONDS.timedWait(completionLock, remaining);
        }
      }
    }

    private Set<Long> javaThreadIds() {
      Set<Long> result = Collections.newSetFromMap(new ConcurrentHashMap<Long, Boolean>());
      for (Carrier identity : identities) {
        result.add(Long.valueOf(identity.javaThreadId));
      }
      return result;
    }

    private Throwable failure() {
      return failure.get();
    }

    @Override
    public synchronized void close() throws InterruptedException {
      if (closed) {
        return;
      }
      closed = true;
      for (BlockingQueue<SchedulerItem> queue : queues) {
        queue.add(STOP);
      }
      for (Thread worker : workers) {
        worker.join(TimeUnit.SECONDS.toMillis(5L));
        require(!worker.isAlive(), "virtual carrier did not terminate: " + worker.getName());
      }
    }
  }

  private static final class SchedulerItem {
    private final Runnable continuation;
    private final DirectCall direct;
    private final boolean stop;

    private SchedulerItem(Runnable continuation, DirectCall direct, boolean stop) {
      this.continuation = continuation;
      this.direct = direct;
      this.stop = stop;
    }
  }

  private static final class DeterministicPlatformExecutor implements Executor, AutoCloseable {
    private static final PlatformItem STOP = new PlatformItem(null, null, true);

    private final List<BlockingQueue<PlatformItem>> queues =
        new ArrayList<BlockingQueue<PlatformItem>>();
    private final List<Thread> workers = new ArrayList<Thread>();
    private final List<Carrier> identities;
    private final CountDownLatch started;
    private final AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
    private final Object completionLock = new Object();
    private long completedTasks;
    private int submissions;
    private boolean closed;

    private DeterministicPlatformExecutor(int size) throws Exception {
      started = new CountDownLatch(size);
      identities = new ArrayList<Carrier>(Collections.nCopies(size, (Carrier) null));
      for (int index = 0; index < size; index++) {
        final int worker = index;
        BlockingQueue<PlatformItem> queue = new LinkedBlockingQueue<PlatformItem>();
        queues.add(queue);
        Thread thread =
            new Thread(
                new Runnable() {
                  @Override
                  public void run() {
                    workerLoop(worker);
                  }
                },
                "obi-java21-platform-" + index);
        thread.setDaemon(true);
        workers.add(thread);
        thread.start();
      }
      await(started, "platform worker startup");
    }

    @Override
    public synchronized void execute(Runnable command) {
      if (closed) {
        throw new IllegalStateException("platform executor is closed");
      }
      int worker =
          command instanceof RelayTask
              ? ((((RelayTask) command).parent.index + 1) % queues.size())
              : submissions++ % queues.size();
      queues.get(worker).add(new PlatformItem(command, null, false));
    }

    private void warmup() throws Exception {
      long start = completedTasks();
      List<WarmupTask> warmups = new ArrayList<WarmupTask>();
      for (int index = 0; index < queues.size(); index++) {
        WarmupTask task = new WarmupTask();
        warmups.add(task);
        execute(task);
      }
      awaitCompleted(start + queues.size(), "platform worker warmup");
      for (WarmupTask task : warmups) {
        require(taskContext(task) == null, "platform warmup retained task context");
      }
    }

    private void runDirect(int worker, CheckedRunnable action) throws Exception {
      require(worker >= 0 && worker < queues.size(), "invalid platform worker index");
      DirectCall direct = new DirectCall(action);
      queues.get(worker).add(new PlatformItem(null, direct, false));
      direct.await("platform direct observation " + worker);
    }

    private void workerLoop(int index) {
      identities.set(index, new Carrier(Thread.currentThread().getId(), nativeThreadId()));
      started.countDown();
      try {
        for (; ; ) {
          PlatformItem item = queues.get(index).take();
          if (item == STOP || item.stop) {
            return;
          }
          if (item.direct != null) {
            item.direct.run();
            continue;
          }
          try {
            item.task.run();
          } catch (Throwable problem) {
            failure.compareAndSet(null, problem);
          } finally {
            synchronized (completionLock) {
              completedTasks++;
              completionLock.notifyAll();
            }
          }
        }
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        failure.compareAndSet(null, interrupted);
      } catch (Throwable problem) {
        failure.compareAndSet(null, problem);
      }
    }

    private long completedTasks() {
      synchronized (completionLock) {
        return completedTasks;
      }
    }

    private void awaitCompleted(long expected, String name) throws InterruptedException {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(TIMEOUT_SECONDS);
      synchronized (completionLock) {
        while (completedTasks < expected) {
          long remaining = deadline - System.nanoTime();
          require(remaining > 0L, name + " timed out");
          TimeUnit.NANOSECONDS.timedWait(completionLock, remaining);
        }
      }
    }

    private Set<Long> javaThreadIds() {
      Set<Long> result = Collections.newSetFromMap(new ConcurrentHashMap<Long, Boolean>());
      for (Carrier identity : identities) {
        result.add(Long.valueOf(identity.javaThreadId));
      }
      return result;
    }

    private Throwable failure() {
      return failure.get();
    }

    @Override
    public synchronized void close() throws InterruptedException {
      if (closed) {
        return;
      }
      closed = true;
      for (BlockingQueue<PlatformItem> queue : queues) {
        queue.add(STOP);
      }
      for (Thread worker : workers) {
        worker.join(TimeUnit.SECONDS.toMillis(5L));
        require(!worker.isAlive(), "platform worker did not terminate: " + worker.getName());
      }
    }
  }

  private static final class PlatformItem {
    private final Runnable task;
    private final DirectCall direct;
    private final boolean stop;

    private PlatformItem(Runnable task, DirectCall direct, boolean stop) {
      this.task = task;
      this.direct = direct;
      this.stop = stop;
    }
  }

  private static final class WarmupTask implements Runnable {
    @Override
    public void run() {}
  }

  private static final class DirectCall implements Runnable {
    private final CheckedRunnable action;
    private final CountDownLatch completed = new CountDownLatch(1);
    private final AtomicReference<Throwable> failure = new AtomicReference<Throwable>();

    private DirectCall(CheckedRunnable action) {
      this.action = action;
    }

    @Override
    public void run() {
      try {
        action.run();
      } catch (Throwable problem) {
        failure.compareAndSet(null, problem);
      } finally {
        completed.countDown();
      }
    }

    private void await(String name) throws Exception {
      OfficialAgentJava21ConcurrencyProbe.await(completed, name);
      Throwable problem = failure.get();
      if (problem != null) {
        throw new IllegalStateException(name + " failed", problem);
      }
    }
  }
}
