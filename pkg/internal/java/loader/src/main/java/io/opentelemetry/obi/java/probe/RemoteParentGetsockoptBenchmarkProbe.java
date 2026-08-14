/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import com.sun.management.ThreadMXBean;
import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.bridge.RemoteParentBootstrap;
import io.opentelemetry.obi.java.bridge.RemoteParentBridge;
import io.opentelemetry.obi.java.bridge.RemoteParentRecord;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;

/** Coordinates the packaged-agent concurrent Java/JNI remote-parent transport benchmark. */
public final class RemoteParentGetsockoptBenchmarkProbe {
  private static final int PACKET_SIZE = 64;
  private static final int MAX_ITERATIONS = 100_000;
  private static final int WORKERS = 8;

  private RemoteParentGetsockoptBenchmarkProbe() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 5) {
      throw new IllegalArgumentException(
          "expected bind host, process capability, warmup iterations, measurement iterations, and"
              + " workers");
    }

    String host = args[0];
    long processCapability = Long.parseUnsignedLong(args[1]);
    int warmupIterations = boundedIterations(args[2], "warmup iterations");
    int measurementIterations = boundedIterations(args[3], "measurement iterations");
    int workers = positiveInt(args[4], "workers");
    if (workers != WORKERS) {
      throw new IllegalArgumentException("workers must equal " + WORKERS);
    }
    if (processCapability == 0L) {
      throw new IllegalArgumentException("process capability must be nonzero");
    }

    ThreadMXBean allocationBean = allocationBean();
    Worker[] workerPool = new Worker[workers];
    try (ServerSocket listener = new ServerSocket();
        BufferedReader commands =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
      listener.bind(new InetSocketAddress(host, 0));
      print("LISTEN port=%d", listener.getLocalPort());
      for (int index = 0; index < workers; index++) {
        Socket socket = listener.accept();
        workerPool[index] = new Worker(index, socket, allocationBean);
        workerPool[index].start();
      }
      for (Worker worker : workerPool) {
        worker.awaitStarted();
        print(
            "READY worker=%d tid=%d fd=%d allocation_thread_id=%d warmup_iterations=%d"
                + " measurement_iterations=%d workers=%d allocation_supported=1"
                + " allocation_enabled=1",
            worker.index,
            worker.tid,
            worker.socketFileDescriptor,
            worker.javaThreadID,
            warmupIterations,
            measurementIterations,
            workers);
      }

      int retainedSamples = 0;
      while (true) {
        String line = commands.readLine();
        if (line == null) {
          throw new IllegalStateException("command stream ended before DONE");
        }
        String[] fields = line.split(" ", -1);
        switch (fields[0]) {
          case "CONFIG":
            configure(fields, processCapability);
            break;
          case "ARM_BATCH":
            armBatch(fields, workerPool);
            break;
          case "TAKE_BATCH":
            retainedSamples += takeBatch(fields, workerPool);
            break;
          case "DONE":
            if (fields.length != 1) {
              throw new IllegalStateException("unexpected DONE command: " + line);
            }
            print("DONE samples=%d", retainedSamples);
            return;
          default:
            throw new IllegalStateException("unexpected command: " + line);
        }
      }
    } finally {
      for (Worker worker : workerPool) {
        if (worker != null) {
          worker.close();
        }
      }
    }
  }

  private static ThreadMXBean allocationBean() {
    java.lang.management.ThreadMXBean platform = ManagementFactory.getThreadMXBean();
    if (!(platform instanceof ThreadMXBean)) {
      throw new IllegalStateException("ThreadMXBean allocated-byte accounting is unavailable");
    }
    ThreadMXBean bean = (ThreadMXBean) platform;
    if (!bean.isThreadAllocatedMemorySupported()) {
      throw new IllegalStateException("ThreadMXBean allocated-byte accounting is unsupported");
    }
    if (!bean.isThreadAllocatedMemoryEnabled()) {
      bean.setThreadAllocatedMemoryEnabled(true);
    }
    if (!bean.isThreadAllocatedMemoryEnabled()) {
      throw new IllegalStateException(
          "ThreadMXBean allocated-byte accounting could not be enabled");
    }
    return bean;
  }

  private static void configure(String[] fields, long processCapability) {
    if (fields.length != 5 || !"CONFIG".equals(fields[0])) {
      throw new IllegalStateException("unexpected CONFIG command");
    }
    String transport = fields[1];
    String socketPath = "-".equals(fields[2]) ? "" : fields[2];
    int timeoutMillis = positiveInt(fields[3], "timeout milliseconds");
    long serverUid = Long.parseUnsignedLong(fields[4]);
    if (!("getsockopt".equals(transport) || "unix".equals(transport))) {
      throw new IllegalStateException("unexpected transport: " + transport);
    }
    boolean ready =
        RemoteParentBootstrap.initialize(
            transport, socketPath, timeoutMillis, serverUid, processCapability);
    if (!ready) {
      throw new IllegalStateException("remote-parent transport is not ready: " + transport);
    }
    print(
        "CONFIGURED transport=%s timeout_millis=%d server_uid=%s",
        transport, timeoutMillis, Long.toUnsignedString(serverUid));
  }

  private static void armBatch(String[] fields, Worker[] workers) throws Exception {
    if (fields.length != 7 + workers.length || !"ARM_BATCH".equals(fields[0])) {
      throw new IllegalStateException("unexpected ARM_BATCH command");
    }
    Batch batch = Batch.from(fields, workers.length, false);
    if (!"getsockopt".equals(batch.transport)) {
      for (int index = 0; index < workers.length; index++) {
        long generation = Long.parseUnsignedLong(fields[7 + index]);
        workers[index].submit(Job.arm(batch, generation));
      }
      batch.releaseAndAwait();
      for (Worker worker : workers) {
        Result result = worker.result();
        result.rethrow();
        print(
            "ARMED phase=%s scope=%s transport=%s outcome=%s iteration=%d worker=%d emit=%d"
                + " nonce=%s",
            batch.phase,
            batch.scope,
            batch.transport,
            batch.outcome,
            batch.iteration,
            worker.index,
            result.emit,
            Long.toUnsignedString(result.nonce));
      }
      return;
    }
    // Primary DATA_ACK uses a process-global native nonce. Arm getsockopt
    // workers one at a time so each staged nonce remains bound to its worker's
    // socket and generation. TAKE_BATCH retains one concurrent latch.
    for (int index = 0; index < workers.length; index++) {
      long generation = Long.parseUnsignedLong(fields[7 + index]);
      Worker worker = workers[index];
      Batch workerBatch = batch.forSingleWorker();
      worker.submit(Job.arm(workerBatch, generation));
      workerBatch.releaseAndAwait();
      Result result = worker.result();
      result.rethrow();
      print(
          "ARMED phase=%s scope=%s transport=%s outcome=%s iteration=%d worker=%d emit=%d nonce=%s",
          batch.phase,
          batch.scope,
          batch.transport,
          batch.outcome,
          batch.iteration,
          index,
          result.emit,
          Long.toUnsignedString(result.nonce));
    }
  }

  private static int takeBatch(String[] fields, Worker[] workers) throws Exception {
    if (fields.length != 6 || !"TAKE_BATCH".equals(fields[0])) {
      throw new IllegalStateException("unexpected TAKE_BATCH command");
    }
    Batch batch = Batch.from(fields, workers.length, true);
    for (Worker worker : workers) {
      workers[worker.index].submit(Job.take(batch, worker.armedGeneration, worker.armedStatus));
    }
    batch.releaseAndAwait();
    int retained = 0;
    for (Worker worker : workers) {
      Result result = worker.result();
      result.rethrow();
      print(
          "SAMPLE phase=%s scope=%s transport=%s outcome=%s iteration=%d worker=%d status=%d"
              + " generation=%s duration_ns=%d allocated_bytes=%d allocation_control_bytes=%d"
              + " java_calls=1 native_calls=1 bridge_calls=%d",
          batch.phase,
          batch.scope,
          batch.transport,
          batch.outcome,
          batch.iteration,
          worker.index,
          result.status,
          Long.toUnsignedString(result.generation),
          result.durationNS,
          result.allocatedBytes,
          result.allocationControlBytes,
          "bridge_provider_jni".equals(batch.scope) ? 1 : 0);
      if ("measurement".equals(batch.phase)) {
        retained++;
      }
    }
    return retained;
  }

  private static final class Batch {
    final String phase;
    final String scope;
    final String transport;
    final String outcome;
    final int iteration;
    final int expectedStatus;
    final CountDownLatch ready;
    final CountDownLatch start = new CountDownLatch(1);
    final CountDownLatch done;

    private Batch(
        String phase,
        String scope,
        String transport,
        String outcome,
        int iteration,
        int expectedStatus,
        int workers) {
      this.phase = phase;
      this.scope = scope;
      this.transport = transport;
      this.outcome = outcome;
      this.iteration = iteration;
      this.expectedStatus = expectedStatus;
      this.ready = new CountDownLatch(workers);
      this.done = new CountDownLatch(workers);
    }

    static Batch from(String[] fields, int workers, boolean take) {
      int expectedLength = take ? 6 : 7 + workers;
      if (fields.length != expectedLength) {
        throw new IllegalStateException("unexpected batch field count");
      }
      String phase = fields[1];
      String scope = fields[2];
      String transport = fields[3];
      String outcome = fields[4];
      int iteration = Integer.parseInt(fields[5]);
      int status = take ? -1 : Integer.parseInt(fields[6]);
      if (!("warmup".equals(phase) || "measurement".equals(phase))) {
        throw new IllegalStateException("unexpected phase: " + phase);
      }
      if (!("raw_jni".equals(scope) || "bridge_provider_jni".equals(scope))) {
        throw new IllegalStateException("unexpected scope: " + scope);
      }
      if (!("getsockopt".equals(transport) || "unix".equals(transport))) {
        throw new IllegalStateException("unexpected transport: " + transport);
      }
      return new Batch(phase, scope, transport, outcome, iteration, status, workers);
    }

    Batch forSingleWorker() {
      return new Batch(phase, scope, transport, outcome, iteration, expectedStatus, 1);
    }

    void releaseAndAwait() throws InterruptedException {
      ready.await();
      start.countDown();
      done.await();
    }
  }

  private static final class Job {
    final Batch batch;
    final boolean arm;
    final long expectedGeneration;
    final int expectedStatus;

    private Job(Batch batch, boolean arm, long expectedGeneration, int expectedStatus) {
      this.batch = batch;
      this.arm = arm;
      this.expectedGeneration = expectedGeneration;
      this.expectedStatus = expectedStatus;
    }

    static Job arm(Batch batch, long generation) {
      return new Job(batch, true, generation, batch.expectedStatus);
    }

    static Job take(Batch batch, long generation, int status) {
      return new Job(batch, false, generation, status);
    }
  }

  private static final class Result {
    Throwable failure;
    int emit;
    long nonce;
    int status;
    long generation;
    long durationNS;
    long allocatedBytes;
    long allocationControlBytes;

    void rethrow() {
      if (failure != null) {
        throw new IllegalStateException("benchmark worker failed", failure);
      }
    }
  }

  private static final class Worker implements AutoCloseable, Runnable {
    final int index;
    final Socket socket;
    final ThreadMXBean allocationBean;
    final NativeMemory packet = new NativeMemory(PACKET_SIZE);
    final byte[] response = new byte[RemoteParentRecord.RECORD_SIZE];
    final ArrayBlockingQueue<Job> jobs = new ArrayBlockingQueue<>(1);
    final CountDownLatch started = new CountDownLatch(1);
    final Thread thread;
    volatile long tid;
    volatile long javaThreadID;
    volatile int socketFileDescriptor = -1;
    volatile Result result;
    volatile boolean closing;
    long armedGeneration;
    int armedStatus;
    String armedIdentity;

    Worker(int index, Socket socket, ThreadMXBean allocationBean) {
      this.index = index;
      this.socket = socket;
      this.allocationBean = allocationBean;
      this.thread = new Thread(this, "obi-remote-parent-benchmark-" + index);
    }

    void start() {
      thread.start();
    }

    void awaitStarted() throws InterruptedException {
      started.await();
      result.rethrow();
    }

    void submit(Job job) throws InterruptedException {
      result = null;
      jobs.put(job);
    }

    Result result() {
      if (result == null) {
        throw new IllegalStateException("worker did not publish a result");
      }
      return result;
    }

    @Override
    public void run() {
      try {
        tid = BootstrapNative.gettid();
        javaThreadID = Thread.currentThread().getId();
        socketFileDescriptor = BootstrapNative.socketFileDescriptor(socket);
        if (tid <= 0L || javaThreadID <= 0L || socketFileDescriptor < 0) {
          throw new IllegalStateException("worker native identity is unavailable");
        }
        result = new Result();
      } catch (Throwable failure) {
        Result failed = new Result();
        failed.failure = failure;
        result = failed;
      } finally {
        started.countDown();
      }
      if (result.failure != null) {
        return;
      }

      while (!closing) {
        Job job;
        try {
          job = jobs.take();
        } catch (InterruptedException interrupted) {
          if (closing) {
            return;
          }
          Thread.currentThread().interrupt();
          return;
        }
        Result next = new Result();
        boolean readySignaled = false;
        try {
          if (!job.arm && "bridge_provider_jni".equals(job.batch.scope)) {
            ThreadInfo.markRemoteParentDirectLookup();
            if ("getsockopt".equals(job.batch.transport)) {
              ThreadInfo.setRemoteParentSocketFileDescriptor(socketFileDescriptor);
            }
          }
          job.batch.ready.countDown();
          readySignaled = true;
          job.batch.start.await();
          if (job.arm) {
            boolean stagedUnix =
                "unix".equals(job.batch.transport)
                    && ("hit".equals(job.batch.outcome) || "stale".equals(job.batch.outcome));
            if ("getsockopt".equals(job.batch.transport) || stagedUnix) {
              next.emit = BootstrapNative.emitData(socketFileDescriptor, packet.getAddress(), true);
              next.nonce = packet.getLong(41);
              int expectedEmit = "getsockopt".equals(job.batch.transport) ? 1 : 0;
              if (next.emit != expectedEmit) {
                throw new IllegalStateException(
                    "unexpected data emission result: got " + next.emit + ", want " + expectedEmit);
              }
              if (next.nonce == 0L) {
                throw new IllegalStateException("data emission returned a zero nonce");
              }
            }
            armedGeneration = job.expectedGeneration;
            armedStatus = job.expectedStatus;
            armedIdentity = batchIdentity(job.batch);
          } else {
            if (!batchIdentity(job.batch).equals(armedIdentity)) {
              throw new IllegalStateException("TAKE_BATCH does not match the armed batch");
            }
            measure(job, next);
          }
        } catch (Throwable failure) {
          next.failure = failure;
        } finally {
          if (!readySignaled) {
            job.batch.ready.countDown();
          }
          result = next;
          job.batch.done.countDown();
        }
      }
    }

    private void measure(Job job, Result next) {
      long controlBefore = allocationBean.getThreadAllocatedBytes(javaThreadID);
      long controlAfter = allocationBean.getThreadAllocatedBytes(javaThreadID);
      next.allocationControlBytes = allocationDelta(controlBefore, controlAfter, "control");

      long allocatedBefore;
      long allocatedAfter;
      long startedNS;
      long finishedNS;
      RemoteParentRecord providerRecord = null;
      if ("raw_jni".equals(job.batch.scope)) {
        int fd = "getsockopt".equals(job.batch.transport) ? socketFileDescriptor : -1;
        allocatedBefore = allocationBean.getThreadAllocatedBytes(javaThreadID);
        startedNS = System.nanoTime();
        next.status = BootstrapNative.takeRemoteParent(fd, response);
        finishedNS = System.nanoTime();
        allocatedAfter = allocationBean.getThreadAllocatedBytes(javaThreadID);
      } else {
        allocatedBefore = allocationBean.getThreadAllocatedBytes(javaThreadID);
        startedNS = System.nanoTime();
        providerRecord = RemoteParentBridge.takeRemoteParent();
        finishedNS = System.nanoTime();
        allocatedAfter = allocationBean.getThreadAllocatedBytes(javaThreadID);
      }
      next.durationNS = finishedNS - startedNS;
      next.allocatedBytes = allocationDelta(allocatedBefore, allocatedAfter, "call");
      if (next.durationNS <= 0L) {
        throw new IllegalStateException("non-positive measured duration");
      }
      if ("raw_jni".equals(job.batch.scope)) {
        if (next.status != Byte.toUnsignedInt(response[8])) {
          throw new IllegalStateException("native and response statuses disagree");
        }
        next.generation = readUnsignedLongLE(response, 40);
      } else {
        next.status = providerRecord.getStatus();
        next.generation = providerRecord.getGeneration();
      }
      if (next.status != job.expectedStatus) {
        throw new IllegalStateException(
            "unexpected status: got " + next.status + ", want " + job.expectedStatus);
      }
      if (next.generation != job.expectedGeneration) {
        throw new IllegalStateException(
            "unexpected generation: got "
                + Long.toUnsignedString(next.generation)
                + ", want "
                + Long.toUnsignedString(job.expectedGeneration));
      }
      ThreadInfo.clearRemoteParentLookupSource();
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
    }

    @Override
    public void close() throws Exception {
      closing = true;
      thread.interrupt();
      thread.join();
      socket.close();
    }
  }

  private static String batchIdentity(Batch batch) {
    return batch.phase
        + '\n'
        + batch.scope
        + '\n'
        + batch.transport
        + '\n'
        + batch.outcome
        + '\n'
        + batch.iteration;
  }

  private static long allocationDelta(long before, long after, String name) {
    if (before < 0L || after < before) {
      throw new IllegalStateException("invalid " + name + " allocated-byte counters");
    }
    return after - before;
  }

  private static long readUnsignedLongLE(byte[] value, int offset) {
    long result = 0L;
    for (int index = 0; index < Long.BYTES; index++) {
      result |= ((long) value[offset + index] & 0xffL) << (index * 8);
    }
    return result;
  }

  private static int positiveInt(String value, String name) {
    int parsed = Integer.parseInt(value);
    if (parsed <= 0) {
      throw new IllegalArgumentException(name + " must be positive");
    }
    return parsed;
  }

  private static int boundedIterations(String value, String name) {
    int parsed = positiveInt(value, name);
    if (parsed > MAX_ITERATIONS) {
      throw new IllegalArgumentException(name + " exceeds " + MAX_ITERATIONS);
    }
    return parsed;
  }

  private static void print(String format, Object... values) {
    System.out.println(String.format(Locale.ROOT, format, values));
    System.out.flush();
  }
}
