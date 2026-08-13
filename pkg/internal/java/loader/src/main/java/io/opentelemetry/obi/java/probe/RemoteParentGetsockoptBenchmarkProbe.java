/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.bridge.RemoteParentBootstrap;
import io.opentelemetry.obi.java.bridge.RemoteParentRecord;
import io.opentelemetry.obi.java.bridge.RemoteParentStatus;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Coordinates a packaged-agent Java-to-JNI getsockopt benchmark with the privileged BPF fixture.
 *
 * <p>Map staging and socket acknowledgement happen before the timed command. The measured region
 * contains one direct Java native-method invocation with a reused response array.
 */
public final class RemoteParentGetsockoptBenchmarkProbe {
  private static final int PACKET_SIZE = 64;
  private static final int MAX_ITERATIONS = 100_000;

  private RemoteParentGetsockoptBenchmarkProbe() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      throw new IllegalArgumentException(
          "expected bind host, process capability, warmup iterations, and measurement iterations");
    }

    String host = args[0];
    long processCapability = Long.parseUnsignedLong(args[1]);
    int warmupIterations = boundedIterations(args[2], "warmup iterations");
    int measurementIterations = boundedIterations(args[3], "measurement iterations");
    if (processCapability == 0L) {
      throw new IllegalArgumentException("process capability must be nonzero");
    }
    if (!RemoteParentBootstrap.initialize("getsockopt", "", 1_000, 0L, processCapability)) {
      throw new IllegalStateException("remote-parent getsockopt transport is not ready");
    }

    byte[] response = new byte[RemoteParentRecord.RECORD_SIZE];
    NativeMemory packet = new NativeMemory(PACKET_SIZE);
    try (ServerSocket listener = new ServerSocket();
        BufferedReader commands =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
      listener.bind(new InetSocketAddress(host, 0));
      print("LISTEN port=%d", listener.getLocalPort());
      try (Socket socket = listener.accept()) {
        int socketFileDescriptor = BootstrapNative.socketFileDescriptor(socket);
        if (socketFileDescriptor < 0) {
          throw new IllegalStateException("socket file descriptor is unavailable");
        }

        print(
            "READY tid=%d fd=%d warmup_iterations=%d measurement_iterations=%d",
            BootstrapNative.gettid(),
            socketFileDescriptor,
            warmupIterations,
            measurementIterations);
        runSeries(
            commands,
            packet,
            response,
            socketFileDescriptor,
            "miss",
            RemoteParentStatus.MISSING,
            warmupIterations,
            measurementIterations);
        runSeries(
            commands,
            packet,
            response,
            socketFileDescriptor,
            "hit",
            RemoteParentStatus.VALID,
            warmupIterations,
            measurementIterations);
        print("DONE samples=%d", 2 * measurementIterations);
      }
    }
  }

  private static void runSeries(
      BufferedReader commands,
      NativeMemory packet,
      byte[] response,
      int socketFileDescriptor,
      String outcome,
      int expectedStatus,
      int warmupIterations,
      int measurementIterations)
      throws Exception {
    int total = warmupIterations + measurementIterations;
    for (int iteration = 0; iteration < total; iteration++) {
      String phase = iteration < warmupIterations ? "warmup" : "measurement";
      int phaseIteration = iteration < warmupIterations ? iteration : iteration - warmupIterations;
      String[] arm = command(commands, "ARM", phase, outcome, phaseIteration, 5);
      long expectedGeneration = Long.parseUnsignedLong(arm[4]);

      int emit = BootstrapNative.emitData(socketFileDescriptor, packet.getAddress(), true);
      long nonce = packet.getLong(41);
      print(
          "ARMED phase=%s outcome=%s iteration=%d emit=%d nonce=%s",
          phase, outcome, phaseIteration, emit, Long.toUnsignedString(nonce));
      if (emit != 1) {
        throw new IllegalStateException("primary data acknowledgement failed: " + emit);
      }

      command(commands, "TAKE", phase, outcome, phaseIteration, 4);
      long started = System.nanoTime();
      int status = BootstrapNative.takeRemoteParent(socketFileDescriptor, response);
      long duration = System.nanoTime() - started;
      if (duration <= 0L) {
        throw new IllegalStateException("non-positive measured duration");
      }
      if (status != expectedStatus || Byte.toUnsignedInt(response[8]) != expectedStatus) {
        throw new IllegalStateException(
            "unexpected " + outcome + " status: native=" + status + " record=" + response[8]);
      }
      long generation = readUnsignedLongLE(response, 40);
      if (generation != expectedGeneration) {
        throw new IllegalStateException(
            "unexpected " + outcome + " generation: " + Long.toUnsignedString(generation));
      }
      BootstrapNative.clearRemoteParentSocketFileDescriptor();
      print(
          "SAMPLE phase=%s outcome=%s iteration=%d status=%d generation=%s duration_ns=%d",
          phase, outcome, phaseIteration, status, Long.toUnsignedString(generation), duration);
    }
  }

  private static String[] command(
      BufferedReader commands,
      String expectedCommand,
      String expectedPhase,
      String expectedOutcome,
      int expectedIteration,
      int expectedFields)
      throws Exception {
    String line = commands.readLine();
    if (line == null) {
      throw new IllegalStateException("command stream ended before " + expectedCommand);
    }
    String[] fields = line.split(" ", -1);
    if (fields.length != expectedFields
        || !expectedCommand.equals(fields[0])
        || !expectedPhase.equals(fields[1])
        || !expectedOutcome.equals(fields[2])
        || Integer.parseInt(fields[3]) != expectedIteration) {
      throw new IllegalStateException("unexpected command: " + line);
    }
    return fields;
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
