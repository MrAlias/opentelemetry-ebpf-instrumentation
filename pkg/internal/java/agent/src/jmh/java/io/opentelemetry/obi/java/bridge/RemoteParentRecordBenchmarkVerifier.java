/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import java.lang.reflect.Method;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

/** Build-time smoke check that the named bridge benchmarks invoke their measured providers. */
public final class RemoteParentRecordBenchmarkVerifier {
  private RemoteParentRecordBenchmarkVerifier() {}

  public static void main(String[] args) throws ReflectiveOperationException {
    verifyJmhMetadata();
    RemoteParentRecordBenchmark benchmark = new RemoteParentRecordBenchmark();

    RemoteParentRecordBenchmark.HitBridgeState hit =
        new RemoteParentRecordBenchmark.HitBridgeState();
    hit.install();
    try {
      requireExact(
          "bridgeTakeHit", benchmark.bridgeTakeHit(hit), hit.expected(), RemoteParentStatus.VALID);
    } finally {
      hit.reset();
    }

    RemoteParentRecordBenchmark.MissBridgeState miss =
        new RemoteParentRecordBenchmark.MissBridgeState();
    miss.install();
    try {
      requireExact(
          "bridgeTakeMiss",
          benchmark.bridgeTakeMiss(miss),
          miss.expected(),
          RemoteParentStatus.MISSING);
    } finally {
      miss.reset();
    }
  }

  private static void verifyJmhMetadata() throws ReflectiveOperationException {
    requireScope(RemoteParentRecordBenchmark.class, Scope.Thread);
    requireScope(RemoteParentRecordBenchmark.HitBridgeState.class, Scope.Benchmark);
    requireScope(RemoteParentRecordBenchmark.MissBridgeState.class, Scope.Benchmark);

    requireBenchmark(
        RemoteParentRecordBenchmark.class.getMethod(
            "bridgeTakeHit", RemoteParentRecordBenchmark.HitBridgeState.class));
    requireBenchmark(
        RemoteParentRecordBenchmark.class.getMethod(
            "bridgeTakeMiss", RemoteParentRecordBenchmark.MissBridgeState.class));
    requireLifecycle(RemoteParentRecordBenchmark.HitBridgeState.class);
    requireLifecycle(RemoteParentRecordBenchmark.MissBridgeState.class);
  }

  private static void requireScope(Class<?> type, Scope expected) {
    State state = type.getAnnotation(State.class);
    if (state == null || state.value() != expected) {
      throw new IllegalStateException(type.getName() + " must use JMH state scope " + expected);
    }
  }

  private static void requireBenchmark(Method method) {
    if (method.getAnnotation(Benchmark.class) == null) {
      throw new IllegalStateException(method + " must remain a JMH benchmark");
    }
  }

  private static void requireLifecycle(Class<?> type) throws ReflectiveOperationException {
    Method install = type.getMethod("install");
    Method reset = type.getMethod("reset");
    Setup setup = install.getAnnotation(Setup.class);
    TearDown tearDown = reset.getAnnotation(TearDown.class);
    if (setup == null || setup.value() != Level.Trial) {
      throw new IllegalStateException(install + " must remain a trial setup");
    }
    if (tearDown == null || tearDown.value() != Level.Trial) {
      throw new IllegalStateException(reset + " must remain a trial teardown");
    }
  }

  private static void requireExact(
      String benchmark, RemoteParentRecord record, RemoteParentRecord expected, int status) {
    if (record == null || record != expected || record.getStatus() != status) {
      throw new IllegalStateException(
          benchmark
              + " returned status "
              + (record == null ? "null" : record.getStatus())
              + ", expected "
              + status);
    }
  }
}
