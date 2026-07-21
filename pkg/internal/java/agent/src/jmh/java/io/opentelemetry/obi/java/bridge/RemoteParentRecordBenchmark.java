/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class RemoteParentRecordBenchmark {
  private final byte[] hit = record(RemoteParentStatus.VALID);
  private final byte[] miss = record(RemoteParentStatus.MISSING);

  @Setup
  public void verifyFixtures() {
    if (RemoteParentRecord.decode(hit).getStatus() != RemoteParentStatus.VALID) {
      throw new IllegalStateException("hit fixture is not ABI-valid");
    }
  }

  @Benchmark
  public RemoteParentRecord decodeHit() {
    return RemoteParentRecord.decode(hit);
  }

  @Benchmark
  public RemoteParentRecord decodeMiss() {
    return RemoteParentRecord.decode(miss);
  }

  @Benchmark
  public RemoteParentRecord bridgeTakeHit(HitBridgeState state) {
    return RemoteParentBridge.takeRemoteParent();
  }

  @Benchmark
  public RemoteParentRecord bridgeTakeMiss(MissBridgeState state) {
    return RemoteParentBridge.takeRemoteParent();
  }

  private static byte[] record(int status) {
    byte[] bytes = new byte[RemoteParentRecord.RECORD_SIZE];
    bytes[0] = 'O';
    bytes[1] = 'B';
    bytes[2] = 'I';
    bytes[3] = 'J';
    bytes[4] = 1;
    bytes[6] = RemoteParentRecord.RECORD_SIZE;
    bytes[8] = (byte) status;
    if (status == RemoteParentStatus.VALID) {
      bytes[16] = 1;
      bytes[32] = 1;
      bytes[40] = 1;
      bytes[48] = 1;
    }
    return bytes;
  }

  private static final class FixedProvider implements RemoteParentProvider {
    private final RemoteParentRecord record;

    private FixedProvider(RemoteParentRecord record) {
      this.record = record;
    }

    @Override
    public int abiVersion() {
      return RemoteParentRecord.ABI_VERSION;
    }

    @Override
    public RemoteParentRecord takeRemoteParent() {
      return record;
    }

    @Override
    public RemoteParentRecord discardRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public void close() {}
  }

  @State(Scope.Benchmark)
  public static class HitBridgeState {
    @Setup
    public void install() {
      RemoteParentBridge.installProviderForTest(
          new FixedProvider(RemoteParentRecord.decode(record(RemoteParentStatus.VALID))));
    }

    @TearDown
    public void reset() {
      RemoteParentBridge.resetForTest();
    }
  }

  @State(Scope.Benchmark)
  public static class MissBridgeState {
    @Setup
    public void install() {
      RemoteParentBridge.installProviderForTest(
          new FixedProvider(RemoteParentRecord.decode(record(RemoteParentStatus.MISSING))));
    }

    @TearDown
    public void reset() {
      RemoteParentBridge.resetForTest();
    }
  }
}
