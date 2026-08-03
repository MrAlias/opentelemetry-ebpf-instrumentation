// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class TlsRecordObserverTest {
  @Test
  void capturesOnlyArmedApplicationRecordLengthsAcrossFragmentedWrites() throws Exception {
    TlsRecordObserver observer = new TlsRecordObserver();
    ByteArrayOutputStream delegate = new ByteArrayOutputStream();
    OutputStream output = observer.observe(delegate);

    output.write(record(22, new byte[] {1, 2, 3}));
    observer.arm();

    byte[] first = record(23, "first-secret".getBytes(StandardCharsets.US_ASCII));
    output.write(first, 0, 2);
    output.write(first, 2, 4);
    for (int index = 6; index < first.length; index++) {
      output.write(first[index]);
    }
    output.write(record(21, new byte[] {0, 1}));
    output.write(record(23, "second-secret".getBytes(StandardCharsets.US_ASCII)));

    TlsRecordObserver.Snapshot snapshot = observer.disarmAndSnapshot();
    assertEquals(List.of(0x0303, 0x0303), snapshot.legacyVersions());
    assertEquals(List.of(12, 13), snapshot.payloadLengths());
    assertEquals(5 + 3 + 5 + 12 + 5 + 2 + 5 + 13, delegate.size());
    assertRetainsOnlyHeaderAndNumericMetadata(observer, record(23, new byte[13]));
  }

  @Test
  void requiresCompleteRecordBoundariesAtArmAndSnapshot() throws Exception {
    TlsRecordObserver armObserver = new TlsRecordObserver();
    OutputStream armOutput = armObserver.observe(new ByteArrayOutputStream());
    armOutput.write(new byte[] {22, 3});
    assertThrows(IOException.class, armObserver::arm);

    TlsRecordObserver snapshotObserver = new TlsRecordObserver();
    OutputStream snapshotOutput = snapshotObserver.observe(new ByteArrayOutputStream());
    snapshotObserver.arm();
    byte[] partial = record(23, new byte[] {1, 2, 3});
    snapshotOutput.write(partial, 0, partial.length - 1);
    assertThrows(IOException.class, snapshotObserver::disarmAndSnapshot);
  }

  @Test
  void rejectsOversizedRecordsAndUnboundedApplicationRecordCounts() throws Exception {
    TlsRecordObserver oversized = new TlsRecordObserver();
    OutputStream oversizedOutput = oversized.observe(new ByteArrayOutputStream());
    int length = TlsRecordObserver.MAX_TLS_RECORD_PAYLOAD_BYTES + 1;
    assertThrows(
        IOException.class,
        () ->
            oversizedOutput.write(
                new byte[] {23, 3, 3, (byte) (length >>> 8), (byte) length}));

    TlsRecordObserver count = new TlsRecordObserver();
    OutputStream countOutput = count.observe(new ByteArrayOutputStream());
    count.arm();
    for (int index = 0; index < TlsRecordObserver.MAX_CAPTURED_APPLICATION_RECORDS; index++) {
      countOutput.write(record(23, new byte[] {(byte) index}));
    }
    assertThrows(
        IOException.class,
        () -> countOutput.write(record(23, new byte[] {(byte) 0xff})));
  }

  @Test
  void rejectsUnexpectedApplicationDataLegacyVersionAfterArming() throws Exception {
    TlsRecordObserver observer = new TlsRecordObserver();
    OutputStream output = observer.observe(new ByteArrayOutputStream());
    observer.arm();

    byte[] invalid = record(23, new byte[] {1});
    invalid[2] = 2;
    assertThrows(IOException.class, () -> output.write(invalid));
  }

  @Test
  void stateTransitionsAreClosed() throws Exception {
    TlsRecordObserver observer = new TlsRecordObserver();

    assertThrows(IOException.class, observer::disarmAndSnapshot);
    observer.arm();
    assertThrows(IOException.class, observer::arm);
    TlsRecordObserver.Snapshot snapshot = observer.disarmAndSnapshot();
    assertEquals(List.of(), snapshot.legacyVersions());
    assertEquals(List.of(), snapshot.payloadLengths());
  }

  private static void assertRetainsOnlyHeaderAndNumericMetadata(
      TlsRecordObserver observer, byte[] expectedLastRecord) throws Exception {
    int retainedByteArrays = 0;
    for (Field field : TlsRecordObserver.class.getDeclaredFields()) {
      if (Modifier.isStatic(field.getModifiers())) {
        continue;
      }
      field.setAccessible(true);
      Object value = field.get(observer);
      if (value instanceof byte[] retainedBytes) {
        retainedByteArrays++;
        assertArrayEquals(
            java.util.Arrays.copyOf(expectedLastRecord, TlsRecordObserver.TLS_HEADER_BYTES),
            retainedBytes);
      } else if (value instanceof List<?> retainedValues) {
        assertTrue(retainedValues.stream().allMatch(Integer.class::isInstance));
      } else {
        assertFalse(value instanceof CharSequence);
        assertFalse(value instanceof ByteArrayOutputStream);
      }
    }
    assertEquals(1, retainedByteArrays);
  }

  private static byte[] record(int type, byte[] payload) {
    byte[] result = new byte[TlsRecordObserver.TLS_HEADER_BYTES + payload.length];
    result[0] = (byte) type;
    result[1] = 3;
    result[2] = 3;
    result[3] = (byte) (payload.length >>> 8);
    result[4] = (byte) payload.length;
    System.arraycopy(payload, 0, result, TlsRecordObserver.TLS_HEADER_BYTES, payload.length);
    return result;
  }
}
