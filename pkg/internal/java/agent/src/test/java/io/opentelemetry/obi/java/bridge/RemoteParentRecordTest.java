/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class RemoteParentRecordTest {
  @Test
  void decodesAbiV1GoldenVector() {
    byte[] bytes = validRecord();

    RemoteParentRecord record = RemoteParentRecord.decode(bytes);

    assertEquals(RemoteParentRecord.ABI_VERSION, record.getAbiVersion());
    assertEquals(RemoteParentStatus.VALID, record.getStatus());
    assertEquals(1, record.getTraceFlags());
    assertEquals("000102030405060708090a0b0c0d0e0f", record.getTraceIdHex());
    assertEquals("1011121314151617", record.getParentSpanIdHex());
    assertEquals(0x0102030405060708L, record.getGeneration());
    assertEquals(0x1112131415161718L, record.getObservedMonotonicNanos());
  }

  @Test
  void preservesEveryDefinedNonValidStatus() {
    for (int status = RemoteParentStatus.MISSING; status <= RemoteParentStatus.DISABLED; status++) {
      if (status == RemoteParentStatus.VALID) {
        continue;
      }
      byte[] bytes = emptyRecord(status);
      RemoteParentRecord record = RemoteParentRecord.decode(bytes);
      assertEquals(status, record.getStatus());
      assertNull(record.getTraceIdHex());
      assertNull(record.getParentSpanIdHex());
    }
  }

  @Test
  void rejectsUnknownWireStatus() {
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentRecord.decode(emptyRecord(RemoteParentStatus.UNKNOWN)).getStatus());
  }

  @Test
  void rejectsMalformedAndTruncatedRecords() {
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentRecord.decode(new byte[RemoteParentRecord.RECORD_SIZE - 1]).getStatus());

    byte[] bytes = validRecord();
    bytes[0] = 'X';
    assertEquals(RemoteParentStatus.MALFORMED, RemoteParentRecord.decode(bytes).getStatus());

    bytes = validRecord();
    bytes[10] = 1;
    assertEquals(RemoteParentStatus.MALFORMED, RemoteParentRecord.decode(bytes).getStatus());

    bytes = validRecord();
    bytes[56] = 1;
    assertEquals(RemoteParentStatus.MALFORMED, RemoteParentRecord.decode(bytes).getStatus());
  }

  @Test
  void distinguishesVersionMismatch() {
    byte[] bytes = validRecord();
    putShort(bytes, 4, 2);
    assertEquals(RemoteParentStatus.VERSION_MISMATCH, RemoteParentRecord.decode(bytes).getStatus());
  }

  @Test
  void rejectsRecordsLargerThanTheExactV1Size() {
    byte[] v1 = validRecord();
    byte[] future = new byte[80];
    System.arraycopy(v1, 0, future, 0, v1.length);
    putShort(future, 6, future.length);
    future[64] = 1;

    assertEquals(RemoteParentStatus.MALFORMED, RemoteParentRecord.decode(future).getStatus());
  }

  @Test
  void rejectsInvalidValidPayloads() {
    byte[] bytes = validRecord();
    for (int i = 16; i < 32; i++) {
      bytes[i] = 0;
    }
    assertEquals(RemoteParentStatus.MALFORMED, RemoteParentRecord.decode(bytes).getStatus());

    bytes = validRecord();
    for (int i = 32; i < 40; i++) {
      bytes[i] = 0;
    }
    assertEquals(RemoteParentStatus.MALFORMED, RemoteParentRecord.decode(bytes).getStatus());

    bytes = validRecord();
    putShort(bytes, 6, RemoteParentRecord.RECORD_SIZE + 1);
    assertEquals(RemoteParentStatus.MALFORMED, RemoteParentRecord.decode(bytes).getStatus());

    bytes = validRecord();
    putLong(bytes, 40, 0);
    assertEquals(RemoteParentStatus.MALFORMED, RemoteParentRecord.decode(bytes).getStatus());

    bytes = validRecord();
    putLong(bytes, 48, 0);
    assertEquals(RemoteParentStatus.MALFORMED, RemoteParentRecord.decode(bytes).getStatus());
  }

  @Test
  void preservesFutureTraceFlagBits() {
    byte[] bytes = validRecord();
    bytes[9] = (byte) 0x81;

    RemoteParentRecord record = RemoteParentRecord.decode(bytes);

    assertEquals(RemoteParentStatus.VALID, record.getStatus());
    assertEquals(0x81, record.getTraceFlags());
  }

  static byte[] validRecord() {
    byte[] bytes = emptyRecord(RemoteParentStatus.VALID);
    bytes[9] = 1;
    for (int i = 0; i < 16; i++) {
      bytes[16 + i] = (byte) i;
    }
    for (int i = 0; i < 8; i++) {
      bytes[32 + i] = (byte) (16 + i);
    }
    putLong(bytes, 40, 0x0102030405060708L);
    putLong(bytes, 48, 0x1112131415161718L);
    return bytes;
  }

  private static byte[] emptyRecord(int status) {
    byte[] bytes = new byte[RemoteParentRecord.RECORD_SIZE];
    bytes[0] = 'O';
    bytes[1] = 'B';
    bytes[2] = 'I';
    bytes[3] = 'J';
    putShort(bytes, 4, RemoteParentRecord.ABI_VERSION);
    putShort(bytes, 6, RemoteParentRecord.RECORD_SIZE);
    bytes[8] = (byte) status;
    return bytes;
  }

  private static void putShort(byte[] bytes, int offset, int value) {
    bytes[offset] = (byte) value;
    bytes[offset + 1] = (byte) (value >>> 8);
  }

  private static void putLong(byte[] bytes, int offset, long value) {
    for (int i = 0; i < Long.BYTES; i++) {
      bytes[offset + i] = (byte) (value >>> (i * 8));
    }
  }
}
