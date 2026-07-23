/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class RemoteParentRecordTest {
  private static final String CORPUS_FORMAT = "format|1";
  private static final String CORPUS_HEADER = "name|outcome|status_name|status|wire_hex";
  private static final Map<String, CorpusSpec> CORPUS_SPECS = corpusSpecs();

  private enum CorpusCase {
    VALID_SAMPLED,
    VALID_UNSAMPLED,
    VALID_FUTURE_FLAGS,
    STATUS_ONLY,
    ALL_ZERO_IDS,
    ZERO_TRACE_ID,
    ZERO_SPAN_ID,
    ZERO_GENERATION,
    ZERO_OBSERVATION,
    ZERO_LENGTH,
    PRE_MAGIC_TRUNCATED,
    TRUNCATED,
    BAD_MAGIC,
    DECLARED_SMALLER,
    DECLARED_LARGER,
    RESERVED_PREFIX,
    RESERVED_SUFFIX,
    UNKNOWN_STATUS_ZERO,
    UNKNOWN_STATUS_14,
    UNKNOWN_VERSION,
    UNKNOWN_VERSION_BAD_SIZE,
    FUTURE_LARGER_V1,
    FUTURE_LARGER_UNKNOWN_VERSION
  }

  private static final class CorpusSpec {
    private final boolean accepted;
    private final String statusName;
    private final int status;
    private final int wireSize;
    private final CorpusCase kind;

    private CorpusSpec(
        boolean accepted, String statusName, int status, int wireSize, CorpusCase kind) {
      this.accepted = accepted;
      this.statusName = statusName;
      this.status = status;
      this.wireSize = wireSize;
      this.kind = kind;
    }
  }

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

  @Test
  void decodesSharedAbiCorpus() throws IOException {
    String corpusPath = System.getProperty("obi.test.remote.parent.vectors");
    assertNotNull(corpusPath);

    List<String> lines = Files.readAllLines(Paths.get(corpusPath), StandardCharsets.US_ASCII);
    Set<String> names = new HashSet<>();
    int stage = 0;

    for (int index = 0; index < lines.size(); index++) {
      String line = lines.get(index);
      int lineNumber = index + 1;
      if (line.isEmpty() || line.startsWith("#")) {
        continue;
      }
      if (stage == 0) {
        assertEquals(CORPUS_FORMAT, line, "line " + lineNumber);
        stage++;
        continue;
      }
      if (stage == 1) {
        assertEquals(CORPUS_HEADER, line, "line " + lineNumber);
        stage++;
        continue;
      }

      String[] fields = line.split("\\|", -1);
      assertEquals(5, fields.length, "line " + lineNumber);
      String name = fields[0];
      assertTrue(name.matches("[a-z][a-z0-9_]*"), "line " + lineNumber);
      assertTrue(names.add(name), "duplicate vector " + name);
      CorpusSpec spec = CORPUS_SPECS.get(name);
      assertNotNull(spec, "unknown vector " + name);

      assertEquals(spec.accepted ? "accept" : "reject", fields[1], "line " + lineNumber);
      assertEquals(spec.statusName, fields[2], "line " + lineNumber);
      int expectedStatus = Integer.parseInt(fields[3]);
      assertEquals(spec.status, expectedStatus, "line " + lineNumber);

      byte[] wire = decodeHex(fields[4], lineNumber);
      assertEquals(spec.wireSize, wire.length, name);
      assertArrayEquals(expectedCorpusWire(spec), wire, name);
      byte[] original = wire.clone();
      RemoteParentRecord record = RemoteParentRecord.decode(wire);
      assertArrayEquals(original, wire, name + " mutated its input");
      assertEquals(expectedStatus, record.getStatus(), name);

      if (spec.accepted && expectedStatus == RemoteParentStatus.VALID) {
        assertEquals(wire[9] & 0xff, record.getTraceFlags(), name);
        assertEquals(hexString(wire, 16, 16), record.getTraceIdHex(), name);
        assertEquals(hexString(wire, 32, 8), record.getParentSpanIdHex(), name);
        assertEquals(readLongLittleEndian(wire, 40), record.getGeneration(), name);
        assertEquals(readLongLittleEndian(wire, 48), record.getObservedMonotonicNanos(), name);
      } else {
        assertNull(record.getTraceIdHex(), name);
        assertNull(record.getParentSpanIdHex(), name);
      }
    }

    assertEquals(2, stage, "corpus format or header is missing");
    assertEquals(CORPUS_SPECS.keySet(), names, "required corpus cases differ");
  }

  private static Map<String, CorpusSpec> corpusSpecs() {
    Map<String, CorpusSpec> specs = new HashMap<>();
    addCorpusSpec(
        specs,
        "valid_sampled",
        true,
        "valid",
        RemoteParentStatus.VALID,
        64,
        CorpusCase.VALID_SAMPLED);
    addCorpusSpec(
        specs,
        "valid_unsampled",
        true,
        "valid",
        RemoteParentStatus.VALID,
        64,
        CorpusCase.VALID_UNSAMPLED);
    addCorpusSpec(
        specs,
        "valid_future_flags",
        true,
        "valid",
        RemoteParentStatus.VALID,
        64,
        CorpusCase.VALID_FUTURE_FLAGS);
    addCorpusSpec(specs, "status_missing", true, "missing", RemoteParentStatus.MISSING);
    addCorpusSpec(specs, "status_stale", true, "stale", RemoteParentStatus.STALE);
    addCorpusSpec(specs, "status_unsupported", true, "unsupported", RemoteParentStatus.UNSUPPORTED);
    addCorpusSpec(specs, "status_malformed", true, "malformed", RemoteParentStatus.MALFORMED);
    addCorpusSpec(
        specs,
        "status_version_mismatch",
        true,
        "version_mismatch",
        RemoteParentStatus.VERSION_MISMATCH);
    addCorpusSpec(specs, "status_ambiguous", true, "ambiguous", RemoteParentStatus.AMBIGUOUS);
    addCorpusSpec(
        specs, "status_unauthorized", true, "unauthorized", RemoteParentStatus.UNAUTHORIZED);
    addCorpusSpec(
        specs,
        "status_already_consumed",
        true,
        "already_consumed",
        RemoteParentStatus.ALREADY_CONSUMED);
    addCorpusSpec(specs, "status_timeout", true, "timeout", RemoteParentStatus.TIMEOUT);
    addCorpusSpec(specs, "status_overload", true, "overload", RemoteParentStatus.OVERLOAD);
    addCorpusSpec(
        specs,
        "status_transport_error",
        true,
        "transport_error",
        RemoteParentStatus.TRANSPORT_ERROR);
    addCorpusSpec(specs, "status_disabled", true, "disabled", RemoteParentStatus.DISABLED);
    addCorpusSpec(specs, "all_zero_ids", CorpusCase.ALL_ZERO_IDS);
    addCorpusSpec(specs, "zero_trace_id", CorpusCase.ZERO_TRACE_ID);
    addCorpusSpec(specs, "zero_span_id", CorpusCase.ZERO_SPAN_ID);
    addCorpusSpec(specs, "zero_generation", CorpusCase.ZERO_GENERATION);
    addCorpusSpec(specs, "zero_observation_time", CorpusCase.ZERO_OBSERVATION);
    addCorpusSpec(specs, "zero_length", 0, CorpusCase.ZERO_LENGTH);
    addCorpusSpec(specs, "pre_magic_truncated", 3, CorpusCase.PRE_MAGIC_TRUNCATED);
    addCorpusSpec(specs, "truncated", 63, CorpusCase.TRUNCATED);
    addCorpusSpec(specs, "bad_magic", CorpusCase.BAD_MAGIC);
    addCorpusSpec(specs, "declared_smaller", CorpusCase.DECLARED_SMALLER);
    addCorpusSpec(specs, "declared_larger", CorpusCase.DECLARED_LARGER);
    addCorpusSpec(specs, "reserved_prefix", CorpusCase.RESERVED_PREFIX);
    addCorpusSpec(specs, "reserved_suffix", CorpusCase.RESERVED_SUFFIX);
    addCorpusSpec(specs, "unknown_status_zero", CorpusCase.UNKNOWN_STATUS_ZERO);
    addCorpusSpec(specs, "unknown_status_14", CorpusCase.UNKNOWN_STATUS_14);
    addCorpusSpec(
        specs,
        "unknown_version",
        false,
        "version_mismatch",
        RemoteParentStatus.VERSION_MISMATCH,
        64,
        CorpusCase.UNKNOWN_VERSION);
    addCorpusSpec(
        specs,
        "unknown_version_bad_declared_size",
        false,
        "version_mismatch",
        RemoteParentStatus.VERSION_MISMATCH,
        64,
        CorpusCase.UNKNOWN_VERSION_BAD_SIZE);
    addCorpusSpec(specs, "future_larger_v1", 80, CorpusCase.FUTURE_LARGER_V1);
    addCorpusSpec(
        specs, "future_larger_unknown_version", 80, CorpusCase.FUTURE_LARGER_UNKNOWN_VERSION);
    return specs;
  }

  private static void addCorpusSpec(
      Map<String, CorpusSpec> specs,
      String name,
      boolean accepted,
      String statusName,
      int status,
      int wireSize,
      CorpusCase kind) {
    if (specs.put(name, new CorpusSpec(accepted, statusName, status, wireSize, kind)) != null) {
      throw new IllegalStateException("duplicate corpus spec " + name);
    }
  }

  private static void addCorpusSpec(
      Map<String, CorpusSpec> specs, String name, boolean accepted, String statusName, int status) {
    addCorpusSpec(
        specs,
        name,
        accepted,
        statusName,
        status,
        RemoteParentRecord.RECORD_SIZE,
        CorpusCase.STATUS_ONLY);
  }

  private static void addCorpusSpec(Map<String, CorpusSpec> specs, String name, CorpusCase kind) {
    addCorpusSpec(specs, name, RemoteParentRecord.RECORD_SIZE, kind);
  }

  private static void addCorpusSpec(
      Map<String, CorpusSpec> specs, String name, int wireSize, CorpusCase kind) {
    addCorpusSpec(specs, name, false, "malformed", RemoteParentStatus.MALFORMED, wireSize, kind);
  }

  private static byte[] expectedCorpusWire(CorpusSpec spec) {
    if (spec.kind == CorpusCase.STATUS_ONLY) {
      return emptyRecord(spec.status);
    }

    byte[] wire = validRecord();
    switch (spec.kind) {
      case VALID_UNSAMPLED:
        wire[9] = 0;
        break;
      case VALID_FUTURE_FLAGS:
        wire[9] = (byte) 0x81;
        break;
      default:
        break;
    }

    switch (spec.kind) {
      case VALID_SAMPLED:
      case VALID_UNSAMPLED:
      case VALID_FUTURE_FLAGS:
        return wire;
      case ALL_ZERO_IDS:
        Arrays.fill(wire, 16, 40, (byte) 0);
        break;
      case ZERO_TRACE_ID:
        Arrays.fill(wire, 16, 32, (byte) 0);
        break;
      case ZERO_SPAN_ID:
        Arrays.fill(wire, 32, 40, (byte) 0);
        break;
      case ZERO_GENERATION:
        Arrays.fill(wire, 40, 48, (byte) 0);
        break;
      case ZERO_OBSERVATION:
        Arrays.fill(wire, 48, 56, (byte) 0);
        break;
      case ZERO_LENGTH:
        return new byte[0];
      case PRE_MAGIC_TRUNCATED:
      case TRUNCATED:
        return Arrays.copyOf(wire, spec.wireSize);
      case BAD_MAGIC:
        wire[0] = 'X';
        break;
      case DECLARED_SMALLER:
        putShort(wire, 6, 63);
        break;
      case DECLARED_LARGER:
        putShort(wire, 6, 80);
        break;
      case RESERVED_PREFIX:
        wire[10] = 1;
        break;
      case RESERVED_SUFFIX:
        wire[56] = 1;
        break;
      case UNKNOWN_STATUS_ZERO:
      case UNKNOWN_STATUS_14:
        wire = emptyRecord(RemoteParentStatus.MISSING);
        wire[8] = (byte) (spec.kind == CorpusCase.UNKNOWN_STATUS_14 ? 14 : 0);
        break;
      case UNKNOWN_VERSION:
        putShort(wire, 4, 2);
        break;
      case UNKNOWN_VERSION_BAD_SIZE:
        putShort(wire, 4, 2);
        putShort(wire, 6, 80);
        break;
      case FUTURE_LARGER_V1:
      case FUTURE_LARGER_UNKNOWN_VERSION:
        wire = Arrays.copyOf(wire, spec.wireSize);
        putShort(wire, 6, spec.wireSize);
        if (spec.kind == CorpusCase.FUTURE_LARGER_UNKNOWN_VERSION) {
          putShort(wire, 4, 2);
        }
        break;
      case STATUS_ONLY:
        break;
    }
    return wire;
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

  private static byte[] decodeHex(String value, int lineNumber) {
    assertTrue(!value.isEmpty(), "line " + lineNumber);
    if (value.equals("-")) {
      return new byte[0];
    }
    assertTrue(value.length() % 2 == 0, "line " + lineNumber);
    assertTrue(value.length() <= 160, "line " + lineNumber);

    byte[] decoded = new byte[value.length() / 2];
    for (int index = 0; index < decoded.length; index++) {
      int high = Character.digit(value.charAt(index * 2), 16);
      int low = Character.digit(value.charAt(index * 2 + 1), 16);
      assertTrue(high >= 0 && low >= 0, "line " + lineNumber);
      assertTrue(
          !Character.isUpperCase(value.charAt(index * 2))
              && !Character.isUpperCase(value.charAt(index * 2 + 1)),
          "line " + lineNumber);
      decoded[index] = (byte) ((high << 4) | low);
    }
    return decoded;
  }

  private static String hexString(byte[] bytes, int offset, int length) {
    char[] encoded = new char[length * 2];
    char[] alphabet = "0123456789abcdef".toCharArray();
    for (int index = 0; index < length; index++) {
      int value = bytes[offset + index] & 0xff;
      encoded[index * 2] = alphabet[value >>> 4];
      encoded[index * 2 + 1] = alphabet[value & 0xf];
    }
    return new String(encoded);
  }

  private static long readLongLittleEndian(byte[] bytes, int offset) {
    long value = 0;
    for (int index = Long.BYTES - 1; index >= 0; index--) {
      value = (value << 8) | (bytes[offset + index] & 0xffL);
    }
    return value;
  }
}
