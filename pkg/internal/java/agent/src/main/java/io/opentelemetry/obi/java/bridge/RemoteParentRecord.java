/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

/** Immutable, OpenTelemetry-independent representation of the remote-parent ABI. */
public final class RemoteParentRecord {
  public static final int ABI_VERSION = 1;
  public static final int RECORD_SIZE = 64;

  private static final int MAGIC_OFFSET = 0;
  private static final int VERSION_OFFSET = 4;
  private static final int SIZE_OFFSET = 6;
  private static final int STATUS_OFFSET = 8;
  private static final int TRACE_FLAGS_OFFSET = 9;
  private static final int TRACE_ID_OFFSET = 16;
  private static final int TRACE_ID_SIZE = 16;
  private static final int PARENT_SPAN_ID_OFFSET = 32;
  private static final int PARENT_SPAN_ID_SIZE = 8;
  private static final int GENERATION_OFFSET = 40;
  private static final int OBSERVED_NANOS_OFFSET = 48;
  private static final RemoteParentRecord[] STATUS_RECORDS = statusRecords();

  private final int status;
  private final int traceFlags;
  private final String traceIdHex;
  private final String parentSpanIdHex;
  private final long generation;
  private final long observedMonotonicNanos;

  private RemoteParentRecord(
      int status,
      int traceFlags,
      String traceIdHex,
      String parentSpanIdHex,
      long generation,
      long observedMonotonicNanos) {
    this.status = status;
    this.traceFlags = traceFlags;
    this.traceIdHex = traceIdHex;
    this.parentSpanIdHex = parentSpanIdHex;
    this.generation = generation;
    this.observedMonotonicNanos = observedMonotonicNanos;
  }

  public static RemoteParentRecord statusOnly(int status) {
    int normalized = RemoteParentStatus.isKnown(status) ? status : RemoteParentStatus.MALFORMED;
    return STATUS_RECORDS[normalized];
  }

  public static RemoteParentRecord decode(byte[] bytes) {
    if (bytes == null || bytes.length != RECORD_SIZE) {
      return statusOnly(RemoteParentStatus.MALFORMED);
    }
    if (bytes[MAGIC_OFFSET] != 'O'
        || bytes[MAGIC_OFFSET + 1] != 'B'
        || bytes[MAGIC_OFFSET + 2] != 'I'
        || bytes[MAGIC_OFFSET + 3] != 'J') {
      return statusOnly(RemoteParentStatus.MALFORMED);
    }

    int version = unsignedShortLittleEndian(bytes, VERSION_OFFSET);
    if (version != ABI_VERSION) {
      return statusOnly(RemoteParentStatus.VERSION_MISMATCH);
    }
    int declaredSize = unsignedShortLittleEndian(bytes, SIZE_OFFSET);
    if (declaredSize != RECORD_SIZE) {
      return statusOnly(RemoteParentStatus.MALFORMED);
    }
    if (!zero(bytes, 10, 16) || !zero(bytes, 56, RECORD_SIZE)) {
      return statusOnly(RemoteParentStatus.MALFORMED);
    }

    int status = bytes[STATUS_OFFSET] & 0xff;
    int traceFlags = bytes[TRACE_FLAGS_OFFSET] & 0xff;
    if (!RemoteParentStatus.isKnown(status) || status == RemoteParentStatus.UNKNOWN) {
      return statusOnly(RemoteParentStatus.MALFORMED);
    }
    if (status != RemoteParentStatus.VALID) {
      return statusOnly(status);
    }

    if (zero(bytes, TRACE_ID_OFFSET, TRACE_ID_OFFSET + TRACE_ID_SIZE)
        || zero(bytes, PARENT_SPAN_ID_OFFSET, PARENT_SPAN_ID_OFFSET + PARENT_SPAN_ID_SIZE)) {
      return statusOnly(RemoteParentStatus.MALFORMED);
    }

    long generation = longLittleEndian(bytes, GENERATION_OFFSET);
    long observedMonotonicNanos = longLittleEndian(bytes, OBSERVED_NANOS_OFFSET);
    if (generation == 0 || observedMonotonicNanos == 0) {
      return statusOnly(RemoteParentStatus.MALFORMED);
    }

    return new RemoteParentRecord(
        status,
        traceFlags,
        hex(bytes, TRACE_ID_OFFSET, TRACE_ID_SIZE),
        hex(bytes, PARENT_SPAN_ID_OFFSET, PARENT_SPAN_ID_SIZE),
        generation,
        observedMonotonicNanos);
  }

  public int getAbiVersion() {
    return ABI_VERSION;
  }

  public int getStatus() {
    return status;
  }

  public int getTraceFlags() {
    return traceFlags;
  }

  public String getTraceIdHex() {
    return traceIdHex;
  }

  public String getParentSpanIdHex() {
    return parentSpanIdHex;
  }

  public long getGeneration() {
    return generation;
  }

  public long getObservedMonotonicNanos() {
    return observedMonotonicNanos;
  }

  private static int unsignedShortLittleEndian(byte[] bytes, int offset) {
    return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
  }

  private static long longLittleEndian(byte[] bytes, int offset) {
    long value = 0;
    for (int i = Long.BYTES - 1; i >= 0; i--) {
      value = (value << 8) | (bytes[offset + i] & 0xffL);
    }
    return value;
  }

  private static boolean zero(byte[] bytes, int start, int end) {
    for (int i = start; i < end; i++) {
      if (bytes[i] != 0) {
        return false;
      }
    }
    return true;
  }

  private static String hex(byte[] bytes, int offset, int length) {
    char[] chars = new char[length * 2];
    final char[] alphabet = "0123456789abcdef".toCharArray();
    for (int i = 0; i < length; i++) {
      int value = bytes[offset + i] & 0xff;
      chars[i * 2] = alphabet[value >>> 4];
      chars[i * 2 + 1] = alphabet[value & 0xf];
    }
    return new String(chars);
  }

  private static RemoteParentRecord[] statusRecords() {
    RemoteParentRecord[] records = new RemoteParentRecord[RemoteParentStatus.DISABLED + 1];
    for (int status = RemoteParentStatus.UNKNOWN; status <= RemoteParentStatus.DISABLED; status++) {
      records[status] = new RemoteParentRecord(status, 0, null, null, 0L, 0L);
    }
    return records;
  }
}
