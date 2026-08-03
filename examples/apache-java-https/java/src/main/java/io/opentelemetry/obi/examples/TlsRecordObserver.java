// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Bounded TLS record-framing observer for the loopback receive-boundary fixture.
 *
 * <p>The observer records only application-data record legacy versions and payload lengths after
 * it is armed. It never retains record contents, negotiated protocol identifiers, or request data.
 */
final class TlsRecordObserver {
  static final int TLS_HEADER_BYTES = 5;
  static final int TLS_APPLICATION_DATA = 23;
  static final int TLS_APPLICATION_DATA_LEGACY_VERSION = 0x0303;
  static final int MAX_TLS_RECORD_PAYLOAD_BYTES = (1 << 14) + 2048;
  static final int MAX_CAPTURED_APPLICATION_RECORDS = 8;

  private final byte[] header = new byte[TLS_HEADER_BYTES];
  private final List<Integer> applicationRecordLegacyVersions = new ArrayList<>();
  private final List<Integer> applicationRecordPayloadLengths = new ArrayList<>();
  private int headerBytes;
  private int payloadBytesRemaining;
  private int currentRecordType;
  private int currentRecordLegacyVersion;
  private int currentRecordPayloadLength;
  private boolean captureCurrentRecord;
  private boolean armed;
  private IOException failure;

  OutputStream observe(OutputStream delegate) {
    if (delegate == null) {
      throw new NullPointerException("delegate");
    }
    return new OutputStream() {
      @Override
      public void write(int value) throws IOException {
        delegate.write(value);
        accept(value);
      }

      @Override
      public void write(byte[] value, int offset, int length) throws IOException {
        delegate.write(value, offset, length);
        accept(value, offset, length);
      }

      @Override
      public void flush() throws IOException {
        delegate.flush();
      }

      @Override
      public void close() throws IOException {
        delegate.close();
      }
    };
  }

  synchronized void arm() throws IOException {
    requireHealthy();
    if (armed) {
      throw new IOException("TLS record observer is already armed");
    }
    requireRecordBoundary("arm");
    applicationRecordLegacyVersions.clear();
    applicationRecordPayloadLengths.clear();
    armed = true;
  }

  synchronized Snapshot disarmAndSnapshot() throws IOException {
    requireHealthy();
    if (!armed) {
      throw new IOException("TLS record observer is not armed");
    }
    armed = false;
    requireRecordBoundary("snapshot");
    return new Snapshot(applicationRecordLegacyVersions, applicationRecordPayloadLengths);
  }

  private synchronized void accept(int value) throws IOException {
    requireHealthy();
    acceptByte(value);
  }

  private synchronized void accept(byte[] value, int offset, int length) throws IOException {
    requireHealthy();
    if (offset < 0 || length < 0 || offset > value.length - length) {
      throw new IndexOutOfBoundsException("invalid TLS record observer input range");
    }

    int cursor = offset;
    int remaining = length;
    while (remaining > 0) {
      acceptByte(value[cursor]);
      cursor++;
      remaining--;
    }
  }

  private void acceptByte(int value) throws IOException {
    if (headerBytes < TLS_HEADER_BYTES) {
      header[headerBytes++] = (byte) value;
      if (headerBytes == TLS_HEADER_BYTES) {
        beginRecord();
        if (payloadBytesRemaining == 0) {
          finishRecord();
        }
      }
      return;
    }

    payloadBytesRemaining--;
    if (payloadBytesRemaining == 0) {
      finishRecord();
    }
  }

  private void beginRecord() throws IOException {
    int payloadLength = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
    if (payloadLength > MAX_TLS_RECORD_PAYLOAD_BYTES) {
      fail("TLS record payload exceeds the fixture bound");
    }
    currentRecordType = header[0] & 0xff;
    currentRecordLegacyVersion = ((header[1] & 0xff) << 8) | (header[2] & 0xff);
    currentRecordPayloadLength = payloadLength;
    payloadBytesRemaining = payloadLength;
    captureCurrentRecord = armed && currentRecordType == TLS_APPLICATION_DATA;
    if (captureCurrentRecord
        && currentRecordLegacyVersion != TLS_APPLICATION_DATA_LEGACY_VERSION) {
      fail("TLS application-data record has an unexpected legacy version");
    }
  }

  private void finishRecord() throws IOException {
    if (captureCurrentRecord) {
      if (applicationRecordPayloadLengths.size() >= MAX_CAPTURED_APPLICATION_RECORDS) {
        fail("TLS application-data record count exceeds the fixture bound");
      }
      applicationRecordLegacyVersions.add(currentRecordLegacyVersion);
      applicationRecordPayloadLengths.add(currentRecordPayloadLength);
    }
    headerBytes = 0;
    payloadBytesRemaining = 0;
    currentRecordType = 0;
    currentRecordLegacyVersion = 0;
    currentRecordPayloadLength = 0;
    captureCurrentRecord = false;
  }

  private void requireRecordBoundary(String operation) throws IOException {
    if (headerBytes != 0 || payloadBytesRemaining != 0) {
      fail("TLS record observer cannot " + operation + " inside a record");
    }
  }

  private void requireHealthy() throws IOException {
    if (failure != null) {
      throw failure;
    }
  }

  private void fail(String message) throws IOException {
    if (failure == null) {
      failure = new IOException(message);
    }
    throw failure;
  }

  static final class Snapshot {
    private final List<Integer> legacyVersions;
    private final List<Integer> payloadLengths;

    private Snapshot(List<Integer> legacyVersions, List<Integer> payloadLengths) {
      this.legacyVersions = List.copyOf(legacyVersions);
      this.payloadLengths = List.copyOf(payloadLengths);
    }

    static Snapshot empty() {
      return new Snapshot(List.of(), List.of());
    }

    List<Integer> legacyVersions() {
      return legacyVersions;
    }

    List<Integer> payloadLengths() {
      return payloadLengths;
    }
  }
}
