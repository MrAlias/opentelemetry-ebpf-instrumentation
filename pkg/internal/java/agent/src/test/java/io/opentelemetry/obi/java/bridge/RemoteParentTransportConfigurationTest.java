/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class RemoteParentTransportConfigurationTest {
  private static final long AUTO_PRIMARY = 0x4f02000101010001L;
  private static final long AUTO_FALLBACK = 0x4f02010403020001L;
  private static final long DISABLED = 0x4f0200000003030dL;

  @Test
  void decodesPrimarySelection() {
    long configuration =
        RemoteParentTransportConfiguration.normalize(AUTO_PRIMARY, RemoteParentTransport.AUTO);

    assertEquals(
        RemoteParentStatus.VALID, RemoteParentTransportConfiguration.status(configuration));
    assertEquals(
        RemoteParentTransport.AUTO, RemoteParentTransportConfiguration.requested(configuration));
    assertEquals(
        RemoteParentTransport.GETSOCKOPT,
        RemoteParentTransportConfiguration.selected(configuration));
    assertEquals(1, RemoteParentTransportConfiguration.attempted(configuration));
    assertEquals(
        RemoteParentStatus.VALID,
        RemoteParentTransportConfiguration.getsockoptStatus(configuration));
    assertEquals(
        RemoteParentStatus.UNKNOWN, RemoteParentTransportConfiguration.unixStatus(configuration));
  }

  @Test
  void preservesBothAutoFallbackProbeOutcomes() {
    long configuration =
        RemoteParentTransportConfiguration.normalize(AUTO_FALLBACK, RemoteParentTransport.AUTO);

    assertEquals(
        RemoteParentTransport.UNIX, RemoteParentTransportConfiguration.selected(configuration));
    assertEquals(3, RemoteParentTransportConfiguration.attempted(configuration));
    assertEquals(
        RemoteParentStatus.UNSUPPORTED,
        RemoteParentTransportConfiguration.getsockoptStatus(configuration));
    assertEquals(
        RemoteParentStatus.VALID, RemoteParentTransportConfiguration.unixStatus(configuration));
    assertEquals(
        "version=2,status=1,requested=0,selected=2,attempted=3,getsockopt=4,unix=1",
        RemoteParentTransportConfiguration.snapshot(configuration));
  }

  @Test
  void representsDisabledWithoutProbeAttempts() {
    long configuration =
        RemoteParentTransportConfiguration.normalize(DISABLED, RemoteParentTransport.DISABLED);

    assertEquals(
        RemoteParentStatus.DISABLED, RemoteParentTransportConfiguration.status(configuration));
    assertEquals(
        RemoteParentTransport.DISABLED, RemoteParentTransportConfiguration.selected(configuration));
    assertEquals(0, RemoteParentTransportConfiguration.attempted(configuration));
  }

  @Test
  void preservesUnixDisabledProbeFailure() {
    long forcedUnixDisabled = 0x4f020d0002ff020dL;

    long configuration =
        RemoteParentTransportConfiguration.normalize(
            forcedUnixDisabled, RemoteParentTransport.UNIX);

    assertEquals(
        RemoteParentStatus.DISABLED, RemoteParentTransportConfiguration.status(configuration));
    assertEquals(
        RemoteParentTransportConfiguration.NONE,
        RemoteParentTransportConfiguration.selected(configuration));
    assertEquals(
        RemoteParentStatus.DISABLED, RemoteParentTransportConfiguration.unixStatus(configuration));
  }

  @Test
  void rejectsWrongMagicAndVersion() {
    long wrongMagic = AUTO_PRIMARY & 0x00ffffffffffffffL;
    long wrongVersion = (AUTO_PRIMARY & ~(0xffL << 48)) | (3L << 48);

    assertEquals(
        RemoteParentStatus.VERSION_MISMATCH,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(wrongMagic, RemoteParentTransport.AUTO)));
    assertEquals(
        RemoteParentStatus.VERSION_MISMATCH,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                wrongVersion, RemoteParentTransport.AUTO)));
  }

  @Test
  void rejectsMismatchedRequestedTransportAndReservedAttemptBits() {
    long wrongRequested = AUTO_PRIMARY | (1L << 8);
    long reservedAttempt = AUTO_PRIMARY | (4L << 24);

    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                wrongRequested, RemoteParentTransport.AUTO)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                reservedAttempt, RemoteParentTransport.AUTO)));
  }

  @Test
  void rejectsSelectionWithoutItsSuccessfulAttempt() {
    long noAttempt = AUTO_PRIMARY & ~(0xffL << 24);
    long failedSelectedProbe = (AUTO_PRIMARY & ~(0xffL << 32)) | (4L << 32);

    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(noAttempt, RemoteParentTransport.AUTO)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                failedSelectedProbe, RemoteParentTransport.AUTO)));
  }

  @Test
  void rejectsImpossibleAutoAndDisabledHistories() {
    long autoSkippedPrimary = 0x4f02010002020001L;
    long autoSelectedFallbackAfterSuccessfulPrimary = 0x4f02010103020001L;
    long autoSelectedFallbackAfterPrimarySuccessSentinel = 0x4f02010203020001L;
    long autoSelectedFallbackAfterImpossiblePrimaryFailure = 0x4f02010303020001L;
    long disabledWithProbe = DISABLED | (1L << 24) | (1L << 32);

    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                autoSkippedPrimary, RemoteParentTransport.AUTO)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                autoSelectedFallbackAfterSuccessfulPrimary, RemoteParentTransport.AUTO)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                autoSelectedFallbackAfterPrimarySuccessSentinel, RemoteParentTransport.AUTO)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                autoSelectedFallbackAfterImpossiblePrimaryFailure, RemoteParentTransport.AUTO)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                disabledWithProbe, RemoteParentTransport.DISABLED)));
  }

  @Test
  void rejectsLegacySelectionThatContradictsTheRequest() {
    long forcedGetsockoptSelectedUnix = 0x4f01000000020101L;

    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                forcedGetsockoptSelectedUnix, RemoteParentTransport.GETSOCKOPT)));
  }

  @Test
  void preservesReachableLegacyUnixDisabledFailures() {
    for (int requested : new int[] {RemoteParentTransport.AUTO, RemoteParentTransport.UNIX}) {
      long configuration =
          RemoteParentTransportConfiguration.normalize(
              RemoteParentTransportConfiguration.legacy(requested, RemoteParentStatus.DISABLED),
              requested);

      assertEquals(
          RemoteParentStatus.DISABLED, RemoteParentTransportConfiguration.status(configuration));
      assertEquals(
          RemoteParentTransportConfiguration.NONE,
          RemoteParentTransportConfiguration.selected(configuration));
    }
  }

  @Test
  void rejectsImpossibleLegacyFailureStatuses() {
    long autoMissing =
        RemoteParentTransportConfiguration.legacy(
            RemoteParentTransport.AUTO, RemoteParentStatus.MISSING);
    long getsockoptStale =
        RemoteParentTransportConfiguration.legacy(
            RemoteParentTransport.GETSOCKOPT, RemoteParentStatus.STALE);
    long disabledStale =
        RemoteParentTransportConfiguration.legacy(
            RemoteParentTransport.DISABLED, RemoteParentStatus.STALE);

    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(autoMissing, RemoteParentTransport.AUTO)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                getsockoptStale, RemoteParentTransport.GETSOCKOPT)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                disabledStale, RemoteParentTransport.DISABLED)));
  }

  @Test
  void rejectsFailureStatusesThatContradictProbeHistory() {
    long forcedGetsockoptMismatch = 0x4f02000801ff010aL;
    long forcedUnixMismatch = 0x4f02080002ff020aL;
    long autoWithoutFallbackMismatch = 0x4f02000801ff0008L;
    long autoFallbackMismatch = 0x4f02080403ff000aL;
    long forcedGetsockoptSwapMismatch = 0x4f02000101ff0103L;
    long forcedUnixSwapMismatch = 0x4f02010002ff0203L;
    long autoFallbackSwapMismatch = 0x4f02010403ff0003L;

    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                forcedGetsockoptMismatch, RemoteParentTransport.GETSOCKOPT)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                forcedUnixMismatch, RemoteParentTransport.UNIX)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                autoWithoutFallbackMismatch, RemoteParentTransport.AUTO)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                autoFallbackMismatch, RemoteParentTransport.AUTO)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                forcedGetsockoptSwapMismatch, RemoteParentTransport.GETSOCKOPT)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                forcedUnixSwapMismatch, RemoteParentTransport.UNIX)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                autoFallbackSwapMismatch, RemoteParentTransport.AUTO)));
  }

  @Test
  void validatesZeroAttemptFailureStatusesByRequestedTransport() {
    long unixEmptyPath = 0x4f02000000ff0204L;
    long disabledSwapTimeout = 0x4f02000000ff030aL;
    long getsockoptMissing = 0x4f02000000ff0102L;
    long disabledStale = 0x4f02000000ff0303L;

    assertEquals(
        RemoteParentStatus.UNSUPPORTED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                unixEmptyPath, RemoteParentTransport.UNIX)));
    assertEquals(
        RemoteParentStatus.TIMEOUT,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                disabledSwapTimeout, RemoteParentTransport.DISABLED)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                getsockoptMissing, RemoteParentTransport.GETSOCKOPT)));
    assertEquals(
        RemoteParentStatus.MALFORMED,
        RemoteParentTransportConfiguration.status(
            RemoteParentTransportConfiguration.normalize(
                disabledStale, RemoteParentTransport.DISABLED)));
  }

  @Test
  void keepsLegacyStatusWhileMarkingAutoSelectionUnknown() {
    long configuration =
        RemoteParentTransportConfiguration.normalize(
            RemoteParentTransportConfiguration.legacy(
                RemoteParentTransport.AUTO, RemoteParentStatus.VALID),
            RemoteParentTransport.AUTO);

    assertEquals(
        RemoteParentStatus.VALID, RemoteParentTransportConfiguration.status(configuration));
    assertEquals(
        RemoteParentTransportConfiguration.NONE,
        RemoteParentTransportConfiguration.selected(configuration));
    assertEquals(
        "version=1,status=1,requested=0,selected=255,attempted=0,getsockopt=0,unix=0",
        RemoteParentTransportConfiguration.snapshot(configuration));
  }

  @Test
  void sanitizesUnknownProviderValues() {
    assertEquals(
        "version=2,status=6,requested=255,selected=255,attempted=0,getsockopt=0,unix=0",
        RemoteParentTransportConfiguration.snapshot(0L));
  }

  @Test
  void reportsUnknownSnapshotVersionsAsVersionMismatches() {
    long futureVersion = (AUTO_PRIMARY & ~(0xffL << 48)) | (3L << 48);

    assertEquals(
        "version=2,status=6,requested=255,selected=255,attempted=0,getsockopt=0,unix=0",
        RemoteParentTransportConfiguration.snapshot(futureVersion));
  }

  @Test
  void preservesNormalizedVersionMismatchSnapshots() {
    long futureVersion = (AUTO_PRIMARY & ~(0xffL << 48)) | (3L << 48);
    long normalized =
        RemoteParentTransportConfiguration.normalize(futureVersion, RemoteParentTransport.AUTO);

    assertEquals(
        RemoteParentStatus.VERSION_MISMATCH, RemoteParentTransportConfiguration.status(normalized));
    assertEquals(
        "version=2,status=6,requested=0,selected=255,attempted=0,getsockopt=0,unix=0",
        RemoteParentTransportConfiguration.snapshot(normalized));
  }
}
