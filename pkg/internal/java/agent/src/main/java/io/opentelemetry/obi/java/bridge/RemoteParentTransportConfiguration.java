/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

/** Fixed-width result of one native remote-parent transport configuration attempt. */
public final class RemoteParentTransportConfiguration {
  public static final int VERSION = 2;
  public static final int NONE = 255;

  private static final int LEGACY_VERSION = 1;
  private static final int MAGIC = 0x4f;
  private static final int GETSOCKOPT_ATTEMPTED = 1;
  private static final int UNIX_ATTEMPTED = 2;
  private static final int ATTEMPT_MASK = GETSOCKOPT_ATTEMPTED | UNIX_ATTEMPTED;

  private static final int STATUS_SHIFT = 0;
  private static final int REQUESTED_SHIFT = 8;
  private static final int SELECTED_SHIFT = 16;
  private static final int ATTEMPTED_SHIFT = 24;
  private static final int GETSOCKOPT_STATUS_SHIFT = 32;
  private static final int UNIX_STATUS_SHIFT = 40;
  private static final int VERSION_SHIFT = 48;
  private static final int MAGIC_SHIFT = 56;

  private RemoteParentTransportConfiguration() {}

  static long unknown() {
    return pack(
        VERSION,
        RemoteParentStatus.UNKNOWN,
        NONE,
        NONE,
        0,
        RemoteParentStatus.UNKNOWN,
        RemoteParentStatus.UNKNOWN);
  }

  static long unknown(int requested) {
    return pack(
        VERSION,
        RemoteParentStatus.UNKNOWN,
        normalizeRequested(requested),
        NONE,
        0,
        RemoteParentStatus.UNKNOWN,
        RemoteParentStatus.UNKNOWN);
  }

  static long failure(int requested, int status) {
    int normalizedStatus =
        RemoteParentStatus.isKnown(status) && status != RemoteParentStatus.VALID
            ? status
            : RemoteParentStatus.MALFORMED;
    return pack(
        VERSION,
        normalizedStatus,
        normalizeRequested(requested),
        NONE,
        0,
        RemoteParentStatus.UNKNOWN,
        RemoteParentStatus.UNKNOWN);
  }

  static long disabled() {
    return pack(
        VERSION,
        RemoteParentStatus.DISABLED,
        RemoteParentTransport.DISABLED,
        RemoteParentTransport.DISABLED,
        0,
        RemoteParentStatus.UNKNOWN,
        RemoteParentStatus.UNKNOWN);
  }

  static long legacy(int requested, int status) {
    int normalizedRequested = normalizeRequested(requested);
    int normalizedStatus =
        RemoteParentStatus.isKnown(status) ? status : RemoteParentStatus.MALFORMED;
    int selected = NONE;
    if (normalizedStatus == RemoteParentStatus.VALID
        && (normalizedRequested == RemoteParentTransport.GETSOCKOPT
            || normalizedRequested == RemoteParentTransport.UNIX)) {
      selected = normalizedRequested;
    } else if (normalizedStatus == RemoteParentStatus.DISABLED
        && normalizedRequested == RemoteParentTransport.DISABLED) {
      selected = RemoteParentTransport.DISABLED;
    }
    return pack(
        LEGACY_VERSION,
        normalizedStatus,
        normalizedRequested,
        selected,
        0,
        RemoteParentStatus.UNKNOWN,
        RemoteParentStatus.UNKNOWN);
  }

  static long normalize(long configuration, int requested) {
    int normalizedRequested = normalizeRequested(requested);
    if (magic(configuration) != MAGIC) {
      return failure(normalizedRequested, RemoteParentStatus.VERSION_MISMATCH);
    }
    if (version(configuration) == LEGACY_VERSION) {
      return requested(configuration) == normalizedRequested && isLegacy(configuration)
          ? configuration
          : failure(normalizedRequested, RemoteParentStatus.MALFORMED);
    }
    if (version(configuration) != VERSION) {
      return failure(normalizedRequested, RemoteParentStatus.VERSION_MISMATCH);
    }
    if (requested(configuration) != normalizedRequested || !isCompleteVersionTwo(configuration)) {
      return failure(normalizedRequested, RemoteParentStatus.MALFORMED);
    }
    return configuration;
  }

  static int status(long configuration) {
    return field(configuration, STATUS_SHIFT);
  }

  static int requested(long configuration) {
    return field(configuration, REQUESTED_SHIFT);
  }

  static int selected(long configuration) {
    return field(configuration, SELECTED_SHIFT);
  }

  static int attempted(long configuration) {
    return field(configuration, ATTEMPTED_SHIFT);
  }

  static int getsockoptStatus(long configuration) {
    return field(configuration, GETSOCKOPT_STATUS_SHIFT);
  }

  static int unixStatus(long configuration) {
    return field(configuration, UNIX_STATUS_SHIFT);
  }

  static int version(long configuration) {
    return field(configuration, VERSION_SHIFT);
  }

  public static String snapshot(long configuration) {
    long sanitized = sanitize(configuration);
    return "version="
        + version(sanitized)
        + ",status="
        + status(sanitized)
        + ",requested="
        + requested(sanitized)
        + ",selected="
        + selected(sanitized)
        + ",attempted="
        + attempted(sanitized)
        + ",getsockopt="
        + getsockoptStatus(sanitized)
        + ",unix="
        + unixStatus(sanitized);
  }

  private static long sanitize(long configuration) {
    if (magic(configuration) != MAGIC) {
      return failure(NONE, RemoteParentStatus.VERSION_MISMATCH);
    }
    int formatVersion = version(configuration);
    if (formatVersion == VERSION) {
      return isSnapshotVersionTwo(configuration)
          ? configuration
          : failure(NONE, RemoteParentStatus.MALFORMED);
    }
    if (formatVersion == LEGACY_VERSION) {
      return isLegacy(configuration) ? configuration : failure(NONE, RemoteParentStatus.MALFORMED);
    }
    return failure(NONE, RemoteParentStatus.VERSION_MISMATCH);
  }

  private static boolean isSnapshotVersionTwo(long configuration) {
    int requested = requested(configuration);
    int status = status(configuration);
    if (requested == NONE
        && selected(configuration) == NONE
        && attempted(configuration) == 0
        && getsockoptStatus(configuration) == RemoteParentStatus.UNKNOWN
        && unixStatus(configuration) == RemoteParentStatus.UNKNOWN
        && RemoteParentStatus.isKnown(status)) {
      return status != RemoteParentStatus.VALID && status != RemoteParentStatus.DISABLED;
    }
    if (status == RemoteParentStatus.UNKNOWN && isTransport(requested)) {
      return selected(configuration) == NONE
          && attempted(configuration) == 0
          && getsockoptStatus(configuration) == RemoteParentStatus.UNKNOWN
          && unixStatus(configuration) == RemoteParentStatus.UNKNOWN;
    }
    return isCompleteVersionTwo(configuration);
  }

  private static boolean isCompleteVersionTwo(long configuration) {
    int status = status(configuration);
    int requested = requested(configuration);
    int selected = selected(configuration);
    int attempted = attempted(configuration);
    int getsockoptStatus = getsockoptStatus(configuration);
    int unixStatus = unixStatus(configuration);

    if (!RemoteParentStatus.isKnown(status)
        || status == RemoteParentStatus.UNKNOWN
        || !isTransport(requested)
        || (selected != NONE
            && selected != RemoteParentTransport.GETSOCKOPT
            && selected != RemoteParentTransport.UNIX
            && selected != RemoteParentTransport.DISABLED)
        || (attempted & ~ATTEMPT_MASK) != 0
        || !RemoteParentStatus.isKnown(getsockoptStatus)
        || !RemoteParentStatus.isKnown(unixStatus)
        || ((attempted & GETSOCKOPT_ATTEMPTED) == 0)
            != (getsockoptStatus == RemoteParentStatus.UNKNOWN)
        || ((attempted & UNIX_ATTEMPTED) == 0) != (unixStatus == RemoteParentStatus.UNKNOWN)
        || ((attempted & GETSOCKOPT_ATTEMPTED) != 0 && !isGetsockoptProbeOutcome(getsockoptStatus))
        || ((attempted & UNIX_ATTEMPTED) != 0 && !isUnixProbeOutcome(unixStatus))) {
      return false;
    }

    if (requested == RemoteParentTransport.AUTO) {
      if ((attempted & UNIX_ATTEMPTED) != 0
          && ((attempted & GETSOCKOPT_ATTEMPTED) == 0
              || !isGetsockoptProbeFailure(getsockoptStatus))) {
        return false;
      }
    } else if (requested == RemoteParentTransport.GETSOCKOPT) {
      if ((attempted & UNIX_ATTEMPTED) != 0) {
        return false;
      }
    } else if (requested == RemoteParentTransport.UNIX) {
      if ((attempted & GETSOCKOPT_ATTEMPTED) != 0) {
        return false;
      }
    } else if (attempted != 0) {
      return false;
    }

    if (selected == RemoteParentTransport.GETSOCKOPT) {
      return status == RemoteParentStatus.VALID
          && (requested == RemoteParentTransport.AUTO
              || requested == RemoteParentTransport.GETSOCKOPT)
          && attempted == GETSOCKOPT_ATTEMPTED
          && getsockoptStatus == RemoteParentStatus.VALID
          && unixStatus == RemoteParentStatus.UNKNOWN;
    }
    if (selected == RemoteParentTransport.UNIX) {
      if (status != RemoteParentStatus.VALID || unixStatus != RemoteParentStatus.VALID) {
        return false;
      }
      if (requested == RemoteParentTransport.AUTO) {
        return attempted == ATTEMPT_MASK && isGetsockoptProbeFailure(getsockoptStatus);
      }
      return requested == RemoteParentTransport.UNIX
          && attempted == UNIX_ATTEMPTED
          && getsockoptStatus == RemoteParentStatus.UNKNOWN;
    }
    if (selected == RemoteParentTransport.DISABLED) {
      return status == RemoteParentStatus.DISABLED
          && requested == RemoteParentTransport.DISABLED
          && attempted == 0;
    }
    return status != RemoteParentStatus.VALID
        && isConsistentFailure(status, requested, attempted, getsockoptStatus, unixStatus);
  }

  private static boolean isLegacy(long configuration) {
    int status = status(configuration);
    int requested = requested(configuration);
    int selected = selected(configuration);
    if (!RemoteParentStatus.isKnown(status)
        || !isTransport(requested)
        || attempted(configuration) != 0
        || getsockoptStatus(configuration) != RemoteParentStatus.UNKNOWN
        || unixStatus(configuration) != RemoteParentStatus.UNKNOWN) {
      return false;
    }
    if (status == RemoteParentStatus.VALID) {
      if (requested == RemoteParentTransport.AUTO) {
        return selected == NONE;
      }
      return (requested == RemoteParentTransport.GETSOCKOPT
              || requested == RemoteParentTransport.UNIX)
          && selected == requested;
    }
    if (status == RemoteParentStatus.UNKNOWN || status == RemoteParentStatus.MISSING) {
      return false;
    }
    if (status == RemoteParentStatus.DISABLED) {
      if (requested == RemoteParentTransport.DISABLED) {
        return selected == RemoteParentTransport.DISABLED;
      }
      return (requested == RemoteParentTransport.AUTO || requested == RemoteParentTransport.UNIX)
          && selected == NONE;
    }
    if (selected != NONE) {
      return false;
    }
    if (requested == RemoteParentTransport.GETSOCKOPT) {
      return isGetsockoptProbeFailure(status);
    }
    if (requested == RemoteParentTransport.AUTO || requested == RemoteParentTransport.UNIX) {
      return isUnixProbeFailure(status);
    }
    return status == RemoteParentStatus.MALFORMED
        || status == RemoteParentStatus.TIMEOUT
        || status == RemoteParentStatus.TRANSPORT_ERROR;
  }

  private static boolean isGetsockoptProbeOutcome(int status) {
    return status == RemoteParentStatus.VALID || isGetsockoptProbeFailure(status);
  }

  private static boolean isGetsockoptProbeFailure(int status) {
    return status == RemoteParentStatus.UNSUPPORTED
        || status == RemoteParentStatus.MALFORMED
        || status == RemoteParentStatus.UNAUTHORIZED
        || status == RemoteParentStatus.TIMEOUT
        || status == RemoteParentStatus.OVERLOAD
        || status == RemoteParentStatus.TRANSPORT_ERROR;
  }

  private static boolean isUnixProbeOutcome(int status) {
    return status == RemoteParentStatus.VALID || isUnixProbeFailure(status);
  }

  private static boolean isUnixProbeFailure(int status) {
    return RemoteParentStatus.isKnown(status)
        && status != RemoteParentStatus.UNKNOWN
        && status != RemoteParentStatus.VALID
        && status != RemoteParentStatus.MISSING;
  }

  private static boolean isConsistentFailure(
      int status, int requested, int attempted, int getsockoptStatus, int unixStatus) {
    if (attempted == 0) {
      return isZeroAttemptFailure(status, requested);
    }
    if (requested == RemoteParentTransport.GETSOCKOPT) {
      return getsockoptStatus == RemoteParentStatus.VALID
          ? isSwapFailure(status)
          : status == getsockoptStatus;
    }
    if (requested == RemoteParentTransport.UNIX) {
      return unixStatus == RemoteParentStatus.VALID ? isSwapFailure(status) : status == unixStatus;
    }
    if (requested == RemoteParentTransport.AUTO && attempted == GETSOCKOPT_ATTEMPTED) {
      return getsockoptStatus == RemoteParentStatus.VALID
          ? isSwapFailure(status)
          : status == RemoteParentStatus.UNSUPPORTED;
    }
    if (requested == RemoteParentTransport.AUTO && attempted == ATTEMPT_MASK) {
      return unixStatus == RemoteParentStatus.VALID ? isSwapFailure(status) : status == unixStatus;
    }
    return false;
  }

  private static boolean isSwapFailure(int status) {
    return status == RemoteParentStatus.TIMEOUT || status == RemoteParentStatus.TRANSPORT_ERROR;
  }

  private static boolean isZeroAttemptFailure(int status, int requested) {
    if (status == RemoteParentStatus.MALFORMED
        || status == RemoteParentStatus.VERSION_MISMATCH
        || status == RemoteParentStatus.TRANSPORT_ERROR) {
      return true;
    }
    if (requested == RemoteParentTransport.DISABLED) {
      return status == RemoteParentStatus.TIMEOUT;
    }
    if (status == RemoteParentStatus.UNAUTHORIZED || status == RemoteParentStatus.OVERLOAD) {
      return true;
    }
    return requested == RemoteParentTransport.UNIX && status == RemoteParentStatus.UNSUPPORTED;
  }

  private static boolean isTransport(int transport) {
    return transport >= RemoteParentTransport.AUTO && transport <= RemoteParentTransport.DISABLED;
  }

  private static int normalizeRequested(int requested) {
    return isTransport(requested) ? requested : NONE;
  }

  private static int magic(long configuration) {
    return field(configuration, MAGIC_SHIFT);
  }

  private static int field(long configuration, int shift) {
    return (int) ((configuration >>> shift) & 0xffL);
  }

  private static long pack(
      int version,
      int status,
      int requested,
      int selected,
      int attempted,
      int getsockoptStatus,
      int unixStatus) {
    return byteAt(status, STATUS_SHIFT)
        | byteAt(requested, REQUESTED_SHIFT)
        | byteAt(selected, SELECTED_SHIFT)
        | byteAt(attempted, ATTEMPTED_SHIFT)
        | byteAt(getsockoptStatus, GETSOCKOPT_STATUS_SHIFT)
        | byteAt(unixStatus, UNIX_STATUS_SHIFT)
        | byteAt(version, VERSION_SHIFT)
        | byteAt(MAGIC, MAGIC_SHIFT);
  }

  private static long byteAt(int value, int shift) {
    return ((long) value & 0xffL) << shift;
  }
}
