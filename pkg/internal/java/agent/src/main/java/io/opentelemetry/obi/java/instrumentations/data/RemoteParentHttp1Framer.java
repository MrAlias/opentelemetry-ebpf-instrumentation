/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

/**
 * A bounded, fail-closed HTTP/1 request stream framer for remote-parent receive ownership.
 *
 * <p>This class deliberately does not extract headers and does not call the native bridge. It only
 * determines when a complete, strictly framed request header is available and which receive bytes
 * belong to that request. All malformed, unsupported, or ambiguous streams enter a sticky terminal
 * state. {@link #reset()} is the only way to resume parsing after a terminal result.
 *
 * <p>The complete request line and header block are retained until they have been validated. When
 * {@link Action#START} is returned, {@link ReceivePlan#deferredPrefix()} contains bytes from
 * earlier receives and {@link ReceivePlan#offset()} / {@link ReceivePlan#length()} identify the
 * non-overlap slice in the current source array. The deferred prefix is emitted in that one START
 * plan only. Bodies are never buffered.
 */
public final class RemoteParentHttp1Framer {
  static final int MAX_REQUEST_LINE_BYTES = 8 * 1024;
  static final int MAX_HEADER_LINE_BYTES = 8 * 1024;
  static final int MAX_HEADER_BYTES = 32 * 1024;
  static final int MAX_RETAINED_BYTES = MAX_REQUEST_LINE_BYTES + MAX_HEADER_BYTES;

  private static final byte[] EMPTY = new byte[0];

  /** The operation that a receive owner may perform for one accepted source range. */
  public enum Action {
    /** No bytes were accepted. The caller must not perform any native operation. */
    NOOP,
    /** More request-line or header bytes are required. No ownership may be started yet. */
    DEFER,
    /** A complete validated header section starts the identified request sequence. */
    START,
    /** Bytes continue the already-started request sequence. */
    CONTINUE,
    /** The stream is unsupported or malformed and must remain untracked until reset. */
    UNTRACKED,
    /** A receive crosses an ownership boundary that cannot be represented without a FIFO. */
    AMBIGUOUS
  }

  /** Immutable instructions for one call to {@link #accept(byte[], int, int)}. */
  public static final class ReceivePlan {
    private final Action action;
    private final long requestSequence;
    private final byte[] deferredPrefix;
    private final byte[] telemetryPrefix;
    private final int offset;
    private final int length;
    private final boolean endOfMessage;

    private ReceivePlan(
        Action action,
        long requestSequence,
        byte[] deferredPrefix,
        byte[] telemetryPrefix,
        int offset,
        int length,
        boolean endOfMessage) {
      this.action = action;
      this.requestSequence = requestSequence;
      // The constructor is private and every non-empty caller passes a newly allocated copy.
      this.deferredPrefix = deferredPrefix;
      this.telemetryPrefix = telemetryPrefix;
      this.offset = offset;
      this.length = length;
      this.endOfMessage = endOfMessage;
    }

    public Action action() {
      return action;
    }

    /**
     * Returns the positive sequence for START/CONTINUE and terminal cleanup of an earlier START, or
     * zero when no request has been staged.
     */
    public long requestSequence() {
      return requestSequence;
    }

    /**
     * Returns a defensive copy of pre-START bytes from earlier receives.
     *
     * <p>This is non-empty only on the single START plan that consumes those bytes.
     */
    public byte[] deferredPrefix() {
      return deferredPrefix.length == 0 ? EMPTY : copyOf(deferredPrefix, deferredPrefix.length);
    }

    /**
     * Returns bytes retained before this receive that must precede its source slice when an
     * unsupported stream falls back to telemetry-only emission.
     */
    public byte[] telemetryPrefix() {
      return telemetryPrefix.length == 0 ? EMPTY : copyOf(telemetryPrefix, telemetryPrefix.length);
    }

    /** Offset of this plan's non-deferred slice in the array passed to {@code accept}. */
    public int offset() {
      return offset;
    }

    /** Length of this plan's non-deferred slice; zero when no source bytes may be emitted. */
    public int length() {
      return length;
    }

    /** Whether the identified request ends in this plan's source slice. */
    public boolean endOfMessage() {
      return endOfMessage;
    }
  }

  private enum State {
    REQUEST_LINE,
    HEADERS,
    FIXED_BODY,
    CHUNK_SIZE,
    CHUNK_DATA,
    CHUNK_DATA_CR,
    CHUNK_DATA_LF,
    TRAILERS,
    BETWEEN_MESSAGES,
    TERMINAL_UNTRACKED,
    TERMINAL_AMBIGUOUS
  }

  private enum BodyKind {
    NONE,
    FIXED,
    CHUNKED,
    INVALID
  }

  // This one adaptively sized buffer retains either the pre-START request prefix or one post-START
  // framing line. Both its capacity and its logical contents are bounded by MAX_RETAINED_BYTES.
  private byte[] buffer = EMPTY;

  private State state = State.REQUEST_LINE;
  private int bufferLength;
  private int lineStart;
  private int lineLength;
  private int headerBytes;
  private int trailerBytes;

  private boolean contentLengthSeen;
  private long contentLength;
  private boolean transferEncodingSeen;
  private boolean upgradeRequested;
  private long bodyRemaining;

  private long lastRequestSequence;
  private long activeRequestSequence;
  private long startReturnedSequence;
  private long extractionObservedSequence;

  /** Accepts exactly the selected bytes without modifying the source array. */
  public synchronized ReceivePlan accept(byte[] source, int offset, int length) {
    if (source == null) {
      throw new NullPointerException("source");
    }
    if (offset < 0 || length < 0 || offset > source.length - length) {
      throw new IndexOutOfBoundsException(
          "invalid source range: offset="
              + offset
              + ", length="
              + length
              + ", capacity="
              + source.length);
    }

    if (length == 0) {
      return new ReceivePlan(Action.NOOP, 0, EMPTY, EMPTY, offset, 0, false);
    }
    if (state == State.TERMINAL_UNTRACKED) {
      return terminalPlan(Action.UNTRACKED, offset, length, EMPTY);
    }
    if (state == State.TERMINAL_AMBIGUOUS) {
      return terminalPlan(Action.AMBIGUOUS, offset, 0, EMPTY);
    }

    int end = offset + length;
    int index = offset;
    boolean startedThisAccept = false;
    boolean endedThisAccept = false;
    byte[] deferredPrefix = EMPTY;
    int planOffset = offset;

    // Bytes already retained at this receive boundary are precisely the non-overlapping prefix
    // that a later START plan must emit. A request that begins in this receive has no prefix.
    int bytesBeforeAccept = isPreStartState() ? bufferLength : 0;
    int requestOffsetInAccept = isPreStartState() ? offset : -1;

    while (index < end && !isTerminal()) {
      switch (state) {
        case BETWEEN_MESSAGES:
          // Crossing a message boundary inside one receive cannot be represented by one plan. A
          // new receive may start the next request only after the previous START was acknowledged.
          if (endedThisAccept
              || activeRequestSequence == 0
              || extractionObservedSequence != activeRequestSequence) {
            failAmbiguous();
            break;
          }
          beginRequestPrelude();
          bytesBeforeAccept = 0;
          requestOffsetInAccept = index;
          break;

        case REQUEST_LINE:
          if (!appendPreludeByte(source[index++], MAX_REQUEST_LINE_BYTES, false)) {
            break;
          }
          if (lineComplete()) {
            if (!validRequestLine(buffer, lineStart, lineLength - 2)) {
              failUntracked();
              break;
            }
            state = State.HEADERS;
            lineStart = bufferLength;
            lineLength = 0;
            headerBytes = 0;
          }
          break;

        case HEADERS:
          if (!appendPreludeByte(source[index++], MAX_HEADER_LINE_BYTES, true)) {
            break;
          }
          if (lineComplete()) {
            if (lineLength == 2) {
              BodyKind bodyKind = finishHeaders();
              if (bodyKind == BodyKind.INVALID) {
                failUntracked();
                break;
              }
              if (lastRequestSequence == Long.MAX_VALUE) {
                failUntracked();
                break;
              }

              activeRequestSequence = ++lastRequestSequence;
              startReturnedSequence = 0;
              extractionObservedSequence = 0;
              startedThisAccept = true;
              planOffset = requestOffsetInAccept;
              deferredPrefix = copyOf(buffer, bytesBeforeAccept);

              clearBuffer();
              releaseOversizedBuffer();
              if (bodyKind == BodyKind.NONE) {
                state = State.BETWEEN_MESSAGES;
                endedThisAccept = true;
              } else if (bodyKind == BodyKind.FIXED) {
                bodyRemaining = contentLength;
                state = State.FIXED_BODY;
              } else {
                state = State.CHUNK_SIZE;
              }
            } else {
              if (!parseHeader(buffer, lineStart, lineLength - 2, false)) {
                failUntracked();
                break;
              }
              lineStart = bufferLength;
              lineLength = 0;
            }
          }
          break;

        case FIXED_BODY:
          int fixedAvailable = end - index;
          int fixedConsumed = bodyRemaining < fixedAvailable ? (int) bodyRemaining : fixedAvailable;
          index += fixedConsumed;
          bodyRemaining -= fixedConsumed;
          if (bodyRemaining == 0) {
            state = State.BETWEEN_MESSAGES;
            endedThisAccept = true;
          }
          break;

        case CHUNK_SIZE:
          if (!appendFramingByte(source[index++], MAX_HEADER_LINE_BYTES)) {
            break;
          }
          if (lineComplete()) {
            long chunkSize = parseChunkSize(buffer, lineStart, lineLength - 2);
            clearBuffer();
            if (chunkSize < 0) {
              failUntracked();
            } else if (chunkSize == 0) {
              trailerBytes = 0;
              state = State.TRAILERS;
            } else {
              bodyRemaining = chunkSize;
              state = State.CHUNK_DATA;
            }
          }
          break;

        case CHUNK_DATA:
          int chunkAvailable = end - index;
          int chunkConsumed = bodyRemaining < chunkAvailable ? (int) bodyRemaining : chunkAvailable;
          index += chunkConsumed;
          bodyRemaining -= chunkConsumed;
          if (bodyRemaining == 0) {
            state = State.CHUNK_DATA_CR;
          }
          break;

        case CHUNK_DATA_CR:
          if (source[index++] != '\r') {
            failUntracked();
          } else {
            state = State.CHUNK_DATA_LF;
          }
          break;

        case CHUNK_DATA_LF:
          if (source[index++] != '\n') {
            failUntracked();
          } else {
            state = State.CHUNK_SIZE;
          }
          break;

        case TRAILERS:
          if (trailerBytes == MAX_HEADER_BYTES) {
            failUntracked();
            break;
          }
          trailerBytes++;
          if (!appendFramingByte(source[index++], MAX_HEADER_LINE_BYTES)) {
            break;
          }
          if (lineComplete()) {
            if (lineLength == 2) {
              clearBuffer();
              state = State.BETWEEN_MESSAGES;
              endedThisAccept = true;
            } else {
              if (!parseHeader(buffer, lineStart, lineLength - 2, true)) {
                failUntracked();
                break;
              }
              clearBuffer();
            }
          }
          break;

        case TERMINAL_UNTRACKED:
        case TERMINAL_AMBIGUOUS:
          break;
      }
    }

    if (state == State.TERMINAL_UNTRACKED) {
      // Header completion clears and may shrink the shared framing buffer before later bytes in
      // this same receive expose malformed body framing. In that case the exact pre-receive bytes
      // already live in deferredPrefix; rebuilding them from the reused buffer would corrupt the
      // telemetry fallback (or read beyond a newly shrunken buffer).
      byte[] telemetryPrefix =
          startedThisAccept ? deferredPrefix : copyOf(buffer, bytesBeforeAccept);
      clearBuffer();
      releaseOversizedBuffer();
      return terminalPlan(Action.UNTRACKED, offset, length, telemetryPrefix);
    }
    if (state == State.TERMINAL_AMBIGUOUS) {
      return terminalPlan(Action.AMBIGUOUS, offset, 0, EMPTY);
    }
    if (startedThisAccept) {
      startReturnedSequence = activeRequestSequence;
      return new ReceivePlan(
          Action.START,
          activeRequestSequence,
          deferredPrefix,
          EMPTY,
          planOffset,
          end - planOffset,
          endedThisAccept);
    }
    if (isPreStartState()) {
      return new ReceivePlan(Action.DEFER, 0, EMPTY, EMPTY, offset, 0, false);
    }
    return new ReceivePlan(
        Action.CONTINUE, activeRequestSequence, EMPTY, EMPTY, offset, length, endedThisAccept);
  }

  /**
   * Acknowledges that the START plan for {@code requestSequence} was observed by the extractor.
   *
   * @return true for the current emitted START sequence; false for zero, stale, future, or terminal
   *     sequences
   */
  public synchronized boolean extractionObserved(long requestSequence) {
    if (isTerminal()
        || requestSequence <= 0
        || requestSequence != activeRequestSequence
        || requestSequence != startReturnedSequence
        || requestSequence == extractionObservedSequence) {
      return false;
    }
    extractionObservedSequence = requestSequence;
    return true;
  }

  /** Clears all framing/terminal state while keeping request sequence numbers monotonic. */
  public synchronized void reset() {
    state = State.REQUEST_LINE;
    clearBuffer();
    releaseOversizedBuffer();
    headerBytes = 0;
    trailerBytes = 0;
    contentLengthSeen = false;
    contentLength = 0;
    transferEncodingSeen = false;
    upgradeRequested = false;
    bodyRemaining = 0;
    activeRequestSequence = 0;
    startReturnedSequence = 0;
    extractionObservedSequence = 0;
  }

  /** Permanently releases retained bytes and prevents this lifecycle from accepting more input. */
  synchronized void discard() {
    state = State.TERMINAL_UNTRACKED;
    clearBuffer();
    buffer = EMPTY;
    headerBytes = 0;
    trailerBytes = 0;
    contentLengthSeen = false;
    contentLength = 0;
    transferEncodingSeen = false;
    upgradeRequested = false;
    bodyRemaining = 0;
    activeRequestSequence = 0;
    startReturnedSequence = 0;
    extractionObservedSequence = 0;
  }

  /** Drains only never-emitted pre-START bytes, then permanently discards all framing state. */
  synchronized byte[] drainDeferredForTelemetry() {
    byte[] deferred = isPreStartState() ? copyOf(buffer, bufferLength) : EMPTY;
    discard();
    return deferred;
  }

  /** Number of source octets currently retained for a future framing decision. */
  synchronized int retainedBytes() {
    return bufferLength;
  }

  private ReceivePlan terminalPlan(Action action, int offset, int length, byte[] telemetryPrefix) {
    return new ReceivePlan(
        action, startReturnedSequence, EMPTY, telemetryPrefix, offset, length, false);
  }

  private void beginRequestPrelude() {
    state = State.REQUEST_LINE;
    clearBuffer();
    headerBytes = 0;
    contentLengthSeen = false;
    contentLength = 0;
    transferEncodingSeen = false;
    upgradeRequested = false;
    activeRequestSequence = 0;
    startReturnedSequence = 0;
    extractionObservedSequence = 0;
  }

  private boolean appendPreludeByte(byte value, int maximumLineBytes, boolean header) {
    if (lineLength == maximumLineBytes || bufferLength == MAX_RETAINED_BYTES) {
      failUntracked();
      return false;
    }
    if (header) {
      if (headerBytes == MAX_HEADER_BYTES) {
        failUntracked();
        return false;
      }
      headerBytes++;
    }
    if (invalidLineContinuation(value)) {
      failUntracked();
      return false;
    }
    ensureBufferCapacity(bufferLength + 1);
    buffer[bufferLength++] = value;
    lineLength++;
    return true;
  }

  private boolean appendFramingByte(byte value, int maximumLineBytes) {
    if (lineLength == maximumLineBytes) {
      failUntracked();
      return false;
    }
    if (invalidLineContinuation(value)) {
      failUntracked();
      return false;
    }
    ensureBufferCapacity(bufferLength + 1);
    buffer[bufferLength++] = value;
    lineLength++;
    return true;
  }

  private boolean invalidLineContinuation(byte value) {
    int unsigned = value & 0xff;
    if (unsigned == '\n') {
      return lineLength == 0 || buffer[bufferLength - 1] != '\r';
    }
    return lineLength > 0 && buffer[bufferLength - 1] == '\r';
  }

  private boolean lineComplete() {
    return lineLength >= 2 && buffer[bufferLength - 2] == '\r' && buffer[bufferLength - 1] == '\n';
  }

  private BodyKind finishHeaders() {
    if (upgradeRequested || (contentLengthSeen && transferEncodingSeen)) {
      return BodyKind.INVALID;
    }
    if (transferEncodingSeen) {
      return BodyKind.CHUNKED;
    }
    if (contentLengthSeen && contentLength != 0) {
      return BodyKind.FIXED;
    }
    return BodyKind.NONE;
  }

  private boolean parseHeader(byte[] bytes, int offset, int length, boolean trailer) {
    if (length == 0 || bytes[offset] == ' ' || bytes[offset] == '\t') {
      return false;
    }

    int end = offset + length;
    int colon = offset;
    while (colon < end && bytes[colon] != ':') {
      if (!isToken(bytes[colon] & 0xff)) {
        return false;
      }
      colon++;
    }
    if (colon == offset || colon == end) {
      return false;
    }
    for (int i = colon + 1; i < end; i++) {
      int value = bytes[i] & 0xff;
      if ((value < 0x20 && value != '\t') || value == 0x7f) {
        return false;
      }
    }

    int valueOffset = colon + 1;
    int valueLength = end - valueOffset;
    if (trailer) {
      return !asciiEquals(bytes, offset, colon - offset, "content-length")
          && !asciiEquals(bytes, offset, colon - offset, "transfer-encoding")
          && !asciiEquals(bytes, offset, colon - offset, "connection")
          && !asciiEquals(bytes, offset, colon - offset, "upgrade")
          && !asciiEquals(bytes, offset, colon - offset, "host");
    }

    if (asciiEquals(bytes, offset, colon - offset, "content-length")) {
      return parseContentLength(bytes, valueOffset, valueLength);
    }
    if (asciiEquals(bytes, offset, colon - offset, "transfer-encoding")) {
      if (transferEncodingSeen || !singleTokenEquals(bytes, valueOffset, valueLength, "chunked")) {
        return false;
      }
      transferEncodingSeen = true;
      return true;
    }
    if (asciiEquals(bytes, offset, colon - offset, "upgrade")) {
      upgradeRequested = true;
      return true;
    }
    if (asciiEquals(bytes, offset, colon - offset, "connection")) {
      int connection = connectionTokens(bytes, valueOffset, valueLength);
      if (connection < 0) {
        return false;
      }
      if (connection > 0) {
        upgradeRequested = true;
      }
    }
    return true;
  }

  private boolean parseContentLength(byte[] bytes, int offset, int length) {
    int end = offset + length;
    int cursor = offset;
    boolean parsed = false;
    long common = 0;
    while (cursor < end) {
      while (cursor < end && isOptionalWhitespace(bytes[cursor])) {
        cursor++;
      }
      if (cursor == end || bytes[cursor] < '0' || bytes[cursor] > '9') {
        return false;
      }
      long value = 0;
      do {
        int digit = bytes[cursor++] - '0';
        if (value > (Long.MAX_VALUE - digit) / 10) {
          return false;
        }
        value = value * 10 + digit;
      } while (cursor < end && bytes[cursor] >= '0' && bytes[cursor] <= '9');

      while (cursor < end && isOptionalWhitespace(bytes[cursor])) {
        cursor++;
      }
      if (!parsed) {
        common = value;
        parsed = true;
      } else if (common != value) {
        return false;
      }
      if (cursor == end) {
        break;
      }
      if (bytes[cursor++] != ',') {
        return false;
      }
      int next = cursor;
      while (next < end && isOptionalWhitespace(bytes[next])) {
        next++;
      }
      if (next == end) {
        return false;
      }
    }
    if (!parsed || (contentLengthSeen && contentLength != common)) {
      return false;
    }
    contentLengthSeen = true;
    contentLength = common;
    return true;
  }

  // Returns -1 for malformed, 0 without an upgrade token, and 1 with one.
  private static int connectionTokens(byte[] bytes, int offset, int length) {
    int end = offset + length;
    int cursor = offset;
    boolean sawToken = false;
    boolean upgrade = false;
    while (cursor < end) {
      while (cursor < end && isOptionalWhitespace(bytes[cursor])) {
        cursor++;
      }
      int tokenStart = cursor;
      while (cursor < end && isToken(bytes[cursor] & 0xff)) {
        cursor++;
      }
      if (cursor == tokenStart) {
        return -1;
      }
      sawToken = true;
      if (asciiEquals(bytes, tokenStart, cursor - tokenStart, "upgrade")) {
        upgrade = true;
      }
      while (cursor < end && isOptionalWhitespace(bytes[cursor])) {
        cursor++;
      }
      if (cursor == end) {
        break;
      }
      if (bytes[cursor++] != ',') {
        return -1;
      }
      int next = cursor;
      while (next < end && isOptionalWhitespace(bytes[next])) {
        next++;
      }
      if (next == end) {
        return -1;
      }
    }
    return sawToken ? (upgrade ? 1 : 0) : -1;
  }

  private static boolean singleTokenEquals(byte[] bytes, int offset, int length, String expected) {
    int start = offset;
    int end = offset + length;
    while (start < end && isOptionalWhitespace(bytes[start])) {
      start++;
    }
    while (end > start && isOptionalWhitespace(bytes[end - 1])) {
      end--;
    }
    return asciiEquals(bytes, start, end - start, expected);
  }

  private static long parseChunkSize(byte[] bytes, int offset, int length) {
    int end = offset + length;
    int cursor = offset;
    long value = 0;
    int digits = 0;
    while (cursor < end) {
      int digit = hexValue(bytes[cursor] & 0xff);
      if (digit < 0) {
        break;
      }
      if (value > (Long.MAX_VALUE - digit) / 16) {
        return -1;
      }
      value = value * 16 + digit;
      cursor++;
      digits++;
    }
    if (digits == 0) {
      return -1;
    }
    if (cursor != end) {
      return -1;
    }
    return value;
  }

  private static boolean validRequestLine(byte[] bytes, int offset, int length) {
    int end = offset + length;
    int firstSpace = offset;
    while (firstSpace < end && bytes[firstSpace] != ' ') {
      firstSpace++;
    }
    if (firstSpace == offset || firstSpace == end) {
      return false;
    }
    if (!supportedMethod(bytes, offset, firstSpace - offset)) {
      return false;
    }

    int target = firstSpace + 1;
    int secondSpace = target;
    while (secondSpace < end && bytes[secondSpace] != ' ') {
      int value = bytes[secondSpace] & 0xff;
      if (value < 0x21 || value > 0x7e) {
        return false;
      }
      secondSpace++;
    }
    if (secondSpace == target
        || secondSpace == end
        || !validRequestTarget(bytes, target, secondSpace - target)) {
      return false;
    }

    int version = secondSpace + 1;
    if (end - version != 8
        || bytes[version] != 'H'
        || bytes[version + 1] != 'T'
        || bytes[version + 2] != 'T'
        || bytes[version + 3] != 'P'
        || bytes[version + 4] != '/'
        || bytes[version + 5] != '1'
        || bytes[version + 6] != '.'
        || bytes[version + 7] != '1') {
      return false;
    }
    return true;
  }

  private static boolean validRequestTarget(byte[] bytes, int offset, int length) {
    if (bytes[offset] == '/') {
      return !contains(bytes, offset, length, '#');
    }

    int schemeLength;
    if (asciiStartsWith(bytes, offset, length, "http://")) {
      schemeLength = 7;
    } else if (asciiStartsWith(bytes, offset, length, "https://")) {
      schemeLength = 8;
    } else {
      return false;
    }
    if (length == schemeLength) {
      return false;
    }
    int authority = bytes[offset + schemeLength] & 0xff;
    return authority != '/'
        && authority != '?'
        && authority != '#'
        && !contains(bytes, offset, length, '#');
  }

  private static boolean supportedMethod(byte[] bytes, int offset, int length) {
    return exactAsciiEquals(bytes, offset, length, "GET")
        || exactAsciiEquals(bytes, offset, length, "POST")
        || exactAsciiEquals(bytes, offset, length, "PUT")
        || exactAsciiEquals(bytes, offset, length, "PATCH")
        || exactAsciiEquals(bytes, offset, length, "DELETE")
        || exactAsciiEquals(bytes, offset, length, "HEAD")
        || exactAsciiEquals(bytes, offset, length, "OPTIONS");
  }

  private static boolean exactAsciiEquals(byte[] bytes, int offset, int length, String expected) {
    if (length != expected.length()) {
      return false;
    }
    for (int i = 0; i < length; i++) {
      if ((bytes[offset + i] & 0xff) != expected.charAt(i)) {
        return false;
      }
    }
    return true;
  }

  private static boolean asciiEquals(byte[] bytes, int offset, int length, String expected) {
    if (length != expected.length()) {
      return false;
    }
    for (int i = 0; i < length; i++) {
      int actual = bytes[offset + i] & 0xff;
      char wanted = expected.charAt(i);
      if (actual >= 'A' && actual <= 'Z') {
        actual += 'a' - 'A';
      }
      if (wanted >= 'A' && wanted <= 'Z') {
        wanted = (char) (wanted + ('a' - 'A'));
      }
      if (actual != wanted) {
        return false;
      }
    }
    return true;
  }

  private static boolean asciiStartsWith(byte[] bytes, int offset, int length, String expected) {
    if (length < expected.length()) {
      return false;
    }
    for (int i = 0; i < expected.length(); i++) {
      int actual = bytes[offset + i] & 0xff;
      int wanted = expected.charAt(i);
      if (actual >= 'A' && actual <= 'Z') {
        actual += 'a' - 'A';
      }
      if (actual != wanted) {
        return false;
      }
    }
    return true;
  }

  private static boolean contains(byte[] bytes, int offset, int length, int wanted) {
    int end = offset + length;
    for (int i = offset; i < end; i++) {
      if ((bytes[i] & 0xff) == wanted) {
        return true;
      }
    }
    return false;
  }

  private static boolean isOptionalWhitespace(byte value) {
    return value == ' ' || value == '\t';
  }

  private static boolean isToken(int value) {
    if ((value >= '0' && value <= '9')
        || (value >= 'A' && value <= 'Z')
        || (value >= 'a' && value <= 'z')) {
      return true;
    }
    switch (value) {
      case '!':
      case '#':
      case '$':
      case '%':
      case '&':
      case '\'':
      case '*':
      case '+':
      case '-':
      case '.':
      case '^':
      case '_':
      case '`':
      case '|':
      case '~':
        return true;
      default:
        return false;
    }
  }

  private static int hexValue(int value) {
    if (value >= '0' && value <= '9') {
      return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
      return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
      return value - 'A' + 10;
    }
    return -1;
  }

  private static byte[] copyOf(byte[] source, int length) {
    if (length == 0) {
      return EMPTY;
    }
    byte[] copy = new byte[length];
    System.arraycopy(source, 0, copy, 0, length);
    return copy;
  }

  private boolean isPreStartState() {
    return state == State.REQUEST_LINE || state == State.HEADERS;
  }

  private boolean isTerminal() {
    return state == State.TERMINAL_UNTRACKED || state == State.TERMINAL_AMBIGUOUS;
  }

  private void clearBuffer() {
    bufferLength = 0;
    lineStart = 0;
    lineLength = 0;
  }

  private void ensureBufferCapacity(int required) {
    if (required <= buffer.length) {
      return;
    }
    int capacity = buffer.length == 0 ? 128 : buffer.length;
    while (capacity < required) {
      int doubled = capacity << 1;
      capacity = doubled <= 0 || doubled > MAX_RETAINED_BYTES ? MAX_RETAINED_BYTES : doubled;
    }
    byte[] replacement = new byte[capacity];
    System.arraycopy(buffer, 0, replacement, 0, bufferLength);
    buffer = replacement;
  }

  private void releaseOversizedBuffer() {
    if (buffer.length > MAX_HEADER_LINE_BYTES) {
      buffer = EMPTY;
    }
  }

  private void failUntracked() {
    state = State.TERMINAL_UNTRACKED;
    bodyRemaining = 0;
  }

  private void failAmbiguous() {
    state = State.TERMINAL_AMBIGUOUS;
    clearBuffer();
    releaseOversizedBuffer();
    bodyRemaining = 0;
  }
}
