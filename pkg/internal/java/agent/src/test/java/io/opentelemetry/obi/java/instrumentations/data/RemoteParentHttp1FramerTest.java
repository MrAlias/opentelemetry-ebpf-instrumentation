/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static io.opentelemetry.obi.java.instrumentations.data.RemoteParentHttp1Framer.Action.AMBIGUOUS;
import static io.opentelemetry.obi.java.instrumentations.data.RemoteParentHttp1Framer.Action.CONTINUE;
import static io.opentelemetry.obi.java.instrumentations.data.RemoteParentHttp1Framer.Action.DEFER;
import static io.opentelemetry.obi.java.instrumentations.data.RemoteParentHttp1Framer.Action.NOOP;
import static io.opentelemetry.obi.java.instrumentations.data.RemoteParentHttp1Framer.Action.START;
import static io.opentelemetry.obi.java.instrumentations.data.RemoteParentHttp1Framer.Action.UNTRACKED;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

class RemoteParentHttp1FramerTest {
  private static final String[] METHODS = {
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
  };

  @Test
  void everySupportedMethodAndEveryPreludeSplitStartsExactlyOnce() {
    for (String method : METHODS) {
      byte[] request =
          ascii(
              method
                  + " /resource HTTP/1.1\r\n"
                  + "Host: example.test\r\n"
                  + "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n"
                  + "Expect: 100-continue\r\n"
                  + "Content-Length: 0\r\n\r\n");

      for (int split = 1; split < request.length; split++) {
        RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
        byte[] original = request.clone();

        RemoteParentHttp1Framer.ReceivePlan first = framer.accept(request, 0, split);
        assertEquals(DEFER, first.action(), method + " split " + split);
        assertEquals(0, first.requestSequence());
        assertEquals(0, first.length());
        assertArrayEquals(new byte[0], first.deferredPrefix());

        RemoteParentHttp1Framer.ReceivePlan second =
            framer.accept(request, split, request.length - split);
        assertEquals(START, second.action(), method + " split " + split);
        assertEquals(1, second.requestSequence());
        assertEquals(split, second.offset());
        assertEquals(request.length - split, second.length());
        assertTrue(second.endOfMessage());
        assertArrayEquals(Arrays.copyOfRange(request, 0, split), second.deferredPrefix());
        assertTrue(framer.extractionObserved(second.requestSequence()));
        assertArrayEquals(original, request, method + " split " + split);
      }
    }
  }

  @Test
  void startPlanOwnsItsPrefixAndIdentifiesOnlyTheSelectedSourceRange() {
    byte[] request =
        ascii(
            "POST / HTTP/1.1\r\n"
                + "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n"
                + "Content-Length: 4\r\n\r\nbody");
    byte[] source = new byte[request.length + 14];
    Arrays.fill(source, (byte) '!');
    System.arraycopy(request, 0, source, 7, request.length);
    byte[] original = source.clone();
    int split = indexOf(request, ascii("6789abcdef-01")) + 5;

    RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
    assertEquals(DEFER, framer.accept(source, 7, split).action());
    RemoteParentHttp1Framer.ReceivePlan start =
        framer.accept(source, 7 + split, request.length - split);

    assertEquals(START, start.action());
    assertEquals(7 + split, start.offset());
    assertEquals(request.length - split, start.length());
    assertTrue(start.endOfMessage());
    assertArrayEquals(Arrays.copyOfRange(request, 0, split), start.deferredPrefix());
    byte[] hostile = start.deferredPrefix();
    hostile[0] = 'X';
    assertArrayEquals(Arrays.copyOfRange(request, 0, split), start.deferredPrefix());
    assertArrayEquals(original, source);
    assertEquals(0, framer.retainedBytes());
  }

  @Test
  void deferredPrefixIncludesAllEarlierReceivesAndIsEmittedOnlyByStart() {
    byte[] request =
        ascii(
            "GET /three-parts HTTP/1.1\r\n"
                + "Host: example.test\r\n"
                + "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n\r\n");
    int firstEnd = 7;
    int secondEnd = request.length - 3;
    RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();

    RemoteParentHttp1Framer.ReceivePlan first = framer.accept(request, 0, firstEnd);
    RemoteParentHttp1Framer.ReceivePlan second =
        framer.accept(request, firstEnd, secondEnd - firstEnd);
    RemoteParentHttp1Framer.ReceivePlan start =
        framer.accept(request, secondEnd, request.length - secondEnd);

    assertEquals(DEFER, first.action());
    assertEquals(DEFER, second.action());
    assertArrayEquals(new byte[0], first.deferredPrefix());
    assertArrayEquals(new byte[0], second.deferredPrefix());
    assertEquals(START, start.action());
    assertArrayEquals(Arrays.copyOfRange(request, 0, secondEnd), start.deferredPrefix());
    assertEquals(secondEnd, start.offset());
    assertEquals(request.length - secondEnd, start.length());
    assertTrue(start.endOfMessage());
    assertTrue(framer.extractionObserved(start.requestSequence()));
    RemoteParentHttp1Framer.ReceivePlan idle = framer.accept(request, request.length, 0);
    assertEquals(NOOP, idle.action());
    assertEquals(0, idle.requestSequence());
    assertEquals(0, idle.length());
    assertFalse(idle.endOfMessage());
    assertArrayEquals(new byte[0], idle.deferredPrefix());
  }

  @Test
  void fixedBodyIsCountedWithoutParsingOrRetention() {
    byte[] headers = ascii("POST /upload HTTP/1.1\r\nContent-Length: 31\r\n\r\n");
    byte[] body = ascii("GET /looks-like-http HTTP/1.1\r\n");
    assertEquals(31, body.length);
    RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();

    RemoteParentHttp1Framer.ReceivePlan start = framer.accept(headers, 0, headers.length);
    assertEquals(START, start.action());
    assertFalse(start.endOfMessage());
    assertTrue(framer.extractionObserved(start.requestSequence()));

    for (int i = 0; i < body.length; i++) {
      RemoteParentHttp1Framer.ReceivePlan part = framer.accept(body, i, 1);
      assertEquals(CONTINUE, part.action(), "body byte " + i);
      assertEquals(1, part.requestSequence());
      assertEquals(i == body.length - 1, part.endOfMessage());
      assertEquals(0, framer.retainedBytes());
    }

    byte[] next = ascii("GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n");
    RemoteParentHttp1Framer.ReceivePlan nextStart = framer.accept(next, 0, next.length);
    assertEquals(START, nextStart.action());
    assertEquals(2, nextStart.requestSequence());
    assertTrue(nextStart.endOfMessage());
  }

  @Test
  void contentLengthDuplicatesMustAgreeAndDecimalOverflowFailsClosed() {
    assertStarts("POST / HTTP/1.1\r\nContent-Length: 5, 5\r\nContent-Length: 05\r\n\r\nhello");
    assertTerminalUntracked(
        "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!");
    assertTerminalUntracked("POST / HTTP/1.1\r\nContent-Length: 5, 6\r\n\r\nhello!");
    assertTerminalUntracked("POST / HTTP/1.1\r\nContent-Length: 5,\r\n\r\nhello");
    assertTerminalUntracked("POST / HTTP/1.1\r\nContent-Length: 9223372036854775808\r\n\r\n");
  }

  @Test
  void requestTargetsAndVersionMatchTheSupportedHttp11Contract() {
    String[] validTargets = {
      "/",
      "/path?query=value",
      "http://example.test",
      "https://example.test/path",
      "HTTP://example.test/path",
      "HTTPS://example.test/path"
    };
    for (String target : validTargets) {
      assertStarts("GET " + target + " HTTP/1.1\r\n\r\n");
    }

    String[] invalidTargets = {
      "h",
      "hello",
      "http:/example.test",
      "http://",
      "http:///path",
      "https://?query",
      "/path#fragment",
      "https://example.test/path#fragment"
    };
    for (String target : invalidTargets) {
      assertTerminalUntracked("GET " + target + " HTTP/1.1\r\n\r\n");
    }
    assertTerminalUntracked("GET / HTTP/1.0\r\n\r\n");
    assertTerminalUntracked("GET / HTTP/2.0\r\n\r\n");
  }

  @Test
  void everyChunkedAndTrailerSplitIsFramedWithoutBufferingBody() {
    byte[] request =
        ascii(
            "POST /chunks HTTP/1.1\r\n"
                + "Transfer-Encoding: chunked\r\n"
                + "Trailer: X-Checksum\r\n\r\n"
                + "4\r\nGET \r\n"
                + "8\r\n/request\r\n"
                + "0\r\n"
                + "X-Checksum: ok\r\n\r\n");
    int headerEnd = indexOf(request, ascii("\r\n\r\n")) + 4;

    for (int split = 1; split < request.length; split++) {
      RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
      RemoteParentHttp1Framer.ReceivePlan first = framer.accept(request, 0, split);
      if (split < headerEnd) {
        assertEquals(DEFER, first.action(), "split " + split);
      } else {
        assertEquals(START, first.action(), "split " + split);
        assertFalse(first.endOfMessage(), "split " + split);
        assertTrue(framer.extractionObserved(first.requestSequence()));
      }

      RemoteParentHttp1Framer.ReceivePlan second =
          framer.accept(request, split, request.length - split);
      assertEquals(split < headerEnd ? START : CONTINUE, second.action(), "split " + split);
      assertTrue(second.endOfMessage(), "split " + split);
      assertEquals(0, framer.retainedBytes(), "split " + split);
    }
  }

  @Test
  void malformedChunkFramingAndHexOverflowAreStickyUntracked() {
    assertChunkTerminal("3\r\nabcX\n0\r\n\r\n");
    assertChunkTerminal("3\r\nabc\rX0\r\n\r\n");
    assertChunkTerminal("8000000000000000\r\n");
    assertChunkTerminal("xyz\r\n");
    assertChunkTerminal("1;\r\na\r\n0\r\n\r\n");
    assertChunkTerminal("1;x=y\r\na\r\n0\r\n\r\n");
    assertChunkTerminal("1; x=y\r\na\r\n0\r\n\r\n");
    assertChunkTerminal("1;=x\r\na\r\n0\r\n\r\n");
    assertChunkTerminal("1;x=\"unterminated\r\na\r\n0\r\n\r\n");
    assertChunkTerminal("0\r\n Content-Fold: no\r\n\r\n");
    assertChunkTerminal("0\r\nContent-Length: 0\r\n\r\n");
  }

  @Test
  void coalescedMessagesAndUnacknowledgedOwnershipAreStickyAmbiguous() {
    byte[] one = ascii("GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n");
    byte[] two = ascii("GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n");
    byte[] both = concatenate(one, two);
    RemoteParentHttp1Framer coalesced = new RemoteParentHttp1Framer();

    assertEquals(AMBIGUOUS, coalesced.accept(both, 0, both.length).action());
    assertEquals(0, coalesced.accept(both, 0, both.length).requestSequence());
    assertEquals(AMBIGUOUS, coalesced.accept(one, 0, one.length).action());
    assertFalse(coalesced.extractionObserved(1));

    RemoteParentHttp1Framer unacknowledged = new RemoteParentHttp1Framer();
    RemoteParentHttp1Framer.ReceivePlan first = unacknowledged.accept(one, 0, one.length);
    assertEquals(START, first.action());
    assertTrue(first.endOfMessage());
    RemoteParentHttp1Framer.ReceivePlan ambiguous = unacknowledged.accept(two, 0, two.length);
    assertEquals(AMBIGUOUS, ambiguous.action());
    assertEquals(first.requestSequence(), ambiguous.requestSequence());

    coalesced.reset();
    RemoteParentHttp1Framer.ReceivePlan afterReset = coalesced.accept(one, 0, one.length);
    assertEquals(START, afterReset.action());
    assertEquals(2, afterReset.requestSequence());
    assertTrue(coalesced.extractionObserved(afterReset.requestSequence()));
    RemoteParentHttp1Framer.ReceivePlan sequential = coalesced.accept(two, 0, two.length);
    assertEquals(START, sequential.action());
    assertEquals(3, sequential.requestSequence());
  }

  @Test
  void extractionAcknowledgementIsExactAndOneShot() {
    byte[] one = ascii("GET /one HTTP/1.1\r\n\r\n");
    byte[] two = ascii("GET /two HTTP/1.1\r\n\r\n");
    RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();

    RemoteParentHttp1Framer.ReceivePlan first = framer.accept(one, 0, one.length);
    assertEquals(START, first.action());
    assertFalse(framer.extractionObserved(0));
    assertFalse(framer.extractionObserved(first.requestSequence() + 1));
    assertTrue(framer.extractionObserved(first.requestSequence()));
    assertFalse(framer.extractionObserved(first.requestSequence()));

    RemoteParentHttp1Framer.ReceivePlan second = framer.accept(two, 0, two.length);
    assertEquals(START, second.action());
    assertFalse(framer.extractionObserved(first.requestSequence()));
    assertFalse(framer.extractionObserved(second.requestSequence() + 1));
    assertTrue(framer.extractionObserved(second.requestSequence()));
    assertFalse(framer.extractionObserved(second.requestSequence()));

    framer.reset();
    assertFalse(framer.extractionObserved(second.requestSequence()));
    RemoteParentHttp1Framer.ReceivePlan afterReset = framer.accept(one, 0, one.length);
    assertEquals(second.requestSequence() + 1, afterReset.requestSequence());
  }

  @Test
  void zeroLengthInputIsANoopInEveryFramingPhaseAndTerminalState() {
    byte[] chunked =
        ascii(
            "POST /chunks HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                + "3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n");
    RemoteParentHttp1Framer chunkedFramer = new RemoteParentHttp1Framer();
    for (int i = 0; i < chunked.length; i++) {
      RemoteParentHttp1Framer.ReceivePlan bytePlan = chunkedFramer.accept(chunked, i, 1);
      if (bytePlan.action() == START) {
        assertTrue(chunkedFramer.extractionObserved(bytePlan.requestSequence()));
      }
      assertNoop(chunkedFramer, chunked, i + 1);
    }

    byte[] fixed = ascii("POST /fixed HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc");
    RemoteParentHttp1Framer fixedFramer = new RemoteParentHttp1Framer();
    for (int i = 0; i < fixed.length; i++) {
      RemoteParentHttp1Framer.ReceivePlan bytePlan = fixedFramer.accept(fixed, i, 1);
      if (bytePlan.action() == START) {
        assertTrue(fixedFramer.extractionObserved(bytePlan.requestSequence()));
      }
      assertNoop(fixedFramer, fixed, i + 1);
    }

    byte[] malformed = ascii("GET / HTTP/1.1\n\n");
    RemoteParentHttp1Framer terminal = new RemoteParentHttp1Framer();
    assertEquals(UNTRACKED, terminal.accept(malformed, 0, malformed.length).action());
    assertNoop(terminal, malformed, malformed.length);
    assertEquals(UNTRACKED, terminal.accept(malformed, 0, 1).action());
  }

  @Test
  void unsupportedMalformedAndUpgradeStreamsNeverResynchronize() {
    String[] invalid = {
      "CONNECT / HTTP/1.1\r\n\r\n",
      "TRACE / HTTP/1.1\r\n\r\n",
      "get / HTTP/1.1\r\n\r\n",
      "GET * HTTP/1.1\r\n\r\n",
      "GET / HTTP/1.0\r\n\r\n",
      "GET / HTTP/2.0\r\n\r\n",
      "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
      "GET / HTTP/1.1\nHost: example.test\n\n",
      "GET / HTTP/1.1\rXHost: example.test\r\n\r\n",
      "GET / HTTP/1.1\r\n folded: no\r\n\r\n",
      "POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
      "POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
      "GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
      "GET / HTTP/1.1\r\nConnection: keep-alive,\r\n\r\n",
      "GET / HTTP/1.1\r\nBad Header: value\r\n\r\n"
    };
    byte[] valid = ascii("GET /valid HTTP/1.1\r\n\r\n");

    for (String request : invalid) {
      RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
      byte[] bytes = ascii(request);
      assertEquals(UNTRACKED, framer.accept(bytes, 0, bytes.length).action(), request);
      assertEquals(UNTRACKED, framer.accept(valid, 0, valid.length).action(), request);
      assertEquals(0, framer.retainedBytes());
    }
  }

  @Test
  void requestHeaderAndTrailerLimitsAreEnforcedAtExactOctetBoundaries() {
    String exactRequestLine =
        "GET /"
            + repeat('a', RemoteParentHttp1Framer.MAX_REQUEST_LINE_BYTES - 16)
            + " HTTP/1.1\r\n";
    assertEquals(RemoteParentHttp1Framer.MAX_REQUEST_LINE_BYTES, ascii(exactRequestLine).length);
    assertStarts(exactRequestLine + "\r\n");
    assertTerminalUntracked(
        "GET /"
            + repeat('a', RemoteParentHttp1Framer.MAX_REQUEST_LINE_BYTES - 15)
            + " HTTP/1.1\r\n\r\n");

    String exactHeaderLine =
        "X:" + repeat('a', RemoteParentHttp1Framer.MAX_HEADER_LINE_BYTES - 4) + "\r\n";
    assertEquals(RemoteParentHttp1Framer.MAX_HEADER_LINE_BYTES, ascii(exactHeaderLine).length);
    assertStarts("GET / HTTP/1.1\r\n" + exactHeaderLine + "\r\n");
    assertTerminalUntracked(
        "GET / HTTP/1.1\r\n"
            + "X:"
            + repeat('a', RemoteParentHttp1Framer.MAX_HEADER_LINE_BYTES - 3)
            + "\r\n\r\n");

    String exactHeaders = exactHeaderBlock();
    assertEquals(RemoteParentHttp1Framer.MAX_HEADER_BYTES, ascii(exactHeaders).length);
    assertStarts("GET / HTTP/1.1\r\n" + exactHeaders);
    String overTotal =
        exactHeaderLine
            + exactHeaderLine
            + exactHeaderLine
            + "Y:"
            + repeat('b', RemoteParentHttp1Framer.MAX_HEADER_LINE_BYTES - 5)
            + "\r\n\r\n";
    assertEquals(RemoteParentHttp1Framer.MAX_HEADER_BYTES + 1, ascii(overTotal).length);
    assertTerminalUntracked("GET / HTTP/1.1\r\n" + overTotal);

    String exactTrailers = exactHeaderBlock();
    assertChunkStarts("0\r\n" + exactTrailers);
    String overTrailers = overTotal;
    assertChunkTerminal("0\r\n" + overTrailers);
  }

  @Test
  void retainedSourceDataIsBoundedAndBodiesAreNotRetained() {
    String requestLine =
        "GET /"
            + repeat('a', RemoteParentHttp1Framer.MAX_REQUEST_LINE_BYTES - 16)
            + " HTTP/1.1\r\n";
    byte[] almostComplete = ascii(requestLine + exactHeaderBlock());
    RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();

    RemoteParentHttp1Framer.ReceivePlan defer =
        framer.accept(almostComplete, 0, almostComplete.length - 1);
    assertEquals(DEFER, defer.action());
    assertEquals(RemoteParentHttp1Framer.MAX_RETAINED_BYTES - 1, framer.retainedBytes());
    RemoteParentHttp1Framer.ReceivePlan start =
        framer.accept(almostComplete, almostComplete.length - 1, 1);
    assertEquals(START, start.action());
    assertTrue(start.endOfMessage());
    assertEquals(0, framer.retainedBytes());

    framer.reset();
    byte[] headers = ascii("POST /large HTTP/1.1\r\nContent-Length: 1000000\r\n\r\n");
    assertEquals(START, framer.accept(headers, 0, headers.length).action());
    byte[] body = new byte[100_000];
    Arrays.fill(body, (byte) 'G');
    for (int i = 0; i < 10; i++) {
      assertEquals(CONTINUE, framer.accept(body, 0, body.length).action());
      assertEquals(0, framer.retainedBytes());
    }
  }

  @Test
  void deterministicRandomFragmentationProducesOneStartAndOneEnd() {
    byte[][] requests = {
      ascii(
          "POST /fixed HTTP/1.1\r\n"
              + "Host: example.test\r\n"
              + "Content-Length: 19\r\n\r\n"
              + "fragmented-body-123"),
      ascii(
          "PATCH http://example.test/chunked HTTP/1.1\r\n"
              + "Transfer-Encoding: chunked\r\n"
              + "Expect: 100-continue\r\n\r\n"
              + "5\r\nabcde\r\n"
              + "4\r\nfghi\r\n"
              + "0\r\nX-End: yes\r\n\r\n")
    };
    Random random = new Random(0x5eed5eedL);
    for (byte[] request : requests) {
      for (int run = 0; run < 100; run++) {
        RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
        int cursor = 0;
        int starts = 0;
        int ends = 0;
        while (cursor < request.length) {
          int count = Math.min(request.length - cursor, 1 + random.nextInt(17));
          RemoteParentHttp1Framer.ReceivePlan plan = framer.accept(request, cursor, count);
          assertTrue(plan.action() == DEFER || plan.action() == START || plan.action() == CONTINUE);
          if (plan.action() == START) {
            starts++;
            assertTrue(framer.extractionObserved(plan.requestSequence()));
          }
          if (plan.endOfMessage()) {
            ends++;
          }
          cursor += count;
        }
        assertEquals(1, starts, "run " + run);
        assertEquals(1, ends, "run " + run);
      }
    }
  }

  @Test
  void sourceRangesAreValidatedWithoutIntegerOverflow() {
    RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
    byte[] bytes = new byte[8];
    assertThrows(NullPointerException.class, () -> framer.accept(null, 0, 0));
    assertThrows(IndexOutOfBoundsException.class, () -> framer.accept(bytes, -1, 1));
    assertThrows(IndexOutOfBoundsException.class, () -> framer.accept(bytes, 0, -1));
    assertThrows(IndexOutOfBoundsException.class, () -> framer.accept(bytes, 7, 2));
    assertThrows(IndexOutOfBoundsException.class, () -> framer.accept(bytes, 1, Integer.MAX_VALUE));
    assertArrayEquals(new byte[8], bytes);
  }

  private static void assertStarts(String request) {
    byte[] bytes = ascii(request);
    RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
    RemoteParentHttp1Framer.ReceivePlan plan = framer.accept(bytes, 0, bytes.length);
    assertEquals(START, plan.action());
    assertTrue(plan.endOfMessage());
  }

  private static void assertTerminalUntracked(String request) {
    byte[] bytes = ascii(request);
    byte[] valid = ascii("GET /later HTTP/1.1\r\n\r\n");
    RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
    assertEquals(UNTRACKED, framer.accept(bytes, 0, bytes.length).action());
    assertEquals(UNTRACKED, framer.accept(valid, 0, valid.length).action());
  }

  private static void assertChunkStarts(String body) {
    byte[] headers = ascii("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
    byte[] bytes = concatenate(headers, ascii(body));
    RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
    RemoteParentHttp1Framer.ReceivePlan plan = framer.accept(bytes, 0, bytes.length);
    assertEquals(START, plan.action());
    assertTrue(plan.endOfMessage());
  }

  private static void assertChunkTerminal(String body) {
    byte[] headers = ascii("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
    RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
    RemoteParentHttp1Framer.ReceivePlan start = framer.accept(headers, 0, headers.length);
    assertEquals(START, start.action());
    assertTrue(framer.extractionObserved(start.requestSequence()));
    byte[] bytes = ascii(body);
    assertEquals(UNTRACKED, framer.accept(bytes, 0, bytes.length).action());
    assertEquals(UNTRACKED, framer.accept(headers, 0, headers.length).action());
  }

  private static void assertNoop(RemoteParentHttp1Framer framer, byte[] source, int offset) {
    int retained = framer.retainedBytes();
    RemoteParentHttp1Framer.ReceivePlan plan = framer.accept(source, offset, 0);
    assertEquals(NOOP, plan.action());
    assertEquals(0, plan.requestSequence());
    assertEquals(0, plan.length());
    assertFalse(plan.endOfMessage());
    assertArrayEquals(new byte[0], plan.deferredPrefix());
    assertEquals(retained, framer.retainedBytes());
  }

  private static String exactHeaderBlock() {
    String line = "X:" + repeat('a', RemoteParentHttp1Framer.MAX_HEADER_LINE_BYTES - 4) + "\r\n";
    return line
        + line
        + line
        + "Y:"
        + repeat('b', RemoteParentHttp1Framer.MAX_HEADER_LINE_BYTES - 6)
        + "\r\n\r\n";
  }

  private static byte[] ascii(String value) {
    return value.getBytes(US_ASCII);
  }

  private static String repeat(char value, int count) {
    char[] result = new char[count];
    Arrays.fill(result, value);
    return new String(result);
  }

  private static byte[] concatenate(byte[] first, byte[] second) {
    ByteArrayOutputStream result = new ByteArrayOutputStream(first.length + second.length);
    result.write(first, 0, first.length);
    result.write(second, 0, second.length);
    return result.toByteArray();
  }

  private static int indexOf(byte[] haystack, byte[] needle) {
    List<Integer> candidates = new ArrayList<Integer>();
    for (int i = 0; i <= haystack.length - needle.length; i++) {
      candidates.add(i);
    }
    for (int candidate : candidates) {
      boolean match = true;
      for (int j = 0; j < needle.length; j++) {
        if (haystack[candidate + j] != needle[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        return candidate;
      }
    }
    return -1;
  }
}
