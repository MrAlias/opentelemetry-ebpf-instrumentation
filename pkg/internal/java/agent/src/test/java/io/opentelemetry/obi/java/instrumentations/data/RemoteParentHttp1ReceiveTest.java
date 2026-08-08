/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.bridge.RemoteParentStatus;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.ReceiveContext;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntConsumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class RemoteParentHttp1ReceiveTest {
  private final Connection connection = connection();

  @AfterEach
  void cleanupThreadState() {
    ThreadInfo.takeRemoteParentSocketContext();
    ThreadInfo.takeRemoteParentReceiveContext();
    ThreadInfo.clearRemoteParentLookupSource();
    ThreadInfo.setRemoteParentEnabled(false);
  }

  @Test
  void splitLargeHeadersProduceOneStartAndBodyContinuationsKeepItsSequence() {
    byte[] header = headerOfSize(18_424);
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);

    int cursor = 0;
    for (int callback = 0; callback < 9; callback++) {
      int count = Math.min(2048, header.length - cursor);
      assertEquals(callback == 8 ? 1 : 0, receive.emit(connection, header, cursor, count));
      cursor += count;
      assertEquals(callback == 8 ? 1 : 0, emitter.events.size());
    }
    assertEquals(header.length, cursor);
    Event start = emitter.events.get(0);
    assertEquals(OperationType.HTTP1_RECEIVE_START, start.operation);
    assertEquals(1L, start.context.requestSequence());
    assertArrayEquals(header, start.payload);

    byte[] body = ascii("body");
    assertEquals(0, receive.emit(connection, body, 0, body.length));
    Event continuation = emitter.events.get(1);
    assertEquals(OperationType.HTTP1_RECEIVE_CONTINUE, continuation.operation);
    assertSame(start.context, continuation.context);
    assertTrue(continuation.primaryAcknowledged);
    assertArrayEquals(body, continuation.payload);
  }

  @Test
  void extractionAcknowledgementSeparatesSequentialKeepaliveRequests() {
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] first = ascii("GET /one HTTP/1.1\r\nHost: example\r\n\r\n");
    byte[] second = ascii("GET /two HTTP/1.1\r\nHost: example\r\n\r\n");

    receive.emit(connection, first, 0, first.length);
    ReceiveContext firstContext = emitter.events.get(0).context;
    assertSame(firstContext, ThreadInfo.takeRemoteParentReceiveContext());
    ThreadInfo.finishRemoteParentExtraction(firstContext);
    receive.emit(connection, second, 0, second.length);

    assertEquals(2, emitter.events.size());
    assertEquals(OperationType.HTTP1_RECEIVE_START, emitter.events.get(1).operation);
    assertEquals(2L, emitter.events.get(1).context.requestSequence());
    assertEquals(firstContext.lifecycle().id(), emitter.events.get(1).context.lifecycle().id());
  }

  @Test
  void postExtractionContinuationKeepsJavaLookupBlockedButEmitsExactNativeIdentity() {
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] header = ascii("POST /one HTTP/1.1\r\nHost: example\r\nContent-Length: 4\r\n\r\n");
    byte[] body = ascii("body");

    receive.emit(connection, header, 0, header.length);
    ReceiveContext context = ThreadInfo.takeRemoteParentReceiveContext();
    assertSame(emitter.events.get(0).context, context);
    ThreadInfo.finishRemoteParentExtraction(context);
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());

    assertEquals(0, receive.emit(connection, body, 0, body.length));

    assertEquals(2, emitter.events.size());
    Event continuation = emitter.events.get(1);
    assertEquals(OperationType.HTTP1_RECEIVE_CONTINUE, continuation.operation);
    assertSame(context, continuation.context);
    assertEquals(context.lifecycle().id(), continuation.context.lifecycle().id());
    assertEquals(context.requestSequence(), continuation.context.requestSequence());
    assertFalse(continuation.primaryAcknowledged);
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
    assertNull(ThreadInfo.takeRemoteParentReceiveContext());
  }

  @Test
  void postExtractionContinuationCannotAuthorizeATaskHandoff() {
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] header = ascii("POST /task HTTP/1.1\r\nContent-Length: 1\r\n\r\n");

    receive.emit(connection, header, 0, header.length);
    ReceiveContext context = ThreadInfo.takeRemoteParentReceiveContext();
    ThreadInfo.finishRemoteParentExtraction(context);
    receive.emit(connection, ascii("x"), 0, 1);
    ThreadInfo.setRemoteParentEnabled(true);

    TaskContext handoff = ThreadInfo.captureTaskContext(101L, context.lifecycle());

    assertEquals(0L, handoff.getHandoffToken());
    assertNull(handoff.getRemoteParentReceiveContext());
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
    assertEquals(2, emitter.events.size());
    assertEquals(OperationType.HTTP1_RECEIVE_CONTINUE, emitter.events.get(1).operation);
    assertSame(context, emitter.events.get(1).context);
  }

  @Test
  void nextRequestBeforeExtractionFailsClosedAndResetsOnlyOnce() {
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] first = ascii("GET /one HTTP/1.1\r\nHost: example\r\n\r\n");
    byte[] second = ascii("GET /two HTTP/1.1\r\nHost: example\r\n\r\n");

    receive.emit(connection, first, 0, first.length);
    ReceiveContext context = emitter.events.get(0).context;
    receive.emit(connection, second, 0, second.length);
    receive.emit(connection, second, 0, second.length);

    assertEquals(2, emitter.events.size());
    assertEquals(OperationType.HTTP1_RECEIVE_RESET, emitter.events.get(1).operation);
    assertSame(context, emitter.events.get(1).context);
    assertFalse(context.extractionObserved());
  }

  @Test
  void coalescedRequestsNeverStartRemoteParentOwnership() {
    RecordingEmitter emitter = new RecordingEmitter();
    AtomicInteger ambiguities = new AtomicInteger();
    RemoteParentHttp1Receive receive =
        receive(
            emitter,
            status -> {
              assertEquals(RemoteParentStatus.AMBIGUOUS, status);
              ambiguities.incrementAndGet();
            });
    byte[] requests =
        ascii(
            "GET /one HTTP/1.1\r\nHost: example\r\n\r\n"
                + "GET /two HTTP/1.1\r\nHost: example\r\n\r\n");

    assertEquals(0, receive.emit(connection, requests, 0, requests.length));
    assertEquals(0, receive.emit(connection, requests, 0, requests.length));
    assertTrue(emitter.events.isEmpty());
    assertEquals(1, ambiguities.get());
  }

  @Test
  void deferredEpochTransitionDrainsOnceThenStaysTelemetryOnlyThroughClose() {
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] deferred = ascii("GET /old HTTP/1.1\r\nHost: exam");

    assertEquals(0, receive.emit(connection, deferred, 0, deferred.length));
    assertTrue(emitter.events.isEmpty());
    ThreadInfo.advanceRemoteParentBridgeEpoch();

    assertEquals(0, receive.beforeLegacyReceive(connection));
    assertEquals(0, receive.beforeLegacyReceive(connection));
    byte[] afterReenable = ascii("GET /new HTTP/1.1\r\nHost: example\r\n\r\n");
    assertEquals(0, receive.emit(connection, afterReenable, 0, afterReenable.length));
    assertEquals(0, receive.close(connection));
    assertEquals(0, receive.close(connection));

    assertEquals(2, emitter.events.size());
    assertEquals(OperationType.TELEMETRY_RECEIVE, emitter.events.get(0).operation);
    assertArrayEquals(deferred, emitter.events.get(0).payload);
    assertEquals(OperationType.TELEMETRY_RECEIVE, emitter.events.get(1).operation);
    assertArrayEquals(afterReenable, emitter.events.get(1).payload);
  }

  @Test
  void activeBodyEpochTransitionResetsOnceWithoutReplayThenUsesTelemetry() {
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] header = ascii("POST /old HTTP/1.1\r\nContent-Length: 4\r\n\r\n");
    assertEquals(1, receive.emit(connection, header, 0, header.length));
    ReceiveContext context = emitter.events.get(0).context;

    ThreadInfo.advanceRemoteParentBridgeEpoch();
    assertEquals(0, receive.beforeLegacyReceive(connection));
    assertEquals(0, receive.beforeLegacyReceive(connection));
    byte[] later = ascii("body");
    assertEquals(0, receive.emit(connection, later, 0, later.length));
    assertEquals(0, receive.close(connection));

    assertEquals(3, emitter.events.size());
    assertEquals(OperationType.HTTP1_RECEIVE_START, emitter.events.get(0).operation);
    assertEquals(OperationType.HTTP1_RECEIVE_RESET, emitter.events.get(1).operation);
    assertSame(context, emitter.events.get(1).context);
    assertTrue(emitter.events.get(1).primaryAcknowledged);
    assertEquals(OperationType.TELEMETRY_RECEIVE, emitter.events.get(2).operation);
    assertArrayEquals(later, emitter.events.get(2).payload);
  }

  @Test
  void acknowledgedAndUnacknowledgedBetweenMessageTransitionsResetExactlyOnce() {
    assertBetweenMessageTransition(1, true);
    assertBetweenMessageTransition(0, false);
  }

  @Test
  void epochTransitionDuringStartEmissionResetsBeforePublishingJavaAuthority() {
    RecordingEmitter emitter = new RecordingEmitter();
    emitter.afterFirstStart = ThreadInfo::advanceRemoteParentBridgeEpoch;
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] request = ascii("GET /race HTTP/1.1\r\nHost: example\r\n\r\n");

    assertEquals(1, receive.emit(connection, request, 0, request.length));
    assertNull(ThreadInfo.takeRemoteParentReceiveContext());
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
    byte[] later = ascii("GET /later HTTP/1.1\r\nHost: example\r\n\r\n");
    assertEquals(0, receive.emit(connection, later, 0, later.length));

    assertEquals(3, emitter.events.size());
    assertEquals(OperationType.HTTP1_RECEIVE_START, emitter.events.get(0).operation);
    assertEquals(OperationType.HTTP1_RECEIVE_RESET, emitter.events.get(1).operation);
    assertEquals(OperationType.TELEMETRY_RECEIVE, emitter.events.get(2).operation);
    assertArrayEquals(later, emitter.events.get(2).payload);
  }

  @Test
  void unsupportedStreamsFlushTheBoundedPreludeThenStreamTelemetryOnly() {
    assertUnsupportedTelemetry(ascii("PRI * HT"), ascii("TP/2.0\r\n\r\nSM\r\n\r\n"));
    assertUnsupportedTelemetry(ascii("BINARY "), ascii("RPC\r\nmore"));
    assertUnsupportedTelemetry(ascii("GET / HTTP/1.1\r\nBad"), ascii(" Header: value\r\n\r\n"));
  }

  @Test
  void unsupportedTerminalFallbackRecordsOneReasonAcrossStickyTelemetryAndEpochRetirement() {
    RecordingEmitter emitter = new RecordingEmitter();
    List<Integer> failures = new ArrayList<>();
    RemoteParentHttp1Receive receive = receive(emitter, failures::add);
    byte[] first = ascii("PRI * HT");
    byte[] second = ascii("TP/2.0\r\n\r\nSM\r\n\r\n");

    receive.emit(connection, first, 0, first.length);
    receive.emit(connection, second, 0, second.length);
    receive.emit(connection, ascii("sticky"), 0, 6);
    ThreadInfo.advanceRemoteParentBridgeEpoch();
    receive.emit(connection, ascii("after-epoch"), 0, 11);

    assertEquals(java.util.Collections.singletonList(RemoteParentStatus.UNSUPPORTED), failures);
    assertEquals(3, emitter.events.size());
    for (Event event : emitter.events) {
      assertEquals(OperationType.TELEMETRY_RECEIVE, event.operation);
    }
  }

  @Test
  void providerEpochMismatchRecordsOneStaleReasonAcrossRepeatedRetirementCalls() {
    RecordingEmitter emitter = new RecordingEmitter();
    List<Integer> failures = new ArrayList<>();
    RemoteParentHttp1Receive receive = receive(emitter, failures::add);
    byte[] deferred = ascii("GET /old HTTP/1.1\r\nHost: exam");

    receive.emit(connection, deferred, 0, deferred.length);
    ThreadInfo.advanceRemoteParentBridgeEpoch();
    receive.beforeLegacyReceive(connection);
    receive.beforeLegacyReceive(connection);
    receive.emit(connection, ascii("later"), 0, 5);
    receive.close(connection);

    assertEquals(java.util.Collections.singletonList(RemoteParentStatus.STALE), failures);
  }

  @Test
  void ownerNeverUsedWhileEnabledDoesNotRecordAStaleRetirement() {
    ThreadInfo.setRemoteParentEnabled(false);
    RecordingEmitter emitter = new RecordingEmitter();
    List<Integer> failures = new ArrayList<>();
    RemoteParentHttp1Receive receive =
        new RemoteParentHttp1Receive(
            new Lifecycle(), ThreadInfo.remoteParentBridgeEpoch(), emitter, failures::add);

    ThreadInfo.advanceRemoteParentBridgeEpoch();
    receive.emit(connection, ascii("disabled-baseline"), 0, 17);
    receive.beforeLegacyReceive(connection);
    receive.close(connection);

    assertTrue(failures.isEmpty());
    assertEquals(1, emitter.events.size());
    assertEquals(OperationType.TELEMETRY_RECEIVE, emitter.events.get(0).operation);
  }

  @Test
  void malformedActiveRequestResetsBeforeTelemetryFallback() {
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] header = ascii("POST / HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n");
    receive.emit(connection, header, 0, header.length);
    ReceiveContext context = emitter.events.get(0).context;

    byte[] malformedChunk = ascii("z\r\n");
    receive.emit(connection, malformedChunk, 0, malformedChunk.length);

    assertEquals(3, emitter.events.size());
    assertEquals(OperationType.HTTP1_RECEIVE_RESET, emitter.events.get(1).operation);
    assertEquals(OperationType.TELEMETRY_RECEIVE, emitter.events.get(2).operation);
    assertArrayEquals(malformedChunk, emitter.events.get(2).payload);
    assertFalse(context.extractionObserved());
  }

  @Test
  void largeSplitHeaderCompletingBeforeMalformedChunkFallsBackExactlyOnce() {
    byte[] deferred =
        ascii(
            "POST /large HTTP/1.1\r\n"
                + "Transfer-Encoding: chunked\r\n"
                + "X-A: "
                + repeat('a', 7000)
                + "\r\nX-B: "
                + repeat('b', 2000)
                + "\r\n");
    assertTrue(deferred.length > 8 * 1024);
    byte[] completionAndMalformedChunk = ascii("\r\nz\r\n");
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);

    assertEquals(0, receive.emit(connection, deferred, 0, deferred.length));
    assertTrue(emitter.events.isEmpty());
    assertEquals(
        0,
        receive.emit(
            connection, completionAndMalformedChunk, 0, completionAndMalformedChunk.length));

    assertEquals(1, emitter.events.size());
    Event fallback = emitter.events.get(0);
    assertEquals(OperationType.TELEMETRY_RECEIVE, fallback.operation);
    byte[] expected = new byte[deferred.length + completionAndMalformedChunk.length];
    System.arraycopy(deferred, 0, expected, 0, deferred.length);
    System.arraycopy(
        completionAndMalformedChunk,
        0,
        expected,
        deferred.length,
        completionAndMalformedChunk.length);
    assertArrayEquals(expected, fallback.payload);
  }

  @Test
  void oversizedEmissionIsFragmentedWithoutChangingSequence() throws Exception {
    byte[] header = ascii("POST /large HTTP/1.1\r\nHost: example\r\nContent-Length: 70000\r\n\r\n");
    byte[] request = new byte[header.length + 70_000];
    System.arraycopy(header, 0, request, 0, header.length);
    for (int i = header.length; i < request.length; i++) {
      request[i] = 'x';
    }
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);

    receive.emit(connection, request, 0, request.length);

    assertEquals(2, emitter.events.size());
    assertEquals(OperationType.HTTP1_RECEIVE_START, emitter.events.get(0).operation);
    assertEquals(IOCTLPacket.http1MaxPayloadSize, emitter.events.get(0).payload.length);
    assertEquals(OperationType.HTTP1_RECEIVE_CONTINUE, emitter.events.get(1).operation);
    assertSame(emitter.events.get(0).context, emitter.events.get(1).context);
    ByteArrayOutputStream emitted = new ByteArrayOutputStream();
    emitted.write(emitter.events.get(0).payload);
    emitted.write(emitter.events.get(1).payload);
    assertArrayEquals(request, emitted.toByteArray());
  }

  @Test
  void closeResetsOnceAndMakesTheExactContextUnusable() {
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] request = ascii("GET /close HTTP/1.1\r\nHost: example\r\n\r\n");
    receive.emit(connection, request, 0, request.length);
    ReceiveContext context = emitter.events.get(0).context;

    assertEquals(0, receive.close(connection));
    assertEquals(0, receive.close(connection));

    assertEquals(2, emitter.events.size());
    assertEquals(OperationType.HTTP1_RECEIVE_RESET, emitter.events.get(1).operation);
    assertFalse(context.extractionObserved());
    assertEquals(-1, receive.emit(connection, request, 0, request.length));
  }

  @Test
  void closeDrainsIncompleteDeferredPlaintextToTelemetryExactlyOnce() {
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] first = ascii("GET /incomplete HTTP/1.1\r\nHost: exam");
    byte[] second = ascii("ple");

    receive.emit(connection, first, 0, first.length);
    receive.emit(connection, second, 0, second.length);
    assertTrue(emitter.events.isEmpty());
    assertEquals(0, receive.close(connection));
    assertEquals(0, receive.close(connection));

    assertEquals(1, emitter.events.size());
    Event drain = emitter.events.get(0);
    assertEquals(OperationType.TELEMETRY_RECEIVE, drain.operation);
    assertNull(drain.context);
    byte[] expected = new byte[first.length + second.length];
    System.arraycopy(first, 0, expected, 0, first.length);
    System.arraycopy(second, 0, expected, first.length, second.length);
    assertArrayEquals(expected, drain.payload);
    assertEquals(ThreadInfo.REMOTE_PARENT_LOOKUP_BLOCKED, ThreadInfo.remoteParentLookupSource());
  }

  private void assertUnsupportedTelemetry(byte[] first, byte[] second) {
    RecordingEmitter emitter = new RecordingEmitter();
    RemoteParentHttp1Receive receive = receive(emitter);

    assertEquals(0, receive.emit(connection, first, 0, first.length));
    assertTrue(emitter.events.isEmpty());
    assertEquals(0, receive.emit(connection, second, 0, second.length));
    assertEquals(1, emitter.events.size());
    Event fallback = emitter.events.get(0);
    assertEquals(OperationType.TELEMETRY_RECEIVE, fallback.operation);
    byte[] expected = new byte[first.length + second.length];
    System.arraycopy(first, 0, expected, 0, first.length);
    System.arraycopy(second, 0, expected, first.length, second.length);
    assertArrayEquals(expected, fallback.payload);

    byte[] later = ascii("later");
    receive.emit(connection, later, 0, later.length);
    assertEquals(OperationType.TELEMETRY_RECEIVE, emitter.events.get(1).operation);
    assertArrayEquals(later, emitter.events.get(1).payload);
  }

  private void assertBetweenMessageTransition(int startStatus, boolean acknowledged) {
    RecordingEmitter emitter = new RecordingEmitter();
    emitter.startStatus = startStatus;
    RemoteParentHttp1Receive receive = receive(emitter);
    byte[] request = ascii("GET /between HTTP/1.1\r\nHost: example\r\n\r\n");
    assertEquals(startStatus, receive.emit(connection, request, 0, request.length));

    ThreadInfo.advanceRemoteParentBridgeEpoch();
    assertEquals(0, receive.beforeLegacyReceive(connection));
    assertEquals(0, receive.beforeLegacyReceive(connection));
    assertEquals(0, receive.close(connection));

    assertEquals(2, emitter.events.size());
    assertEquals(OperationType.HTTP1_RECEIVE_RESET, emitter.events.get(1).operation);
    assertEquals(acknowledged, emitter.events.get(1).primaryAcknowledged);
  }

  private static RemoteParentHttp1Receive receive(RecordingEmitter emitter) {
    ThreadInfo.setRemoteParentEnabled(true);
    return new RemoteParentHttp1Receive(new Lifecycle(), emitter);
  }

  private static RemoteParentHttp1Receive receive(
      RecordingEmitter emitter, IntConsumer failureRecorder) {
    ThreadInfo.setRemoteParentEnabled(true);
    return new RemoteParentHttp1Receive(
        new Lifecycle(), ThreadInfo.remoteParentBridgeEpoch(), emitter, failureRecorder);
  }

  private static byte[] headerOfSize(int target) {
    StringBuilder header =
        new StringBuilder("POST /split HTTP/1.1\r\nHost: example\r\nContent-Length: 4\r\n");
    while (target - header.length() - 2 > 0) {
      int lineLength = Math.min(7000, target - header.length() - 2);
      if (lineLength < 4) {
        throw new IllegalArgumentException("unrepresentable header size");
      }
      header.append("X:");
      for (int i = 0; i < lineLength - 4; i++) {
        header.append('a');
      }
      header.append("\r\n");
    }
    header.append("\r\n");
    byte[] result = ascii(header.toString());
    assertEquals(target, result.length);
    return result;
  }

  private static Connection connection() {
    return new Connection(
        InetAddress.getLoopbackAddress(), 8443, InetAddress.getLoopbackAddress(), 42_000, 73);
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static String repeat(char value, int count) {
    char[] result = new char[count];
    java.util.Arrays.fill(result, value);
    return new String(result);
  }

  private static final class RecordingEmitter implements RemoteParentHttp1Receive.Emitter {
    private final List<Event> events = new ArrayList<>();
    private int startStatus = 1;
    private Runnable afterFirstStart;

    @Override
    public int emit(
        Object transport,
        Lifecycle lifecycle,
        OperationType operation,
        ReceiveContext context,
        byte[] first,
        int firstOffset,
        int firstLength,
        byte[] second,
        int secondOffset,
        int secondLength,
        boolean primaryAcknowledged) {
      byte[] payload = new byte[firstLength + secondLength];
      System.arraycopy(first, firstOffset, payload, 0, firstLength);
      System.arraycopy(second, secondOffset, payload, firstLength, secondLength);
      events.add(new Event(operation, context, payload, primaryAcknowledged));
      if (operation == OperationType.HTTP1_RECEIVE_START && afterFirstStart != null) {
        Runnable callback = afterFirstStart;
        afterFirstStart = null;
        callback.run();
      }
      return operation == OperationType.HTTP1_RECEIVE_START ? startStatus : 0;
    }
  }

  private static final class Event {
    private final OperationType operation;
    private final ReceiveContext context;
    private final byte[] payload;
    private final boolean primaryAcknowledged;

    private Event(
        OperationType operation,
        ReceiveContext context,
        byte[] payload,
        boolean primaryAcknowledged) {
      this.operation = operation;
      this.context = context;
      this.payload = payload;
      this.primaryAcknowledged = primaryAcknowledged;
    }
  }
}
