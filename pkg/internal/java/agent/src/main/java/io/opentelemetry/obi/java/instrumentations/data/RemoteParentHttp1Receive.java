/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.bridge.RemoteParentBridge;
import io.opentelemetry.obi.java.bridge.RemoteParentStatus;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentHttp1Framer.Action;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentHttp1Framer.ReceivePlan;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.Lifecycle;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext.ReceiveContext;
import java.net.Socket;
import java.util.function.IntConsumer;

/** Serialized HTTP/1 receive framing and native emission for one physical connection lifecycle. */
final class RemoteParentHttp1Receive implements RemoteParentSocketContext.ExtractionObserver {
  private static final byte[] EMPTY = new byte[0];

  private final Lifecycle lifecycle;
  private final long bridgeEpoch;
  private final RemoteParentHttp1Framer framer = new RemoteParentHttp1Framer();
  private final Emitter emitter;
  private final IntConsumer failureRecorder;

  private ReceiveContext activeContext;
  private long nativeStartedSequence;
  private long primaryAcknowledgedSequence;
  private long extractionObservedSequence;
  private long resetSequence;
  private boolean bridgeCapabilityIssued;
  private boolean bridgeRetired;
  private boolean terminalFailureRecorded;
  private boolean closed;

  RemoteParentHttp1Receive(Lifecycle lifecycle) {
    this(lifecycle, ThreadInfo.remoteParentBridgeEpoch());
  }

  RemoteParentHttp1Receive(Lifecycle lifecycle, long bridgeEpoch) {
    this(
        lifecycle,
        bridgeEpoch,
        RemoteParentHttp1Receive::emitNative,
        RemoteParentHttp1Receive::recordReceiveFailure);
  }

  RemoteParentHttp1Receive(Lifecycle lifecycle, Emitter emitter) {
    this(
        lifecycle,
        ThreadInfo.remoteParentBridgeEpoch(),
        emitter,
        RemoteParentHttp1Receive::recordReceiveFailure);
  }

  RemoteParentHttp1Receive(
      Lifecycle lifecycle, long bridgeEpoch, Emitter emitter, IntConsumer failureRecorder) {
    if (lifecycle == null || bridgeEpoch == 0L || emitter == null || failureRecorder == null) {
      throw new NullPointerException();
    }
    this.lifecycle = lifecycle;
    this.bridgeEpoch = bridgeEpoch;
    this.emitter = emitter;
    this.failureRecorder = failureRecorder;
    bridgeCapabilityIssued = ThreadInfo.isCurrentRemoteParentBridgeCapability(bridgeEpoch);
  }

  synchronized int emit(Object transport, byte[] source, int offset, int length) {
    if (closed || !supportedTransport(transport) || !lifecycle.active()) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      return -1;
    }
    if (source == null) {
      throw new NullPointerException("source");
    }
    if (offset < 0 || length < 0 || offset > source.length - length) {
      throw new IndexOutOfBoundsException("invalid source range");
    }
    if (bridgeRetired || !bridgeEpochCurrent()) {
      int transitionStatus = retireBridgeEpoch(transport);
      int telemetryStatus = emitTelemetryFragments(transport, EMPTY, source, offset, length);
      return mergeStatus(transitionStatus, telemetryStatus);
    }

    // An owner created while disabled becomes provider-issued only after an enabled callback
    // actually selects its bound epoch. This avoids stale noise for disabled baseline owners.
    bridgeCapabilityIssued = true;

    ReceivePlan plan = framer.accept(source, offset, length);
    Action action = plan.action();
    if (!bridgeEpochCurrent()) {
      if (action == Action.AMBIGUOUS) {
        recordTerminalFailureOnce(RemoteParentStatus.AMBIGUOUS);
        return retireBridgeEpoch(transport);
      }
      if (action == Action.DEFER) {
        // The framer retained this callback together with any older prelude; retirement drains the
        // exact non-overlapping prefix once.
        return retireBridgeEpoch(transport);
      }
      byte[] prefix =
          action == Action.START
              ? plan.deferredPrefix()
              : action == Action.UNTRACKED ? plan.telemetryPrefix() : EMPTY;
      int transitionStatus = retireBridgeEpoch(transport);
      int telemetryStatus = emitTelemetryFragments(transport, prefix, source, offset, length);
      return mergeStatus(transitionStatus, telemetryStatus);
    }
    if (action == Action.NOOP) {
      return 0;
    }
    if (action == Action.DEFER) {
      ThreadInfo.beginRemoteParentReceiveAttempt();
      return 0;
    }
    if (action == Action.AMBIGUOUS) {
      recordTerminalFailureOnce(RemoteParentStatus.AMBIGUOUS);
      int status = resetTerminalSequence(transport, plan.requestSequence());
      releaseActiveContext();
      return status;
    }
    if (action == Action.UNTRACKED) {
      recordTerminalFailureOnce(RemoteParentStatus.UNSUPPORTED);
      int resetStatus = resetTerminalSequence(transport, plan.requestSequence());
      releaseActiveContext();
      if (resetStatus < 0) {
        return resetStatus;
      }
      return emitTelemetryFragments(
          transport, plan.telemetryPrefix(), source, plan.offset(), plan.length());
    }

    ReceiveContext context;
    OperationType operation;
    if (action == Action.START) {
      context = new ReceiveContext(lifecycle, plan.requestSequence(), bridgeEpoch, this);
      operation = OperationType.HTTP1_RECEIVE_START;
      primaryAcknowledgedSequence = 0L;
      extractionObservedSequence = 0L;
      activeContext = context;
    } else {
      context = activeContext;
      operation = OperationType.HTTP1_RECEIVE_CONTINUE;
      if (context == null || context.requestSequence() != plan.requestSequence()) {
        BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
        return -1;
      }
    }

    byte[] prefix = action == Action.START ? plan.deferredPrefix() : EMPTY;
    int result = emitFragments(transport, operation, context, prefix, source, plan);
    if (result < 0) {
      releaseActiveContext();
      return result;
    }

    if (bridgeRetired || !bridgeEpochCurrent()) {
      return mergeStatus(result, retireBridgeEpoch(transport));
    }

    if (extractionObservedSequence == context.requestSequence()) {
      // CONTINUE still advances the exact native framing cursor, but an extractor has already
      // consumed this request's one-shot Java capability. Do not reinstall it (or its descriptor)
      // on a later body receive and do not let a task alias repeat the extraction attempt.
      ThreadInfo.beginRemoteParentReceiveAttempt();
      ThreadInfo.clearRemoteParentSocketFileDescriptor();
      return result;
    }
    if (!ThreadInfo.markRemoteParentDirectReceiveContext(context)) {
      if (!bridgeEpochCurrent()) {
        return mergeStatus(result, retireBridgeEpoch(transport));
      }
      BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
      releaseActiveContext();
      return -1;
    }
    if (!bridgeEpochCurrent()) {
      return mergeStatus(result, retireBridgeEpoch(transport));
    }
    return result;
  }

  @Override
  public synchronized boolean extractionObserved(ReceiveContext context) {
    boolean observed =
        context != null
            && context == activeContext
            && context.bridgeEpoch() == bridgeEpoch
            && bridgeEpochCurrent()
            && lifecycle.active()
            && framer.extractionObserved(context.requestSequence());
    if (observed) {
      extractionObservedSequence = context.requestSequence();
    }
    return observed;
  }

  /** Best-effort native reset followed by unconditional local release for a terminal owner. */
  synchronized int close(Object transport) {
    if (closed) {
      return 0;
    }
    if (bridgeRetired || !bridgeEpochCurrent()) {
      int status = retireBridgeEpoch(transport);
      closed = true;
      ThreadInfo.beginRemoteParentReceiveAttempt();
      ThreadInfo.revokeRemoteParentLookup(lifecycle);
      return status;
    }
    closed = true;
    ThreadInfo.beginRemoteParentReceiveAttempt();
    int status = 0;
    byte[] deferred = framer.drainDeferredForTelemetry();
    ReceiveContext context = activeContext;
    if (context != null && lifecycle.active()) {
      try {
        status = resetTerminalSequence(transport, context.requestSequence());
      } catch (Throwable failure) {
        status = -1;
      }
    }
    releaseActiveContext();
    if (status >= 0 && deferred.length > 0 && lifecycle.active()) {
      try {
        status = emitTelemetryFragments(transport, deferred, EMPTY, 0, 0);
      } catch (Throwable failure) {
        status = -1;
      }
    }
    ThreadInfo.revokeRemoteParentLookup(lifecycle);
    return status;
  }

  /** Retires authority before one disabled-mode fragment takes the exact legacy RECEIVE path. */
  synchronized int beforeLegacyReceive(Object transport) {
    if (closed || !supportedTransport(transport) || !lifecycle.active()) {
      return -1;
    }
    return retireBridgeEpoch(transport);
  }

  private int emitFragments(
      Object transport,
      OperationType firstOperation,
      ReceiveContext context,
      byte[] prefix,
      byte[] source,
      ReceivePlan plan) {
    int prefixOffset = 0;
    int sourceOffset = plan.offset();
    int sourceRemaining = plan.length();
    OperationType operation = firstOperation;
    int result = 0;

    while (prefixOffset < prefix.length || sourceRemaining > 0) {
      if (!bridgeEpochCurrent()) {
        int transitionStatus = retireBridgeEpoch(transport);
        int telemetryStatus =
            emitTelemetryFragments(
                transport,
                slice(prefix, prefixOffset, prefix.length - prefixOffset),
                source,
                sourceOffset,
                sourceRemaining);
        return mergeStatus(result, transitionStatus, telemetryStatus);
      }
      int prefixLength = Math.min(prefix.length - prefixOffset, IOCTLPacket.http1MaxPayloadSize);
      int sourceLength = Math.min(sourceRemaining, IOCTLPacket.http1MaxPayloadSize - prefixLength);
      boolean primaryAcknowledged =
          primaryAcknowledgedSequence == context.requestSequence()
              && extractionObservedSequence != context.requestSequence();
      int status =
          emitter.emit(
              transport,
              lifecycle,
              operation,
              context,
              prefix,
              prefixOffset,
              prefixLength,
              source,
              sourceOffset,
              sourceLength,
              primaryAcknowledged);
      if (status < 0) {
        BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
        return status;
      }
      if (operation == OperationType.HTTP1_RECEIVE_START) {
        nativeStartedSequence = context.requestSequence();
      }
      if (operation == OperationType.HTTP1_RECEIVE_START && status == 1) {
        primaryAcknowledgedSequence = context.requestSequence();
      }
      result = Math.max(result, status);
      prefixOffset += prefixLength;
      sourceOffset += sourceLength;
      sourceRemaining -= sourceLength;
      operation = OperationType.HTTP1_RECEIVE_CONTINUE;
      if (!bridgeEpochCurrent()) {
        int transitionStatus = retireBridgeEpoch(transport);
        int telemetryStatus =
            emitTelemetryFragments(
                transport,
                slice(prefix, prefixOffset, prefix.length - prefixOffset),
                source,
                sourceOffset,
                sourceRemaining);
        return mergeStatus(result, transitionStatus, telemetryStatus);
      }
    }
    return result;
  }

  private int emitTelemetryFragments(
      Object transport, byte[] prefix, byte[] source, int sourceOffset, int sourceLength) {
    int prefixOffset = 0;
    int sourceRemaining = sourceLength;
    int result = 0;
    while (prefixOffset < prefix.length || sourceRemaining > 0) {
      int prefixLength = Math.min(prefix.length - prefixOffset, IOCTLPacket.http1MaxPayloadSize);
      int fragmentLength =
          Math.min(sourceRemaining, IOCTLPacket.http1MaxPayloadSize - prefixLength);
      int status =
          emitter.emit(
              transport,
              lifecycle,
              OperationType.TELEMETRY_RECEIVE,
              null,
              prefix,
              prefixOffset,
              prefixLength,
              source,
              sourceOffset,
              fragmentLength,
              false);
      if (status < 0) {
        BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
        return status;
      }
      result = Math.max(result, status);
      prefixOffset += prefixLength;
      sourceOffset += fragmentLength;
      sourceRemaining -= fragmentLength;
    }
    return result;
  }

  /**
   * Permanently converts this physical owner to telemetry-only after a provider epoch boundary.
   *
   * <p>Only bytes retained before START are drained. Bytes already emitted under the old epoch are
   * never replayed. A native cursor that actually observed START is reset once, regardless of
   * acknowledgement, and every Java capability is released before this method returns.
   */
  private int retireBridgeEpoch(Object transport) {
    if (bridgeRetired) {
      return 0;
    }
    if (bridgeCapabilityIssued && !ThreadInfo.isCurrentRemoteParentBridgeEpoch(bridgeEpoch)) {
      recordTerminalFailureOnce(RemoteParentStatus.STALE);
    }
    bridgeRetired = true;
    ThreadInfo.beginRemoteParentReceiveAttempt();
    byte[] deferred = framer.drainDeferredForTelemetry();
    int resetStatus = 0;
    ReceiveContext context = activeContext;
    if (context != null
        && nativeStartedSequence == context.requestSequence()
        && lifecycle.active()) {
      try {
        resetStatus = resetTerminalSequence(transport, context.requestSequence(), false);
      } catch (Throwable failure) {
        resetStatus = -1;
      }
    }
    releaseActiveContext();
    ThreadInfo.revokeRemoteParentLookup(lifecycle);

    int telemetryStatus = 0;
    if (deferred.length > 0 && lifecycle.active()) {
      try {
        telemetryStatus = emitTelemetryFragments(transport, deferred, EMPTY, 0, 0);
      } catch (Throwable failure) {
        telemetryStatus = -1;
      }
    }
    return mergeStatus(resetStatus, telemetryStatus);
  }

  private boolean bridgeEpochCurrent() {
    return !bridgeRetired && ThreadInfo.isCurrentRemoteParentBridgeCapability(bridgeEpoch);
  }

  private void recordTerminalFailureOnce(int status) {
    if (terminalFailureRecorded) {
      return;
    }
    terminalFailureRecorded = true;
    try {
      failureRecorder.accept(status);
    } catch (Throwable ignored) {
    }
  }

  private static void recordReceiveFailure(int status) {
    RemoteParentBridge.recordReceiveFailure(status);
  }

  private int resetTerminalSequence(Object transport, long requestSequence) {
    return resetTerminalSequence(transport, requestSequence, true);
  }

  private int resetTerminalSequence(
      Object transport, long requestSequence, boolean invalidateOnFailure) {
    ThreadInfo.beginRemoteParentReceiveAttempt();
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
    if (requestSequence <= 0L || requestSequence == resetSequence) {
      return 0;
    }

    resetSequence = requestSequence;
    ReceiveContext context = activeContext;
    if (context == null || context.requestSequence() != requestSequence) {
      if (invalidateOnFailure) {
        BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
      }
      return -1;
    }
    if (nativeStartedSequence != requestSequence) {
      return 0;
    }
    int status =
        emitter.emit(
            transport,
            lifecycle,
            OperationType.HTTP1_RECEIVE_RESET,
            context,
            EMPTY,
            0,
            0,
            EMPTY,
            0,
            0,
            primaryAcknowledgedSequence == requestSequence);
    if (status < 0 && invalidateOnFailure) {
      BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
    }
    return status;
  }

  private void releaseActiveContext() {
    activeContext = null;
    nativeStartedSequence = 0L;
    primaryAcknowledgedSequence = 0L;
  }

  private static byte[] slice(byte[] source, int offset, int length) {
    if (length == 0) {
      return EMPTY;
    }
    byte[] result = new byte[length];
    System.arraycopy(source, offset, result, 0, length);
    return result;
  }

  private static int mergeStatus(int... statuses) {
    int result = 0;
    for (int status : statuses) {
      if (status < 0) {
        return status;
      }
      result = Math.max(result, status);
    }
    return result;
  }

  private static int emitNative(
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
    int payloadLength = firstLength + secondLength;
    boolean telemetry = operation == OperationType.TELEMETRY_RECEIVE;
    NativeMemory packet =
        new NativeMemory(
            (telemetry ? IOCTLPacket.packetPrefixSize : IOCTLPacket.http1PacketPrefixSize)
                + payloadLength);
    int writeOffset;
    if (transport instanceof Connection) {
      Connection connection = (Connection) transport;
      writeOffset =
          telemetry
              ? IOCTLPacket.writeTelemetryReceivePacketPrefix(packet, 0, connection, payloadLength)
              : IOCTLPacket.writeHttp1PacketPrefix(
                  packet,
                  0,
                  operation,
                  connection,
                  payloadLength,
                  context.lifecycle().id(),
                  context.requestSequence());
    } else if (transport instanceof Socket) {
      Socket socket = (Socket) transport;
      writeOffset =
          telemetry
              ? IOCTLPacket.writeTelemetryReceivePacketPrefix(packet, 0, socket, payloadLength)
              : IOCTLPacket.writeHttp1PacketPrefix(
                  packet,
                  0,
                  operation,
                  socket,
                  payloadLength,
                  context.lifecycle().id(),
                  context.requestSequence());
    } else {
      return -1;
    }
    writeOffset =
        IOCTLPacket.writePacketBuffer(packet, writeOffset, first, firstOffset, firstLength);
    IOCTLPacket.writePacketBuffer(packet, writeOffset, second, secondOffset, secondLength);
    if (transport instanceof Connection) {
      Connection connection = (Connection) transport;
      return telemetry
          ? BootstrapNative.emitTelemetryReceiveData(connection, packet.getAddress())
          : BootstrapNative.emitHttp1Data(
              connection,
              packet.getAddress(),
              operation,
              primaryAcknowledged,
              context.bridgeEpoch());
    }
    Socket socket = (Socket) transport;
    return telemetry
        ? BootstrapNative.emitTelemetryReceiveData(socket, lifecycle, packet.getAddress())
        : BootstrapNative.emitHttp1Data(
            socket,
            context.lifecycle(),
            packet.getAddress(),
            operation,
            primaryAcknowledged,
            context.bridgeEpoch());
  }

  private static boolean supportedTransport(Object transport) {
    return transport instanceof Connection || transport instanceof Socket;
  }

  interface Emitter {
    int emit(
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
        boolean primaryAcknowledged);
  }
}
