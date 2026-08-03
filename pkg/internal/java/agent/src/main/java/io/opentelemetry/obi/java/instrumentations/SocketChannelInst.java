/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor.b;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.data.BytesWithLen;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class SocketChannelInst {
  private static final long INVALID_READ_STATE = -1;
  private static final long FRESH_FILL_READ_STATE = 1L << Integer.SIZE;

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(SocketChannel.class)
        .and(ElementMatchers.not(ElementMatchers.isAbstract()))
        .and(ElementMatchers.not(ElementMatchers.isInterface()))
        .and(ElementMatchers.declaresField(ElementMatchers.named("localAddress")))
        .and(ElementMatchers.declaresField(ElementMatchers.named("remoteAddress")))
        .and(
            ElementMatchers.declaresField(
                ElementMatchers.named("fdVal").and(ElementMatchers.fieldType(int.class))));
  }

  public static boolean matches(Class<?> clazz) {
    return SocketChannel.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(WriteAdvice.class)
                    .on(
                        ElementMatchers.named("write")
                            .and(ElementMatchers.takesArgument(0, ByteBuffer.class))))
            .visit(
                Advice.to(WriteAdviceArray.class)
                    .on(
                        ElementMatchers.named("write")
                            .and(ElementMatchers.takesArgument(0, ByteBuffer[].class))))
            .visit(
                Advice.to(ReadAdvice.class)
                    .on(
                        ElementMatchers.named("read")
                            .and(ElementMatchers.takesArguments(1))
                            .and(ElementMatchers.takesArgument(0, ByteBuffer.class))))
            .visit(
                Advice.to(ReadAdviceArray.class)
                    .on(
                        ElementMatchers.named("read")
                            .and(ElementMatchers.takesArguments(3))
                            .and(ElementMatchers.takesArgument(0, ByteBuffer[].class))))
            .visit(
                Advice.to(KillAdvice.class)
                    .on(
                        ElementMatchers.named("kill")
                            .and(ElementMatchers.takesArguments(0))
                            .and(ElementMatchers.returns(void.class))))
            .visit(
                Advice.to(TryCloseAdvice.class)
                    .on(
                        ElementMatchers.named("tryClose")
                            .and(ElementMatchers.takesArguments(0))
                            .and(ElementMatchers.returns(boolean.class))));
  }

  public static final class WriteAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int write(@Advice.Argument(0) final ByteBuffer src) {
      if (src == null) {
        return -1;
      }
      return b(src).position();
    }

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void write(
        @Advice.This Object channel,
        @Advice.Argument(0) final ByteBuffer src,
        @Advice.Enter int savedPos,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket,
        @Advice.FieldValue("fdVal") int socketFileDescriptor) {

      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)) {
        return;
      }

      if (src == null) {
        return;
      }

      if (savedPos < 0) {
        return;
      }

      ByteBuffer dup = src.duplicate();
      b(dup).position(savedPos);
      String bufKey = ByteBufferExtractor.keyFromFreshBuffer(dup);

      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] write advice, lookup: " + bufKey);
      }

      BytesWithLen unencrypted = SSLStorage.getUnencryptedBuffer(bufKey);
      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] write advice, unencrypted: " + unencrypted);
      }
      if (unencrypted == null) {
        return;
      }
      InetSocketAddress inetSocketAddress = (InetSocketAddress) localSocket;
      InetSocketAddress remoteSocketAddress = (InetSocketAddress) remoteSocket;

      Connection c =
          new Connection(
              inetSocketAddress.getAddress(),
              inetSocketAddress.getPort(),
              remoteSocketAddress.getAddress(),
              remoteSocketAddress.getPort(),
              socketFileDescriptor);
      c = SSLStorage.associateConnectionWithChannel(channel, c);
      if (c == null) {
        return;
      }

      NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + unencrypted.len);
      int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, c, unencrypted.len);
      IOCTLPacket.writePacketBuffer(p, wOff, unencrypted.buf, 0, unencrypted.len);
      BootstrapNative.emitData(c, p.getAddress(), false);
    }
  }

  public static final class WriteAdviceArray {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static int[] write(@Advice.Argument(0) final ByteBuffer[] srcs) {
      if (srcs == null) {
        return null;
      }
      int[] positions = new int[srcs.length];
      for (int i = 0; i < srcs.length; i++) {
        if (srcs[i] == null) {
          positions[i] = -1;
          continue;
        }
        positions[i] = b(srcs[i]).position();
      }

      return positions;
    }

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void write(
        @Advice.This Object channel,
        @Advice.Argument(0) final ByteBuffer[] srcs,
        @Advice.Enter int[] savedSrcPositions,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket,
        @Advice.FieldValue("fdVal") int socketFileDescriptor) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || (srcs == null)) {
        return;
      }

      if (savedSrcPositions == null) {
        return;
      }

      ByteBuffer[] dups = new ByteBuffer[srcs.length];

      for (int i = 0; i < srcs.length; i++) {
        if (srcs[i] == null) {
          continue;
        }
        if (savedSrcPositions[i] != -1) {
          dups[i] = srcs[i].duplicate();
          b(dups[i]).position(savedSrcPositions[i]);
        }
      }

      ByteBuffer srcBuffer = ByteBufferExtractor.flattenFreshByteBufferArray(dups);
      String bufKey = ByteBufferExtractor.keyFromUsedBuffer(srcBuffer);

      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] write array advice, lookup: " + bufKey);
      }

      BytesWithLen unencrypted = SSLStorage.getUnencryptedBuffer(bufKey);
      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] unencrypted: " + unencrypted);
      }
      if (unencrypted == null) {
        return;
      }

      SSLStorage.removeBufferMapping(bufKey);

      InetSocketAddress inetSocketAddress = (InetSocketAddress) localSocket;
      InetSocketAddress remoteSocketAddress = (InetSocketAddress) remoteSocket;

      Connection c =
          new Connection(
              inetSocketAddress.getAddress(),
              inetSocketAddress.getPort(),
              remoteSocketAddress.getAddress(),
              remoteSocketAddress.getPort(),
              socketFileDescriptor);
      c = SSLStorage.associateConnectionWithChannel(channel, c);
      if (c == null) {
        return;
      }

      NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + unencrypted.len);
      int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, c, unencrypted.len);
      IOCTLPacket.writePacketBuffer(p, wOff, unencrypted.buf, 0, unencrypted.len);
      BootstrapNative.emitData(c, p.getAddress(), false);
    }
  }

  public static final class ReadAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static long read(@Advice.Argument(0) final ByteBuffer dst) {
      if (dst == null) {
        return INVALID_READ_STATE;
      }
      Buffer unwrapped = b(dst);
      int position = unwrapped.position();
      return Integer.toUnsignedLong(position)
          | (position == 0 && unwrapped.limit() == unwrapped.capacity()
              ? FRESH_FILL_READ_STATE
              : 0);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void read(
        @Advice.This Object channel,
        @Advice.Argument(0) final ByteBuffer dst,
        @Advice.Enter long initialState,
        @Advice.Return int readBytes,
        @Advice.Thrown Throwable throwable,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket,
        @Advice.FieldValue("fdVal") int socketFileDescriptor) {
      if (throwable != null || readBytes < 0) {
        // EOF and read failures can be followed immediately by descriptor teardown or reuse. The
        // channel is no longer a safe source for queued TLS correlation, even if its close hook
        // has not run yet.
        KillAdvice.cleanup(
            channel, KillAdvice.capture(localSocket, remoteSocket, socketFileDescriptor));
        return;
      }
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || dst == null
          || readBytes == 0
          || initialState == INVALID_READ_STATE
          || b(dst).position() - (int) initialState != readBytes) {
        return;
      }
      InetSocketAddress localSocketAddress = (InetSocketAddress) localSocket;
      InetSocketAddress remoteSocketAddress = (InetSocketAddress) remoteSocket;

      Connection c =
          new Connection(
              localSocketAddress.getAddress(),
              localSocketAddress.getPort(),
              remoteSocketAddress.getAddress(),
              remoteSocketAddress.getPort(),
              socketFileDescriptor);
      c = SSLStorage.associateConnectionWithChannel(channel, c);
      if (c == null) {
        return;
      }

      SSLStorage.setConnectionForReadBuffer(dst, c, (initialState & FRESH_FILL_READ_STATE) != 0);
      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] Setting connection for read buffer");
      }
    }
  }

  public static final class ReadAdviceArray {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object[] read(
        @Advice.Argument(0) final ByteBuffer[] dsts,
        @Advice.Argument(1) int offset,
        @Advice.Argument(2) int length) {
      if (dsts == null || offset < 0 || length < 0 || offset > dsts.length - length) {
        return null;
      }
      long[] states = new long[dsts.length];
      ByteBuffer[] buffers = dsts.clone();
      for (int i = offset; i < offset + length; i++) {
        if (buffers[i] == null) {
          states[i] = INVALID_READ_STATE;
          continue;
        }
        Buffer unwrapped = b(buffers[i]);
        int position = unwrapped.position();
        states[i] =
            Integer.toUnsignedLong(position)
                | (position == 0 && unwrapped.limit() == unwrapped.capacity()
                    ? FRESH_FILL_READ_STATE
                    : 0);
      }
      return new Object[] {buffers, states, offset, length};
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void read(
        @Advice.This Object channel,
        @Advice.Argument(0) final ByteBuffer[] dsts,
        @Advice.Enter Object[] saved,
        @Advice.Return long readBytes,
        @Advice.Thrown Throwable throwable,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket,
        @Advice.FieldValue("fdVal") int socketFileDescriptor) {
      if (throwable != null || readBytes < 0) {
        // See the scalar read advice: no queued correlation may outlive EOF or a read failure.
        KillAdvice.cleanup(
            channel, KillAdvice.capture(localSocket, remoteSocket, socketFileDescriptor));
        return;
      }
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || dsts == null
          || saved == null
          || readBytes == 0) {
        return;
      }
      ByteBuffer[] buffers = (ByteBuffer[]) saved[0];
      long[] states = (long[]) saved[1];
      int offset = (Integer) saved[2];
      int length = (Integer) saved[3];
      if (dsts.length != buffers.length || states.length != buffers.length) {
        return;
      }

      long advanced = 0;
      for (int i = offset; i < offset + length; i++) {
        if (dsts[i] != buffers[i]) {
          return;
        }
        if (buffers[i] == null) {
          continue;
        }
        int delta = b(buffers[i]).position() - (int) states[i];
        if (states[i] == INVALID_READ_STATE || delta < 0) {
          return;
        }
        advanced += delta;
      }
      if (advanced != readBytes) {
        return;
      }

      InetSocketAddress localSocketAddress = (InetSocketAddress) localSocket;
      InetSocketAddress remoteSocketAddress = (InetSocketAddress) remoteSocket;

      Connection c =
          new Connection(
              localSocketAddress.getAddress(),
              localSocketAddress.getPort(),
              remoteSocketAddress.getAddress(),
              remoteSocketAddress.getPort(),
              socketFileDescriptor);
      c = SSLStorage.associateConnectionWithChannel(channel, c);
      if (c == null) {
        return;
      }

      for (int i = offset; i < offset + length; i++) {
        if (buffers[i] != null && b(buffers[i]).position() > (int) states[i]) {
          SSLStorage.setConnectionForReadBuffer(
              buffers[i], c, (states[i] & FRESH_FILL_READ_STATE) != 0);
        }
      }

      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] Setting connection for read buffer array");
      }
    }
  }

  public static final class KillAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void cleanup(
        @Advice.This Object channel,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket,
        @Advice.FieldValue("fdVal") int socketFileDescriptor) {
      cleanup(channel, capture(localSocket, remoteSocket, socketFileDescriptor));
    }

    static Connection capture(
        SocketAddress localSocket, SocketAddress remoteSocket, int socketFileDescriptor) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || socketFileDescriptor < 0) {
        return null;
      }
      InetSocketAddress localSocketAddress = (InetSocketAddress) localSocket;
      InetSocketAddress remoteSocketAddress = (InetSocketAddress) remoteSocket;

      return new Connection(
          localSocketAddress.getAddress(),
          localSocketAddress.getPort(),
          remoteSocketAddress.getAddress(),
          remoteSocketAddress.getPort(),
          socketFileDescriptor);
    }

    static void cleanup(Object channel, Connection connection) {
      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] Cleanup connection " + connection);
      }
      SSLStorage.cleanupConnection(channel, connection);
    }
  }

  public static final class TryCloseAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object[] capture(
        @Advice.This Object channel,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket,
        @Advice.FieldValue("fdVal") int socketFileDescriptor) {
      Connection connection = captureConnection(localSocket, remoteSocket, socketFileDescriptor);
      return new Object[] {
        connection, SSLStorage.beginRemoteParentConnectionClose(channel, connection)
      };
    }

    static Connection captureConnection(
        SocketAddress localSocket, SocketAddress remoteSocket, int socketFileDescriptor) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || socketFileDescriptor < 0) {
        return null;
      }
      InetSocketAddress localSocketAddress = (InetSocketAddress) localSocket;
      InetSocketAddress remoteSocketAddress = (InetSocketAddress) remoteSocket;

      return new Connection(
          localSocketAddress.getAddress(),
          localSocketAddress.getPort(),
          remoteSocketAddress.getAddress(),
          remoteSocketAddress.getPort(),
          socketFileDescriptor);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void cleanup(@Advice.This Object channel, @Advice.Enter Object[] closeState) {
      Connection connection =
          closeState != null && closeState.length > 0 && closeState[0] instanceof Connection
              ? (Connection) closeState[0]
              : null;
      Object fence = closeState != null && closeState.length > 1 ? closeState[1] : null;
      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] Cleanup connection " + connection);
      }
      SSLStorage.finishRemoteParentConnectionClose(channel, connection, fence);
    }
  }
}
