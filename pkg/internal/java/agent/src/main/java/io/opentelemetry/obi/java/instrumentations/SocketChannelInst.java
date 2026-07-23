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
                Advice.to(CleanupAdvice.class)
                    .on(
                        ElementMatchers.named("shutdownInput")
                            .or(ElementMatchers.named("shutdownOutput"))
                            .or(ElementMatchers.named("kill"))
                            .or(ElementMatchers.named("tryClose"))));
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

      NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + unencrypted.len);
      int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, c, unencrypted.len);
      IOCTLPacket.writePacketBuffer(p, wOff, unencrypted.buf, 0, unencrypted.len);
      BootstrapNative.emitData(c.getSocketFileDescriptor(), p.getAddress(), false);
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

      NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + unencrypted.len);
      int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, c, unencrypted.len);
      IOCTLPacket.writePacketBuffer(p, wOff, unencrypted.buf, 0, unencrypted.len);
      BootstrapNative.emitData(c.getSocketFileDescriptor(), p.getAddress(), false);
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
        @Advice.Argument(0) final ByteBuffer dst,
        @Advice.Enter long initialState,
        @Advice.Return int readBytes,
        @Advice.Thrown Throwable throwable,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket,
        @Advice.FieldValue("fdVal") int socketFileDescriptor) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || dst == null
          || throwable != null
          || readBytes <= 0
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
        @Advice.Argument(0) final ByteBuffer[] dsts,
        @Advice.Enter Object[] saved,
        @Advice.Return long readBytes,
        @Advice.Thrown Throwable throwable,
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket,
        @Advice.FieldValue("fdVal") int socketFileDescriptor) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || dsts == null
          || saved == null
          || throwable != null
          || readBytes <= 0) {
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

  public static final class CleanupAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void cleanup(
        @Advice.FieldValue("localAddress") SocketAddress localSocket,
        @Advice.FieldValue("remoteAddress") SocketAddress remoteSocket,
        @Advice.FieldValue("fdVal") int socketFileDescriptor) {
      if (!(localSocket instanceof InetSocketAddress)
          || !(remoteSocket instanceof InetSocketAddress)
          || socketFileDescriptor < 0) {
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

      if (SSLStorage.debugOn) {
        System.err.println("[SocketChannelInst] Cleanup connection " + c);
      }
      SSLStorage.cleanupConnection(c);
    }
  }
}
