/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor.b;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.bridge.RemoteParentBridge;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.data.BytesWithLen;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class SSLEngineInst {

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.isSubTypeOf(SSLEngine.class);
  }

  public static boolean matches(Class<?> clazz) {
    return SSLEngine.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(UnwrapAdvice.class)
                    .on(
                        ElementMatchers.named("unwrap")
                            .and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.takesArgument(1, ByteBuffer.class))))
            .visit(
                Advice.to(UnwrapAdviceArray.class)
                    .on(
                        ElementMatchers.named("unwrap")
                            .and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.takesArgument(1, ByteBuffer[].class))))
            .visit(
                Advice.to(WrapAdvice.class)
                    .on(
                        ElementMatchers.named("wrap")
                            .and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.takesArgument(0, ByteBuffer.class))))
            .visit(
                Advice.to(WrapAdviceArray.class)
                    .on(
                        ElementMatchers.named("wrap")
                            .and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.takesArgument(0, ByteBuffer[].class))));
  }

  public static final class UnwrapAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object[] unwrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(0) final ByteBuffer src,
        @Advice.Argument(1) final ByteBuffer dst) {
      if (dst == null) {
        return null;
      }

      int savedPos = b(dst).position();
      Object handoff = SSLStorage.captureReadBufferHandoff(src);
      Connection scoped = SSLStorage.currentScopedConnection();

      if (SSLStorage.debugOn) {
        System.err.println("[SSLEngineInst] looking up connection for read buffer");
      }
      Connection c = SSLStorage.resolveConnectionForUnwrap(engine, handoff);
      Object owner = SSLStorage.captureConnectionOwnerForUnwrap(engine, c);

      if (SSLStorage.debugOn && c != null) {
        System.err.println("[SSLEngineInst] unwrap found connection " + c);
      }
      return new Object[] {savedPos, c, handoff, owner, scoped};
    }

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void unwrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Enter Object[] saved,
        @Advice.Argument(0) final ByteBuffer src,
        @Advice.Argument(1) final ByteBuffer dst,
        @Advice.Return SSLEngineResult result) {
      if (saved == null) {
        return;
      }
      int savedPos = (Integer) saved[0];
      Connection c = (Connection) saved[1];
      Object handoff = saved[2];
      Object owner = saved[3];
      Connection scoped = (Connection) saved[4];

      if (src == null || dst == null || result == null) {
        return;
      }

      if (engine.getSession().getId().length == 0) {
        return;
      }

      ByteBuffer dstBuffer =
          ByteBufferExtractor.fromProducedBuffer(dst, savedPos, result.bytesProduced());

      byte[] b = dstBuffer.array();
      int len = b(dstBuffer).position();
      if (len == 0) {
        return;
      }

      c =
          SSLStorage.claimConnectionForUnwrap(
              engine, src, handoff, c, owner, scoped, result.bytesConsumed(), len);
      if (c == null) {
        return;
      }

      if (SSLStorage.debugOn) {
        System.err.println("[SSLEngineInst] unwrap:" + java.util.Arrays.toString(b));
      }

      NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + len);
      int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.RECEIVE, c, len);
      IOCTLPacket.writePacketBuffer(p, wOff, b, 0, len);
      try {
        BootstrapNative.markTlsConnectionIfDue(engine, c);
      } catch (Throwable failure) {
        if (SSLStorage.debugOn) {
          System.err.println("[SSLEngineInst] failed to mark TLS connection: " + failure);
        }
      }
      int emitStatus = BootstrapNative.emitData(c.getSocketFileDescriptor(), p.getAddress(), true);
      if (emitStatus >= 0) {
        RemoteParentBridge.recordTlsRead(len);
      }
    }
  }

  public static final class UnwrapAdviceArray {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object[] unwrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(0) final ByteBuffer src,
        @Advice.Argument(1) final ByteBuffer[] dsts) {
      if (dsts == null || dsts.length == 0) {
        return null;
      }

      int[] positions = new int[dsts.length];
      ByteBuffer[] buffers = dsts.clone();
      for (int i = 0; i < dsts.length; i++) {
        if (buffers[i] == null) {
          positions[i] = -1;
          continue;
        }
        positions[i] = b(buffers[i]).position();
      }

      Object handoff = SSLStorage.captureReadBufferHandoff(src);
      Connection scoped = SSLStorage.currentScopedConnection();

      if (SSLStorage.debugOn) {
        System.err.println("[SSLEngineInst] looking up connection for read buffer array");
      }
      Connection c = SSLStorage.resolveConnectionForUnwrap(engine, handoff);
      Object owner = SSLStorage.captureConnectionOwnerForUnwrap(engine, c);

      if (SSLStorage.debugOn && c != null) {
        System.err.println("[SSLEngineInst] unwrap array found connection " + c);
      }
      return new Object[] {positions, buffers, c, handoff, owner, scoped};
    }

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void unwrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Enter Object[] saved,
        @Advice.Argument(0) final ByteBuffer src,
        @Advice.Argument(1) final ByteBuffer[] dsts,
        @Advice.Return SSLEngineResult result) {
      if (src == null || dsts == null || saved == null || result == null) {
        return;
      }
      int[] savedDstPositions = (int[]) saved[0];
      ByteBuffer[] savedDstBuffers = (ByteBuffer[]) saved[1];
      Connection c = (Connection) saved[2];
      Object handoff = saved[3];
      Object owner = saved[4];
      Connection scoped = (Connection) saved[5];

      if (dsts.length == 0 || engine.getSession().getId().length == 0) {
        return;
      }

      if (result.bytesProduced() > 0) {
        if (savedDstPositions == null || savedDstBuffers == null) {
          return;
        }

        ByteBuffer dstBuffer =
            ByteBufferExtractor.fromProducedBufferArray(
                dsts, savedDstBuffers, savedDstPositions, result.bytesProduced());

        byte[] b = dstBuffer.array();
        int len = b(dstBuffer).position();
        if (len == 0) {
          return;
        }

        c =
            SSLStorage.claimConnectionForUnwrap(
                engine, src, handoff, c, owner, scoped, result.bytesConsumed(), len);
        if (c == null) {
          return;
        }

        if (SSLStorage.debugOn) {
          System.err.println("[SSLEngineInst] unwrap array:" + java.util.Arrays.toString(b));
        }

        NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + len);
        int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.RECEIVE, c, len);
        IOCTLPacket.writePacketBuffer(p, wOff, b, 0, len);
        try {
          BootstrapNative.markTlsConnectionIfDue(engine, c);
        } catch (Throwable failure) {
          if (SSLStorage.debugOn) {
            System.err.println("[SSLEngineInst] failed to mark TLS connection: " + failure);
          }
        }
        int emitStatus =
            BootstrapNative.emitData(c.getSocketFileDescriptor(), p.getAddress(), true);
        if (emitStatus >= 0) {
          RemoteParentBridge.recordTlsRead(len);
        }
      }
    }
  }

  public static final class WrapAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void wrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(0) final ByteBuffer src) {
      if (src == null) {
        return;
      }
      if (engine.getSession().getId().length == 0) {
        return;
      }

      if (!b(src).hasRemaining()) {
        return;
      }

      ByteBuffer buf = ByteBufferExtractor.fromFreshBuffer(src, b(src).remaining());
      byte[] b = buf.array();
      int len = b(buf).position();

      SSLStorage.unencrypted.set(new BytesWithLen(b, len));
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void wrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(0) final ByteBuffer src,
        @Advice.Argument(1) final ByteBuffer dst,
        @Advice.Return SSLEngineResult result,
        @Advice.Thrown Throwable throwable) {
      try {
        if (throwable != null || src == null || dst == null || result == null) {
          return;
        }
        if (engine.getSession().getId().length == 0) {
          return;
        }

        if (result.bytesConsumed() > 0) {
          BytesWithLen bLen = SSLStorage.unencrypted.get();
          if (bLen == null) {
            return;
          }

          if (SSLStorage.debugOn) {
            System.err.println("[SSLEngineInst] wrap :" + java.util.Arrays.toString(bLen.buf));
          }

          Connection c = SSLStorage.currentScopedConnection();
          if (SSLStorage.debugOn) {
            System.err.println(
                "[SSLEngineInst] Found netty connection "
                    + c
                    + " thread "
                    + Thread.currentThread().getName());
          }
          if (c != null && c.getSocketFileDescriptor() >= 0) {
            NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + bLen.len);
            int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, c, bLen.len);
            IOCTLPacket.writePacketBuffer(p, wOff, bLen.buf, 0, bLen.len);
            BootstrapNative.emitData(c.getSocketFileDescriptor(), p.getAddress(), false);
          } else {
            String encrypted = ByteBufferExtractor.keyFromUsedBuffer(dst);
            if (SSLStorage.debugOn) {
              System.err.println("[SSLEngineInst] buf mapping on: " + encrypted);
            }
            SSLStorage.setBufferMapping(encrypted, bLen);
          }
        }
      } finally {
        SSLStorage.unencrypted.remove();
      }
    }
  }

  public static final class WrapAdviceArray {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void wrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(0) final ByteBuffer[] srcs) {
      if (srcs == null) {
        return;
      }
      if (srcs.length == 0 || engine.getSession().getId().length == 0) {
        return;
      }

      ByteBuffer buf = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
      byte[] b = buf.array();
      int len = b(buf).position();

      SSLStorage.unencrypted.set(new BytesWithLen(b, len));
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void wrap(
        @Advice.This final javax.net.ssl.SSLEngine engine,
        @Advice.Argument(0) final ByteBuffer[] srcs,
        @Advice.Argument(1) final ByteBuffer dst,
        @Advice.Return SSLEngineResult result,
        @Advice.Thrown Throwable throwable) {
      try {
        if (throwable != null || srcs == null || dst == null || result == null) {
          return;
        }
        if (srcs.length == 0 || engine.getSession().getId().length == 0) {
          return;
        }

        if (result.bytesConsumed() > 0) {
          BytesWithLen bLen = SSLStorage.unencrypted.get();
          if (bLen == null) {
            return;
          }

          if (SSLStorage.debugOn) {
            System.err.println(
                "[SSLEngineInst] wrap array :["
                    + bLen.len
                    + "]"
                    + java.util.Arrays.toString(bLen.buf));
          }

          Connection c = SSLStorage.currentScopedConnection();
          if (SSLStorage.debugOn) {
            System.err.println(
                "[SSLEngineInst] Found netty connection "
                    + c
                    + " thread "
                    + Thread.currentThread().getName());
          }
          if (c != null && c.getSocketFileDescriptor() >= 0) {
            NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + bLen.len);
            int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, c, bLen.len);
            IOCTLPacket.writePacketBuffer(p, wOff, bLen.buf, 0, bLen.len);
            BootstrapNative.emitData(c.getSocketFileDescriptor(), p.getAddress(), false);
          } else {
            String encrypted = ByteBufferExtractor.keyFromUsedBuffer(dst);
            if (SSLStorage.debugOn) {
              System.err.println("[SSLEngineInst] buf array mapping on: " + encrypted);
            }
            SSLStorage.setBufferMapping(encrypted, bLen);
          }
        }
      } finally {
        SSLStorage.unencrypted.remove();
      }
    }
  }
}
