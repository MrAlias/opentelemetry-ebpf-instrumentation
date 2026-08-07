/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.BootstrapNative;
import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

// This advice handles the same functionality as SSLSocketInst (with the help of ProxyInputStream
// and ProxyOutputStream)
// however it's better because it allows us to instrument already established streams, which are
// typical for
// things like databases or stream storage.
public class SSLSocketStreamInst {
  public static ElementMatcher<? super TypeDescription> inputStreamType() {
    return ElementMatchers.isSubTypeOf(InputStream.class)
        .and(ElementMatchers.not(ElementMatchers.isAbstract()))
        .and(ElementMatchers.not(ElementMatchers.isInterface()))
        .and(ElementMatchers.named("sun.security.ssl.SSLSocketImpl$AppInputStream"));
  }

  public static ElementMatcher<? super TypeDescription> outputStreamType() {
    return ElementMatchers.isSubTypeOf(OutputStream.class)
        .and(ElementMatchers.not(ElementMatchers.isAbstract()))
        .and(ElementMatchers.not(ElementMatchers.isInterface()))
        .and(ElementMatchers.named("sun.security.ssl.SSLSocketImpl$AppOutputStream"));
  }

  public static boolean matchesInputStream(Class<?> clazz) {
    return clazz.getName().equals("sun.security.ssl.SSLSocketImpl$AppInputStream");
  }

  public static boolean matchesOutputStream(Class<?> clazz) {
    return clazz.getName().equals("sun.security.ssl.SSLSocketImpl$AppOutputStream");
  }

  public static AgentBuilder.Transformer inputStreamTransformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(InputStreamReadAdvice.class)
                    .on(
                        ElementMatchers.named("read")
                            .and(ElementMatchers.takesArguments(1))
                            .and(ElementMatchers.takesArgument(0, byte[].class))))
            .visit(
                Advice.to(InputStreamReadOffsetAdvice.class)
                    .on(
                        ElementMatchers.named("read")
                            .and(ElementMatchers.takesArguments(3))
                            .and(ElementMatchers.takesArgument(0, byte[].class))))
            .visit(
                Advice.to(InputStreamCloseAdvice.class)
                    .on(
                        ElementMatchers.named("close")
                            .and(ElementMatchers.takesArguments(0))
                            .and(ElementMatchers.returns(void.class))));
  }

  public static AgentBuilder.Transformer outputStreamTransformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(OutputStreamWriteAdvice.class)
                    .on(
                        ElementMatchers.named("write")
                            .and(ElementMatchers.takesArguments(1))
                            .and(ElementMatchers.takesArgument(0, byte[].class))))
            .visit(
                Advice.to(OutputStreamWriteOffsetAdvice.class)
                    .on(
                        ElementMatchers.named("write")
                            .and(ElementMatchers.takesArguments(3))
                            .and(ElementMatchers.takesArgument(0, byte[].class))));
  }

  // The advice bytecode below is inlined into sun.security.ssl classes, which live in the
  // bootstrap classloader: it must only reference bootstrap-injected classes (see
  // Agent.injectBootstrapClasses), never SSLSocketStreamInst itself.
  public static final class InputStreamReadAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(@Advice.FieldValue("this$0") Object outer) {
      return outer instanceof Socket
          ? BootstrapNative.prepareRemoteParentSocketLifecycle((Socket) outer)
          : null;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void read(
        @Advice.FieldValue("this$0") Object outer,
        @Advice.Enter Object lifecycle,
        @Advice.Argument(0) byte[] b,
        @Advice.Return int len,
        @Advice.Thrown Throwable throwable) {

      if (throwable != null || len < 0 || b == null) {
        if (outer instanceof Socket) {
          BootstrapNative.invalidateRemoteParentSocketFileDescriptor((Socket) outer, lifecycle);
        } else {
          BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
        }
        return;
      }

      if (len > 0) {
        Socket socket = null;
        if (outer instanceof Socket) {
          socket = (Socket) outer;
        }

        if (SSLStorage.debugOn) {
          System.err.println(
              "[SSLSocketStreamInst] InputStream.read() intercepted: "
                  + len
                  + " bytes"
                  + ", socket "
                  + socket);
        }
        if (socket != null) {
          try {
            BootstrapNative.emitTelemetryReceiveData(socket, lifecycle, b, 0, len);
          } catch (Throwable t) {
            BootstrapNative.invalidateRemoteParentSocketFileDescriptor(socket, lifecycle);
            if (SSLStorage.debugOn) {
              System.err.println("[SSLSocketStreamInst] Error in read advice: " + t.getMessage());
            }
          }
        } else {
          BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
        }
      }
    }
  }

  public static final class InputStreamReadOffsetAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(@Advice.FieldValue("this$0") Object outer) {
      return outer instanceof Socket
          ? BootstrapNative.prepareRemoteParentSocketLifecycle((Socket) outer)
          : null;
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void read(
        @Advice.FieldValue("this$0") Object outer,
        @Advice.Enter Object lifecycle,
        @Advice.Argument(0) byte[] b,
        @Advice.Argument(1) int off,
        @Advice.Return int bytesRead,
        @Advice.Thrown Throwable throwable) {

      if (throwable != null || bytesRead < 0 || b == null) {
        if (outer instanceof Socket) {
          BootstrapNative.invalidateRemoteParentSocketFileDescriptor((Socket) outer, lifecycle);
        } else {
          BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
        }
        return;
      }

      if (bytesRead > 0) {
        Socket socket = null;
        if (outer instanceof Socket) {
          socket = (Socket) outer;
        }
        if (SSLStorage.debugOn) {
          System.err.println(
              "[SSLSocketStreamInst] InputStream.read(off,len) intercepted: "
                  + bytesRead
                  + " bytes"
                  + ", socket "
                  + socket);
        }
        if (socket != null) {
          try {
            BootstrapNative.emitTelemetryReceiveData(socket, lifecycle, b, off, bytesRead);
          } catch (Throwable t) {
            BootstrapNative.invalidateRemoteParentSocketFileDescriptor(socket, lifecycle);
            if (SSLStorage.debugOn) {
              System.err.println("[SSLSocketStreamInst] Error in read advice: " + t.getMessage());
            }
          }
        } else {
          BootstrapNative.invalidateRemoteParentSocketFileDescriptor(lifecycle);
        }
      }
    }
  }

  public static final class InputStreamCloseAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object close(@Advice.FieldValue("this$0") Object outer) {
      if (outer instanceof Socket) {
        return BootstrapNative.beginRemoteParentSocketClose((Socket) outer);
      }
      return BootstrapNative.beginRemoteParentSocketClose(null);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void close(
        @Advice.FieldValue("this$0") Object outer, @Advice.Enter Object lifecycle) {
      BootstrapNative.finishRemoteParentSocketClose(
          outer instanceof Socket ? (Socket) outer : null, lifecycle);
    }
  }

  public static final class OutputStreamWriteAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void write(
        @Advice.FieldValue("this$0") Object outer, @Advice.Argument(0) byte[] b) {

      if (b != null && b.length > 0) {
        Socket socket = null;
        if (outer instanceof Socket) {
          socket = (Socket) outer;
        }
        if (SSLStorage.debugOn) {
          System.err.println(
              "[SSLSocketStreamInst] OutputStream.write() intercepted: "
                  + b.length
                  + " bytes"
                  + ", socket "
                  + socket);
        }
        if (socket != null) {
          try {
            NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + b.length);
            int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, socket, b.length);
            IOCTLPacket.writePacketBuffer(p, wOff, b);
            BootstrapNative.emitData(socket, p.getAddress(), false);
          } catch (Throwable t) {
            if (SSLStorage.debugOn) {
              System.err.println("[SSLSocketStreamInst] Error in write advice: " + t.getMessage());
            }
          }
        }
      }
    }
  }

  public static final class OutputStreamWriteOffsetAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void write(
        @Advice.FieldValue("this$0") Object outer,
        @Advice.Argument(0) byte[] b,
        @Advice.Argument(1) int off,
        @Advice.Argument(2) int len) {

      if (b != null && len > 0) {
        Socket socket = null;
        if (outer instanceof Socket) {
          socket = (Socket) outer;
        }
        if (SSLStorage.debugOn) {
          System.err.println(
              "[SSLSocketStreamInst] OutputStream.write(off,len) intercepted: "
                  + len
                  + " bytes"
                  + ", socket "
                  + socket);
        }
        if (socket != null) {
          try {
            NativeMemory p = new NativeMemory(IOCTLPacket.packetPrefixSize + len);
            int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.SEND, socket, len);
            IOCTLPacket.writePacketBuffer(p, wOff, b, off, len);
            BootstrapNative.emitData(socket, p.getAddress(), false);
          } catch (Throwable t) {
            if (SSLStorage.debugOn) {
              System.err.println("[SSLSocketStreamInst] Error in write advice: " + t.getMessage());
            }
          }
        }
      }
    }
  }
}
