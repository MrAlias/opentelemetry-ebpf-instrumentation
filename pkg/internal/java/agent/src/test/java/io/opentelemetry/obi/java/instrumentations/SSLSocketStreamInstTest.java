/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.ebpf.IOCTLPacket;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SSLSocketStreamInstTest {

  @AfterEach
  void clearRemoteParentSocketFileDescriptor() {
    ThreadInfo.clearRemoteParentSocketFileDescriptor();
  }

  @Test
  void inputStreamReadPacketUsesBytesReadForPartialBuffer() {
    byte[] buffer = {10, 20, 30, 40, 50};
    int bytesRead = 3;
    NativeMemory packet = new NativeMemory(IOCTLPacket.packetPrefixSize + bytesRead + 1, true);

    // same call sequence the read advices inline
    int wOff = IOCTLPacket.writeTelemetryReceivePacketPrefix(packet, 0, (Socket) null, bytesRead);
    int end = IOCTLPacket.writePacketBuffer(packet, wOff, buffer, 0, bytesRead);

    assertEquals(IOCTLPacket.packetPrefixSize + bytesRead, end);
    assertEquals(OperationType.TELEMETRY_RECEIVE.code, packet.getBuffer().get(0));
    assertEquals(bytesRead, packet.getInt(IOCTLPacket.bufferLengthOffset));
    assertEquals(0L, packet.getLong(IOCTLPacket.dataSignalOffset));
    for (int i = 0; i < bytesRead; i++) {
      assertEquals(buffer[i], packet.getBuffer().get(IOCTLPacket.packetPrefixSize + i));
    }
    assertEquals(0, packet.getBuffer().get(IOCTLPacket.packetPrefixSize + bytesRead));
  }

  @Test
  void inputStreamReadAdvicesClearStagedParentForTerminalAndFailedReceives() {
    ThreadInfo.setRemoteParentSocketFileDescriptor(51);
    SSLSocketStreamInst.InputStreamReadAdvice.read(
        null, SSLSocketStreamInst.InputStreamReadAdvice.enter(null), new byte[1], -1, null);
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());

    ThreadInfo.setRemoteParentSocketFileDescriptor(52);
    SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
        null,
        SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(null),
        new byte[1],
        0,
        0,
        new IOException("expected read failure"));
    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void inputStreamReadAdvicesIgnoreZeroLengthReadsWithoutClearingStagedParent() {
    ThreadInfo.setRemoteParentSocketFileDescriptor(53);
    SSLSocketStreamInst.InputStreamReadAdvice.read(
        null, SSLSocketStreamInst.InputStreamReadAdvice.enter(null), new byte[1], 0, null);
    assertEquals(53, ThreadInfo.remoteParentSocketFileDescriptor());

    SSLSocketStreamInst.InputStreamReadOffsetAdvice.read(
        null, SSLSocketStreamInst.InputStreamReadOffsetAdvice.enter(null), new byte[1], 0, 0, null);
    assertEquals(53, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void inputStreamCloseAdviceClearsStagedParent() {
    ThreadInfo.setRemoteParentSocketFileDescriptor(54);

    Object lifecycle = SSLSocketStreamInst.InputStreamCloseAdvice.close(null);
    SSLSocketStreamInst.InputStreamCloseAdvice.close(null, lifecycle);

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void socketCloseAdviceClearsStagedParent() {
    ThreadInfo.setRemoteParentSocketFileDescriptor(55);

    Object lifecycle = SSLSocketInst.CloseAdvice.close(null);
    SSLSocketInst.CloseAdvice.close(null, lifecycle);

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
  }

  @Test
  void inheritedSocketCloseAdviceFencesACustomSslSocketWithoutItsOwnCloseOverride() {
    FakeInheritedSSLSocket socket = new FakeInheritedSSLSocket();
    RemoteParentSocketContext.Lifecycle lifecycle =
        (RemoteParentSocketContext.Lifecycle) SSLStorage.prepareRemoteParentSocketLifecycle(socket);
    assertNotNull(lifecycle);
    assertTrue(ThreadInfo.setRemoteParentSocketFileDescriptor(56, lifecycle));
    RemoteParentSocketContext alias = new RemoteParentSocketContext(56, lifecycle);

    Object closeLifecycle = SSLSocketInst.InheritedSocketCloseAdvice.close(socket);

    assertEquals(-1, ThreadInfo.remoteParentSocketFileDescriptor());
    assertEquals(-1, alias.peek());
    SSLSocketInst.InheritedSocketCloseAdvice.close(socket, closeLifecycle);
  }

  @Test
  void inputStreamTransformerInlinesTheTerminalAdvices() {
    DynamicType.Builder<?> builder = new ByteBuddy().redefine(FakeAppInputStream.class);
    TypeDescription type = new TypeDescription.ForLoadedType(FakeAppInputStream.class);

    byte[] transformed =
        SSLSocketStreamInst.inputStreamTransformer()
            .transform(builder, type, getClass().getClassLoader(), null, null)
            .make()
            .getBytes();

    // AppInputStream.read() delegates to read(byte[], int, int) on supported JDKs. Advising both
    // would duplicate one-byte receives, so the zero-argument overload must remain untouched.
    assertEquals(
        0,
        staticInvocationCount(
            transformed,
            "read",
            "()I",
            "io/opentelemetry/obi/java/BootstrapNative",
            "invalidateRemoteParentSocketFileDescriptor"));
    assertTrue(
        staticInvocationCount(
                transformed,
                "read",
                "([B)I",
                "io/opentelemetry/obi/java/BootstrapNative",
                "beginRemoteParentSocketRead")
            > 0);
    assertTrue(
        staticInvocationCount(
                transformed,
                "read",
                "([B)I",
                "io/opentelemetry/obi/java/BootstrapNative",
                "abortRemoteParentSocketRead")
            > 0);
    assertTrue(
        staticInvocationCount(
                transformed,
                "read",
                "([B)I",
                "io/opentelemetry/obi/java/BootstrapNative",
                "endRemoteParentSocketRead")
            > 0);
    assertEquals(
        1,
        staticInvocationCount(
            transformed,
            "read",
            "([B)I",
            "io/opentelemetry/obi/java/BootstrapNative",
            "emitRemoteParentSocketReceive"));
    assertTrue(
        staticInvocationCount(
                transformed,
                "read",
                "([BII)I",
                "io/opentelemetry/obi/java/BootstrapNative",
                "invalidateRemoteParentSocketFileDescriptor")
            > 0);
    assertTrue(
        staticInvocationCount(
                transformed,
                "read",
                "([BII)I",
                "io/opentelemetry/obi/java/BootstrapNative",
                "beginRemoteParentSocketRead")
            > 0);
    assertTrue(
        staticInvocationCount(
                transformed,
                "read",
                "([BII)I",
                "io/opentelemetry/obi/java/BootstrapNative",
                "abortRemoteParentSocketRead")
            > 0);
    assertTrue(
        staticInvocationCount(
                transformed,
                "read",
                "([BII)I",
                "io/opentelemetry/obi/java/BootstrapNative",
                "endRemoteParentSocketRead")
            > 0);
    assertEquals(
        0,
        staticInvocationCount(
            transformed,
            "read",
            "([BII)I",
            "io/opentelemetry/obi/java/BootstrapNative",
            "emitTelemetryReceiveData"));
    assertEquals(
        0,
        staticInvocationCount(
            transformed,
            "read",
            "([BII)I",
            "io/opentelemetry/obi/java/BootstrapNative",
            "rejectUnsupportedRemoteParentSocket"));
    assertEquals(
        1,
        staticInvocationCount(
            transformed,
            "read",
            "([BII)I",
            "io/opentelemetry/obi/java/BootstrapNative",
            "emitRemoteParentSocketReceive"));
    assertEquals(
        0,
        staticInvocationCount(
            transformed,
            "read",
            "([BII)I",
            "io/opentelemetry/obi/java/BootstrapNative",
            "emitData"));
    assertEquals(
        0,
        staticInvocationCount(
            transformed,
            "read",
            "([BII)I",
            "io/opentelemetry/obi/java/instrumentations/data/SSLStorage",
            "emitRemoteParentSocketReceive"));
    assertTrue(
        staticInvocationCount(
                transformed,
                "close",
                "()V",
                "io/opentelemetry/obi/java/BootstrapNative",
                "beginRemoteParentSocketClose")
            > 0);
    assertEquals(
        1,
        staticInvocationCount(
            transformed,
            "close",
            "()V",
            "io/opentelemetry/obi/java/BootstrapNative",
            "finishRemoteParentSocketClose"));

    assertTrue(
        SSLSocketInst.inheritedSocketCloseType()
            .matches(new TypeDescription.ForLoadedType(Socket.class)));
    byte[] inheritedSocketCloseTransformed =
        SSLSocketInst.inheritedSocketCloseTransformer()
            .transform(
                new ByteBuddy().redefine(Socket.class),
                new TypeDescription.ForLoadedType(Socket.class),
                null,
                null,
                null)
            .make()
            .getBytes();
    assertEquals(
        1,
        staticInvocationCount(
            inheritedSocketCloseTransformed,
            "close",
            "()V",
            "io/opentelemetry/obi/java/BootstrapNative",
            "beginRemoteParentSocketClose"));
    assertEquals(
        1,
        staticInvocationCount(
            inheritedSocketCloseTransformed,
            "close",
            "()V",
            "io/opentelemetry/obi/java/BootstrapNative",
            "finishRemoteParentSocketClose"));

    byte[] genericSocketCloseTransformed =
        SSLSocketInst.transformer()
            .transform(
                new ByteBuddy().redefine(FakeSSLSocket.class),
                new TypeDescription.ForLoadedType(FakeSSLSocket.class),
                getClass().getClassLoader(),
                null,
                null)
            .make()
            .getBytes();
    assertEquals(
        1,
        staticInvocationCount(
            genericSocketCloseTransformed,
            "close",
            "()V",
            "io/opentelemetry/obi/java/BootstrapNative",
            "beginRemoteParentSocketClose"));
    assertEquals(
        1,
        staticInvocationCount(
            genericSocketCloseTransformed,
            "close",
            "()V",
            "io/opentelemetry/obi/java/BootstrapNative",
            "finishRemoteParentSocketClose"));

    byte[] socketCloseTransformed =
        SSLSocketInst.defaultSocketCloseTransformer()
            .transform(
                new ByteBuddy().redefine(FakeSSLSocket.class),
                new TypeDescription.ForLoadedType(FakeSSLSocket.class),
                getClass().getClassLoader(),
                null,
                null)
            .make()
            .getBytes();
    assertEquals(
        1,
        staticInvocationCount(
            socketCloseTransformed,
            "close",
            "()V",
            "io/opentelemetry/obi/java/BootstrapNative",
            "beginRemoteParentSocketClose"));
    assertEquals(
        1,
        staticInvocationCount(
            socketCloseTransformed,
            "close",
            "()V",
            "io/opentelemetry/obi/java/BootstrapNative",
            "finishRemoteParentSocketClose"));
  }

  @Test
  void matchersRecognizeTheRealDefaultJdkSslTypes() throws Exception {
    Class<?> socket = Class.forName("sun.security.ssl.SSLSocketImpl");
    Class<?> inputStream = Class.forName("sun.security.ssl.SSLSocketImpl$AppInputStream");

    assertTrue(
        SSLSocketInst.defaultSocketCloseType().matches(new TypeDescription.ForLoadedType(socket)));
    assertTrue(
        SSLSocketStreamInst.inputStreamType()
            .matches(new TypeDescription.ForLoadedType(inputStream)));
  }

  private static int staticInvocationCount(
      byte[] classFile, String methodName, String descriptor, String owner, String staticMethod) {
    int[] count = new int[1];
    new ClassReader(classFile)
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public MethodVisitor visitMethod(
                  int access,
                  String name,
                  String methodDescriptor,
                  String signature,
                  String[] exceptions) {
                MethodVisitor visitor =
                    super.visitMethod(access, name, methodDescriptor, signature, exceptions);
                if (!methodName.equals(name) || !descriptor.equals(methodDescriptor)) {
                  return visitor;
                }
                return new MethodVisitor(Opcodes.ASM9, visitor) {
                  @Override
                  public void visitMethodInsn(
                      int opcode,
                      String methodOwner,
                      String name,
                      String methodDescriptor,
                      boolean isInterface) {
                    if (opcode == Opcodes.INVOKESTATIC
                        && owner.equals(methodOwner)
                        && staticMethod.equals(name)) {
                      count[0]++;
                    }
                    super.visitMethodInsn(opcode, methodOwner, name, methodDescriptor, isInterface);
                  }
                };
              }
            },
            0);
    return count[0];
  }

  private static class FakeAppInputStream extends InputStream {
    @SuppressWarnings("unused")
    private Object this$0;

    @Override
    public int read() {
      return -1;
    }

    @Override
    public int read(byte[] buffer) {
      return -1;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) {
      return -1;
    }

    @Override
    public void close() {}
  }

  private static class FakeSSLSocketBase extends SSLSocket {
    @Override
    public String[] getSupportedCipherSuites() {
      return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
      return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {}

    @Override
    public String[] getSupportedProtocols() {
      return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
      return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {}

    @Override
    public SSLSession getSession() {
      return null;
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {}

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {}

    @Override
    public void startHandshake() {}

    @Override
    public void setUseClientMode(boolean mode) {}

    @Override
    public boolean getUseClientMode() {
      return false;
    }

    @Override
    public void setNeedClientAuth(boolean need) {}

    @Override
    public boolean getNeedClientAuth() {
      return false;
    }

    @Override
    public void setWantClientAuth(boolean want) {}

    @Override
    public boolean getWantClientAuth() {
      return false;
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {}

    @Override
    public boolean getEnableSessionCreation() {
      return false;
    }
  }

  private static class FakeSSLSocket extends FakeSSLSocketBase {
    @Override
    public void close() throws IOException {}
  }

  private static class FakeInheritedSSLSocket extends FakeSSLSocketBase {}
}
