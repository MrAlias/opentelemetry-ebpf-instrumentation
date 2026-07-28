/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class NettyChannelExtractorTest {

  static class MockChannel {
    private final InetSocketAddress local;
    private final InetSocketAddress remote;

    MockChannel(InetSocketAddress local, InetSocketAddress remote) {
      this.local = local;
      this.remote = remote;
    }

    public InetSocketAddress localAddress() {
      return local;
    }

    public InetSocketAddress remoteAddress() {
      return remote;
    }
  }

  static class MockContext {
    private final MockChannel channel;

    MockContext(MockChannel channel) {
      this.channel = channel;
    }

    public MockChannel channel() {
      return channel;
    }
  }

  static final class ObjectContext {
    private final Object channel;

    ObjectContext(Object channel) {
      this.channel = channel;
    }

    public Object channel() {
      return channel;
    }
  }

  static class MockNioChannel extends MockChannel {
    private final SocketChannel javaChannel;

    MockNioChannel(InetSocketAddress local, InetSocketAddress remote, SocketChannel javaChannel) {
      super(local, remote);
      this.javaChannel = javaChannel;
    }

    @SuppressWarnings("unused")
    SocketChannel javaChannel() {
      return javaChannel;
    }
  }

  static final class MockNioFdChannel extends MockNioChannel {
    MockNioFdChannel(InetSocketAddress local, InetSocketAddress remote, SocketChannel javaChannel) {
      super(local, remote, javaChannel);
    }

    @SuppressWarnings("unused")
    MockFileDescriptor fd() {
      return new MockFileDescriptor(32);
    }
  }

  static final class MockFileDescriptor {
    private final int value;

    MockFileDescriptor(int value) {
      this.value = value;
    }

    @SuppressWarnings("unused")
    int intValue() {
      return value;
    }
  }

  @AfterEach
  void resetDebug() {
    SSLStorage.debugOn = false;
  }

  @Test
  void doesNotExtractConnectionsWithoutAnAccessibleDescriptor() throws Exception {
    InetSocketAddress local = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1234);
    InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName("192.168.1.1"), 5678);
    MockChannel channel = new MockChannel(local, remote);
    MockContext ctx = new MockContext(channel);

    assertNull(NettyChannelExtractor.extractConnectionFromChannelHandlerContext(ctx));
  }

  @Test
  void testExtractConnectionWithDebug() throws Exception {
    SSLStorage.debugOn = true;
    InetSocketAddress local = new InetSocketAddress(InetAddress.getByName("127.0.0.2"), 4321);
    InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName("10.0.0.1"), 8765);
    try (SocketChannel javaChannel = SocketChannel.open()) {
      Connection c =
          NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
              new MockContext(new MockNioFdChannel(local, remote, javaChannel)));

      assertNotNull(c);
      assertEquals(local.getAddress(), c.getLocalAddress());
      assertEquals(local.getPort(), c.getLocalPort());
      assertEquals(remote.getAddress(), c.getRemoteAddress());
      assertEquals(remote.getPort(), c.getRemotePort());
      SSLStorage.cleanupConnection(javaChannel, c);
    }
  }

  @Test
  void testExtractConnectionNullChannel() {
    Object ctx =
        new Object() {
          public Object channel() {
            return null;
          }
        };
    Connection c = NettyChannelExtractor.extractConnectionFromChannelHandlerContext(ctx);
    assertNull(c);
  }

  @Test
  void testExtractConnectionNullAddresses() {
    MockChannel channel = new MockChannel(null, null);
    MockContext ctx = new MockContext(channel);
    Connection c = NettyChannelExtractor.extractConnectionFromChannelHandlerContext(ctx);
    assertThrows(
        NullPointerException.class,
        () -> {
          // Accessing address/port will throw
          c.getLocalAddress();
        });
  }

  @Test
  void testExtractConnectionExceptionHandling() {
    Object badCtx = new Object(); // No channel() method
    Connection c = NettyChannelExtractor.extractConnectionFromChannelHandlerContext(badCtx);
    assertNull(c);
  }

  @Test
  void reusesTheConnectionCapturedForTheExactJavaChannel() throws Exception {
    InetSocketAddress local = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1234);
    InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName("192.168.1.1"), 5678);
    Connection captured =
        new Connection(
            local.getAddress(), local.getPort(), remote.getAddress(), remote.getPort(), 17);
    try (SocketChannel javaChannel = SocketChannel.open()) {
      assertSame(captured, SSLStorage.associateConnectionWithSocketChannel(javaChannel, captured));

      Connection extracted =
          NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
              new MockContext(new MockNioChannel(local, remote, javaChannel)));

      assertSame(captured, extracted);
      SSLStorage.cleanupConnection(javaChannel, captured);
      assertNull(SSLStorage.getConnectionForSocketChannel(javaChannel));
    }
  }

  @Test
  void cachesAnExtractedConnectionForItsExactJavaChannel() throws Exception {
    InetSocketAddress local = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1234);
    InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName("192.168.1.1"), 5678);
    try (SocketChannel javaChannel = SocketChannel.open()) {
      Connection extracted =
          NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
              new MockContext(new MockNioFdChannel(local, remote, javaChannel)));

      assertNotNull(extracted);
      assertSame(extracted, SSLStorage.getConnectionForSocketChannel(javaChannel));
      SSLStorage.cleanupConnection(javaChannel, extracted);
    }
  }

  @Test
  void NettyTerminalCloseInvalidatesTheSharedJavaChannelState() throws Exception {
    InetSocketAddress local = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1234);
    InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName("192.168.1.1"), 5678);
    try (SocketChannel javaChannel = SocketChannel.open()) {
      MockNioFdChannel channel = new MockNioFdChannel(local, remote, javaChannel);
      Connection extracted =
          NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
              new MockContext(channel));

      assertNotNull(extracted);
      SSLStorage.closeNettyChannel(channel);

      assertNull(SSLStorage.getConnectionForChannel(javaChannel));
      assertNull(
          NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
              new MockContext(channel)));
    }
  }

  @Test
  void extractsNativeConnectionsWhenTheOptionalJavaChannelLookupFails() throws Exception {
    Object channel = nativeChannelWithAbstractChannelAncestor("NativeChannelWithCloseHook");

    assertNull(
        NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
            new ObjectContext(channel)));

    SSLStorage.registerNettyCloseHook(channel);

    Connection extracted =
        NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
            new ObjectContext(channel));

    assertNotNull(extracted);
    assertEquals(31, extracted.getSocketFileDescriptor());
    assertSame(extracted, SSLStorage.getConnectionForChannel(channel));
    SSLStorage.closeNettyChannel(channel);
    assertNull(SSLStorage.getConnectionForChannel(channel));
    assertNull(
        NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
            new ObjectContext(channel)));
  }

  @Test
  void nativeChannelsFailClosedWithoutARegisteredCloseHook() throws Exception {
    Object channel = isolatedNativeChannel();

    assertNull(
        NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
            new ObjectContext(channel)));
  }

  @Test
  void closeHookAvailabilityUsesTheAbstractChannelLoader() throws Exception {
    ByteArrayClassLoader abstractChannelLoader =
        new ByteArrayClassLoader(getClass().getClassLoader());
    abstractChannelLoader.define(
        "io.netty.channel.AbstractChannel",
        classWithDefaultConstructor("io/netty/channel/AbstractChannel", "java/lang/Object"));
    Object registeredChannel =
        childChannel(
            "test.netty.ChildChannelOne",
            abstractChannelLoader,
            "io/netty/channel/AbstractChannel");
    Object otherChildChannel =
        childChannel(
            "test.netty.ChildChannelTwo",
            abstractChannelLoader,
            "io/netty/channel/AbstractChannel");

    SSLStorage.registerNettyCloseHook(registeredChannel);

    assertTrue(SSLStorage.isNettyCloseHookAvailable(otherChildChannel));
  }

  @Test
  void nonAbstractChannelsCannotUseAnAbstractChannelLoadersCloseHook() throws Exception {
    ByteArrayClassLoader loader = new ByteArrayClassLoader(getClass().getClassLoader());
    loader.define(
        "io.netty.channel.AbstractChannel",
        classWithDefaultConstructor("io/netty/channel/AbstractChannel", "java/lang/Object"));
    Object hookedChannel =
        nativeChannel("test.netty.HookedChannel", loader, "io/netty/channel/AbstractChannel");
    Object unhookedChannel =
        nativeChannel("test.netty.UnhookedChannel", loader, "java/lang/Object");

    SSLStorage.registerNettyCloseHook(hookedChannel);

    assertFalse(SSLStorage.isNettyCloseHookAvailable(unhookedChannel));
    assertNull(
        NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
            new ObjectContext(unhookedChannel)));
  }

  @Test
  void doesNotExtractConnectionsAfterTheirJavaChannelCloses() throws Exception {
    InetSocketAddress local = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1234);
    InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName("192.168.1.1"), 5678);
    try (SocketChannel javaChannel = SocketChannel.open()) {
      Connection captured =
          new Connection(
              local.getAddress(), local.getPort(), remote.getAddress(), remote.getPort(), 32);
      assertSame(captured, SSLStorage.associateConnectionWithSocketChannel(javaChannel, captured));
      SSLStorage.cleanupConnection(javaChannel, captured);

      assertNull(
          NettyChannelExtractor.extractConnectionFromChannelHandlerContext(
              new MockContext(new MockNioFdChannel(local, remote, javaChannel))));
    }
  }

  @Test
  void repeatedExtractorFailuresProduceOneDiagnostic() throws Exception {
    Method reset = SSLStorage.class.getDeclaredMethod("resetNettyFailureLoggingForTest");
    reset.setAccessible(true);
    reset.invoke(null);
    PrintStream originalError = System.err;
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try {
      System.setErr(new PrintStream(output, true, "UTF-8"));
      for (int i = 0; i < 10; i++) {
        assertNull(NettyChannelExtractor.extractConnectionFromChannelHandlerContext(new Object()));
      }
    } finally {
      System.setErr(originalError);
      reset.invoke(null);
    }

    assertEquals(1, output.toString("UTF-8").split("Netty helper unavailable", -1).length - 1);
  }

  private static Object isolatedNativeChannel() throws Exception {
    ByteArrayClassLoader loader =
        new ByteArrayClassLoader(NettyChannelExtractorTest.class.getClassLoader());
    return nativeChannel("test.netty.NativeChannelWithoutCloseHook", loader, "java/lang/Object");
  }

  private Object nativeChannelWithAbstractChannelAncestor(String channelName) throws Exception {
    ByteArrayClassLoader loader = new ByteArrayClassLoader(getClass().getClassLoader());
    loader.define(
        "io.netty.channel.AbstractChannel",
        classWithDefaultConstructor("io/netty/channel/AbstractChannel", "java/lang/Object"));
    return nativeChannel("test.netty." + channelName, loader, "io/netty/channel/AbstractChannel");
  }

  private static Object childChannel(
      String className, ClassLoader parent, String abstractChannelInternalName) throws Exception {
    ByteArrayClassLoader loader = new ByteArrayClassLoader(parent);
    Class<?> channel =
        loader.define(
            className,
            classWithDefaultConstructor(className.replace('.', '/'), abstractChannelInternalName));
    return channel.getDeclaredConstructor().newInstance();
  }

  private static Object nativeChannel(
      String className, ByteArrayClassLoader loader, String superName) throws Exception {
    Class<?> channel =
        loader.define(className, nativeChannelClass(className.replace('.', '/'), superName));
    return channel.getDeclaredConstructor().newInstance();
  }

  private static byte[] nativeChannelClass(String internalName, String superName) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, superName, null);
    defaultConstructor(writer, superName);
    inetSocketAddressMethod(writer, "localAddress", "127.0.0.1", 1234);
    inetSocketAddressMethod(writer, "remoteAddress", "192.168.1.1", 5678);
    nullMethod(writer, "javaChannel", "()Ljava/lang/Object;");
    integerMethod(writer, "fd", 31);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] classWithDefaultConstructor(String internalName, String superName) {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, superName, null);
    defaultConstructor(writer, superName);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static void defaultConstructor(ClassWriter writer, String superName) {
    MethodVisitor visitor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    visitor.visitCode();
    visitor.visitVarInsn(Opcodes.ALOAD, 0);
    visitor.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false);
    visitor.visitInsn(Opcodes.RETURN);
    visitor.visitMaxs(0, 0);
    visitor.visitEnd();
  }

  private static void inetSocketAddressMethod(
      ClassWriter writer, String name, String host, int port) {
    MethodVisitor visitor =
        writer.visitMethod(Opcodes.ACC_PUBLIC, name, "()Ljava/net/InetSocketAddress;", null, null);
    visitor.visitCode();
    visitor.visitTypeInsn(Opcodes.NEW, "java/net/InetSocketAddress");
    visitor.visitInsn(Opcodes.DUP);
    visitor.visitLdcInsn(host);
    visitor.visitIntInsn(Opcodes.SIPUSH, port);
    visitor.visitMethodInsn(
        Opcodes.INVOKESPECIAL,
        "java/net/InetSocketAddress",
        "<init>",
        "(Ljava/lang/String;I)V",
        false);
    visitor.visitInsn(Opcodes.ARETURN);
    visitor.visitMaxs(0, 0);
    visitor.visitEnd();
  }

  private static void nullMethod(ClassWriter writer, String name, String descriptor) {
    MethodVisitor visitor = writer.visitMethod(Opcodes.ACC_PUBLIC, name, descriptor, null, null);
    visitor.visitCode();
    visitor.visitInsn(Opcodes.ACONST_NULL);
    visitor.visitInsn(Opcodes.ARETURN);
    visitor.visitMaxs(0, 0);
    visitor.visitEnd();
  }

  private static void integerMethod(ClassWriter writer, String name, int value) {
    MethodVisitor visitor =
        writer.visitMethod(Opcodes.ACC_PUBLIC, name, "()Ljava/lang/Integer;", null, null);
    visitor.visitCode();
    visitor.visitIntInsn(Opcodes.BIPUSH, value);
    visitor.visitMethodInsn(
        Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false);
    visitor.visitInsn(Opcodes.ARETURN);
    visitor.visitMaxs(0, 0);
    visitor.visitEnd();
  }

  private static final class ByteArrayClassLoader extends ClassLoader {
    ByteArrayClassLoader(ClassLoader parent) {
      super(parent);
    }

    Class<?> define(String className, byte[] classFile) {
      return defineClass(className, classFile, 0, classFile.length);
    }
  }
}
