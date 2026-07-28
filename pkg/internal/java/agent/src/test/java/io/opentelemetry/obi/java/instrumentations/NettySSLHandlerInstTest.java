/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.lang.instrument.ClassFileTransformer;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class NettySSLHandlerInstTest {
  private static final String SSL_HANDLER_INTERNAL_NAME = "io/netty/handler/ssl/SslHandler";
  private static final String SSL_HANDLER_CLASS_NAME = "io.netty.handler.ssl.SslHandler";
  private static final String ABSTRACT_UNSAFE_INTERNAL_NAME =
      "io/netty/channel/AbstractChannel$AbstractUnsafe";
  private static final String AUXILIARY_INTERFACE_INTERNAL_NAME =
      "io/opentelemetry/javaagent/bootstrap/field/VirtualFieldAccessor$io$netty$channel$ChannelHandler$io$netty$channel$ChannelHandler";
  private static final String AUXILIARY_INTERFACE_CLASS_NAME =
      AUXILIARY_INTERFACE_INTERNAL_NAME.replace('/', '.');
  private static final String SSL_STORAGE_INTERNAL_NAME =
      "io/opentelemetry/obi/java/instrumentations/data/SSLStorage";
  private static final String UNWRAP_DESCRIPTOR =
      "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V";
  private static final String WRAP_DESCRIPTOR = "(Ljava/lang/Object;Ljava/lang/Object;)V";

  @AfterEach
  void cleanup() {
    SSLStorage.nettyConnection.remove();
  }

  @Test
  void transformsOtelModifiedSslHandlerWithoutResolvingItsAuxiliaryInterface() throws Exception {
    byte[] transformed = transform(sslHandlerWithThrowingUnwrap());

    assertNotNull(transformed);
    assertTrue(hasInterface(transformed, AUXILIARY_INTERFACE_INTERNAL_NAME));
    assertEquals(
        1,
        scopeInvocationCount(transformed, "unwrap", UNWRAP_DESCRIPTOR, "beginNettyHandlerScope"));
    assertEquals(
        2, scopeInvocationCount(transformed, "unwrap", UNWRAP_DESCRIPTOR, "endNettyHandlerScope"));
    assertEquals(
        1, scopeInvocationCount(transformed, "wrap", WRAP_DESCRIPTOR, "beginNettyHandlerScope"));
    assertEquals(
        2, scopeInvocationCount(transformed, "wrap", WRAP_DESCRIPTOR, "endNettyHandlerScope"));
  }

  @Test
  void transformsAbstractUnsafeTerminalCloseMethods() throws Exception {
    byte[] transformed = transform(ABSTRACT_UNSAFE_INTERNAL_NAME, abstractUnsafeWithCloseMethods());

    assertNotNull(transformed);
    assertEquals(
        1,
        staticInvocationCount(
            transformed, "close", "(Lio/netty/channel/ChannelPromise;)V", "closeNettyChannel"));
    assertEquals(
        1, staticInvocationCount(transformed, "closeForcibly", "()V", "closeNettyChannel"));
    assertEquals(1, staticInvocationCount(transformed, "<init>", "()V", "registerNettyCloseHook"));
    assertEquals(
        1,
        outerChannelFieldAccessCount(transformed, "close", "(Lio/netty/channel/ChannelPromise;)V"));
    assertEquals(1, outerChannelFieldAccessCount(transformed, "closeForcibly", "()V"));
    assertEquals(1, outerChannelFieldAccessCount(transformed, "<init>", "()V"));
  }

  @Test
  void rejectsAbstractUnsafeWithoutBothTerminalCloseMethods() throws Exception {
    assertNull(transform(ABSTRACT_UNSAFE_INTERNAL_NAME, abstractUnsafeWithoutCloseForcibly()));
  }

  @Test
  void transformedImplicitFailureRestoresTheOuterScope() throws Exception {
    ByteArrayClassLoader loader = new ByteArrayClassLoader(getClass().getClassLoader());
    loader.define(AUXILIARY_INTERFACE_CLASS_NAME, auxiliaryInterface());
    Class<?> sslHandler =
        loader.define(SSL_HANDLER_CLASS_NAME, transform(sslHandlerWithThrowingUnwrap()));
    Object handler = sslHandler.getDeclaredConstructor().newInstance();

    Object outer = new Object();
    SSLStorage.beginNettyConnectionScope();
    SSLStorage.nettyConnection.set(outer);
    try {
      InvocationTargetException failure =
          assertThrows(
              InvocationTargetException.class,
              () ->
                  sslHandler
                      .getMethod("unwrap", Object.class, Object.class, Object.class)
                      .invoke(handler, new FakeContext(), new Object(), new Object()));

      assertEquals(IllegalStateException.class, failure.getCause().getClass());
      assertSame(outer, SSLStorage.nettyConnection.get());
    } finally {
      SSLStorage.endNettyConnectionScope();
    }
    assertNull(SSLStorage.nettyConnection.get());
  }

  @Test
  void transformedNormalReturnRestoresTheOuterScope() throws Exception {
    ByteArrayClassLoader loader = new ByteArrayClassLoader(getClass().getClassLoader());
    loader.define(AUXILIARY_INTERFACE_CLASS_NAME, auxiliaryInterface());
    Class<?> sslHandler =
        loader.define(SSL_HANDLER_CLASS_NAME, transform(sslHandlerWithThrowingUnwrap()));
    Object handler = sslHandler.getDeclaredConstructor().newInstance();

    Object outer = new Object();
    SSLStorage.beginNettyConnectionScope();
    SSLStorage.nettyConnection.set(outer);
    try {
      sslHandler
          .getMethod("wrap", Object.class, Object.class)
          .invoke(handler, new FakeContext(), new Object());

      assertSame(outer, SSLStorage.nettyConnection.get());
    } finally {
      SSLStorage.endNettyConnectionScope();
    }
    assertNull(SSLStorage.nettyConnection.get());
  }

  @Test
  void ignoresUnrelatedClasses() throws Exception {
    ClassFileTransformer transformer = NettySSLHandlerInst.classFileTransformer();

    assertNull(
        transformer.transform(
            getClass().getClassLoader(),
            "io/netty/handler/ssl/NotSslHandler",
            null,
            null,
            sslHandlerWithThrowingUnwrap()));
  }

  @Test
  void failsOpenForMalformedSslHandlerBytes() throws Exception {
    assertNull(
        NettySSLHandlerInst.classFileTransformer()
            .transform(
                getClass().getClassLoader(),
                SSL_HANDLER_INTERNAL_NAME,
                null,
                null,
                new byte[] {0x01}));
  }

  private byte[] transform(byte[] source) throws Exception {
    return transform(SSL_HANDLER_INTERNAL_NAME, source);
  }

  private byte[] transform(String className, byte[] source) throws Exception {
    return NettySSLHandlerInst.classFileTransformer()
        .transform(getClass().getClassLoader(), className, null, null, source);
  }

  private static boolean hasInterface(byte[] classFile, String interfaceName) {
    String[] interfaces = new String[1];
    new ClassReader(classFile)
        .accept(
            new ClassVisitor(Opcodes.ASM9) {
              @Override
              public void visit(
                  int version,
                  int access,
                  String name,
                  String signature,
                  String superName,
                  String[] implementedInterfaces) {
                interfaces[0] = String.join(",", implementedInterfaces);
              }
            },
            0);
    return interfaces[0].contains(interfaceName);
  }

  private static int scopeInvocationCount(
      byte[] classFile, String methodName, String descriptor, String scopeMethod) {
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
                      String owner,
                      String name,
                      String descriptor,
                      boolean isInterface) {
                    if (opcode == Opcodes.INVOKESTATIC
                        && SSL_STORAGE_INTERNAL_NAME.equals(owner)
                        && scopeMethod.equals(name)) {
                      count[0]++;
                    }
                    super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                  }
                };
              }
            },
            0);
    return count[0];
  }

  private static int staticInvocationCount(
      byte[] classFile, String methodName, String descriptor, String staticMethod) {
    return scopeInvocationCount(classFile, methodName, descriptor, staticMethod);
  }

  private static int outerChannelFieldAccessCount(
      byte[] classFile, String methodName, String descriptor) {
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
                  public void visitFieldInsn(
                      int opcode, String owner, String name, String fieldType) {
                    if (opcode == Opcodes.GETFIELD
                        && ABSTRACT_UNSAFE_INTERNAL_NAME.equals(owner)
                        && "this$0".equals(name)) {
                      count[0]++;
                    }
                    super.visitFieldInsn(opcode, owner, name, fieldType);
                  }
                };
              }
            },
            0);
    return count[0];
  }

  private static byte[] sslHandlerWithThrowingUnwrap() {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V1_8,
        Opcodes.ACC_PUBLIC,
        SSL_HANDLER_INTERNAL_NAME,
        null,
        "java/lang/Object",
        new String[] {AUXILIARY_INTERFACE_INTERNAL_NAME});
    constructor(writer);
    throwingUnwrap(writer);
    returningWrap(writer);
    throwingCallee(writer);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] auxiliaryInterface() {
    ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V1_8,
        Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_INTERFACE,
        AUXILIARY_INTERFACE_INTERNAL_NAME,
        null,
        "java/lang/Object",
        null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] abstractUnsafeWithCloseMethods() {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V1_8,
        Opcodes.ACC_PUBLIC,
        ABSTRACT_UNSAFE_INTERNAL_NAME,
        null,
        "java/lang/Object",
        null);
    writer.visitField(
        Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
        "this$0",
        "Lio/netty/channel/AbstractChannel;",
        null,
        null);
    constructor(writer);
    returningMethod(writer, "close", "(Lio/netty/channel/ChannelPromise;)V");
    returningMethod(writer, "closeForcibly", "()V");
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] abstractUnsafeWithoutCloseForcibly() {
    ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V1_8,
        Opcodes.ACC_PUBLIC,
        ABSTRACT_UNSAFE_INTERNAL_NAME,
        null,
        "java/lang/Object",
        null);
    writer.visitField(
        Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC,
        "this$0",
        "Lio/netty/channel/AbstractChannel;",
        null,
        null);
    constructor(writer);
    returningMethod(writer, "close", "(Lio/netty/channel/ChannelPromise;)V");
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static void constructor(ClassWriter writer) {
    MethodVisitor visitor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
    visitor.visitCode();
    visitor.visitVarInsn(Opcodes.ALOAD, 0);
    visitor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
    visitor.visitInsn(Opcodes.RETURN);
    visitor.visitMaxs(0, 0);
    visitor.visitEnd();
  }

  private static void throwingUnwrap(ClassWriter writer) {
    MethodVisitor visitor =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "unwrap", UNWRAP_DESCRIPTOR, null, null);
    visitor.visitCode();
    visitor.visitMethodInsn(Opcodes.INVOKESTATIC, SSL_HANDLER_INTERNAL_NAME, "fail", "()V", false);
    visitor.visitInsn(Opcodes.RETURN);
    visitor.visitMaxs(0, 0);
    visitor.visitEnd();
  }

  private static void returningWrap(ClassWriter writer) {
    MethodVisitor visitor =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "wrap", WRAP_DESCRIPTOR, null, null);
    visitor.visitCode();
    visitor.visitInsn(Opcodes.RETURN);
    visitor.visitMaxs(0, 0);
    visitor.visitEnd();
  }

  private static void returningMethod(ClassWriter writer, String name, String descriptor) {
    MethodVisitor visitor = writer.visitMethod(Opcodes.ACC_PUBLIC, name, descriptor, null, null);
    visitor.visitCode();
    visitor.visitInsn(Opcodes.RETURN);
    visitor.visitMaxs(0, 0);
    visitor.visitEnd();
  }

  private static void throwingCallee(ClassWriter writer) {
    MethodVisitor visitor =
        writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "fail", "()V", null, null);
    visitor.visitCode();
    visitor.visitTypeInsn(Opcodes.NEW, "java/lang/IllegalStateException");
    visitor.visitInsn(Opcodes.DUP);
    visitor.visitLdcInsn("TLS operation failed");
    visitor.visitMethodInsn(
        Opcodes.INVOKESPECIAL,
        "java/lang/IllegalStateException",
        "<init>",
        "(Ljava/lang/String;)V",
        false);
    visitor.visitInsn(Opcodes.ATHROW);
    visitor.visitMaxs(0, 0);
    visitor.visitEnd();
  }

  public static final class FakeContext {
    public FakeChannel channel() {
      return new FakeChannel();
    }
  }

  public static final class FakeChannel {
    public InetSocketAddress localAddress() {
      return new InetSocketAddress(InetAddress.getLoopbackAddress(), 1234);
    }

    public InetSocketAddress remoteAddress() {
      return new InetSocketAddress(InetAddress.getLoopbackAddress(), 5678);
    }
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
