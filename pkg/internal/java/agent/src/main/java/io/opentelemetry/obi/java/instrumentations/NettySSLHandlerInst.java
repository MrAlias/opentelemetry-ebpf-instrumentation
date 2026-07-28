/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.FieldVisitor;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;

public class NettySSLHandlerInst {
  private static final String CLASS_NAME = "io.netty.handler.ssl.SslHandler";
  private static final String INTERNAL_CLASS_NAME = "io/netty/handler/ssl/SslHandler";
  private static final String ABSTRACT_UNSAFE_CLASS_NAME =
      "io.netty.channel.AbstractChannel$AbstractUnsafe";
  private static final String ABSTRACT_UNSAFE_INTERNAL_CLASS_NAME =
      "io/netty/channel/AbstractChannel$AbstractUnsafe";
  private static final String ABSTRACT_CHANNEL_INTERNAL_CLASS_NAME =
      "io/netty/channel/AbstractChannel";
  private static final String ABSTRACT_UNSAFE_OUTER_CHANNEL_FIELD = "this$0";
  private static final String ABSTRACT_UNSAFE_OUTER_CHANNEL_DESCRIPTOR =
      "L" + ABSTRACT_CHANNEL_INTERNAL_CLASS_NAME + ";";
  private static final String SSL_STORAGE_INTERNAL_CLASS_NAME =
      "io/opentelemetry/obi/java/instrumentations/data/SSLStorage";
  private static final String BEGIN_SCOPE_METHOD = "beginNettyHandlerScope";
  private static final String END_SCOPE_METHOD = "endNettyHandlerScope";
  private static final String CLOSE_NETTY_CHANNEL_METHOD = "closeNettyChannel";
  private static final String REGISTER_NETTY_CLOSE_HOOK_METHOD = "registerNettyCloseHook";
  private static final String BEGIN_SCOPE_DESCRIPTOR = "(Ljava/lang/Object;)V";
  private static final String END_SCOPE_DESCRIPTOR = "()V";
  private static final String CLOSE_NETTY_CHANNEL_DESCRIPTOR = "(Ljava/lang/Object;)V";
  private static final String REGISTER_NETTY_CLOSE_HOOK_DESCRIPTOR = "(Ljava/lang/Object;)V";
  private static final String CLOSE_DESCRIPTOR = "(Lio/netty/channel/ChannelPromise;)V";

  public static ClassFileTransformer install(Instrumentation instrumentation) {
    ClassFileTransformer transformer = classFileTransformer();
    instrumentation.addTransformer(transformer, true);
    return transformer;
  }

  static ClassFileTransformer classFileTransformer() {
    return new Transformer();
  }

  public static boolean matches(Class<?> clazz) {
    String className = clazz.getName();
    return className.equals(CLASS_NAME) || className.equals(ABSTRACT_UNSAFE_CLASS_NAME);
  }

  private static final class Transformer implements ClassFileTransformer {
    @Override
    public byte[] transform(
        ClassLoader loader,
        String className,
        Class<?> classBeingRedefined,
        ProtectionDomain protectionDomain,
        byte[] classfileBuffer) {
      if (!INTERNAL_CLASS_NAME.equals(className)
          && !ABSTRACT_UNSAFE_INTERNAL_CLASS_NAME.equals(className)) {
        return null;
      }

      try {
        ClassReader reader = new ClassReader(classfileBuffer);
        if (INTERNAL_CLASS_NAME.equals(className)) {
          ClassWriter writer = new NonLoadingClassWriter(reader);
          NettySslHandlerVisitor visitor = new NettySslHandlerVisitor(writer);
          reader.accept(visitor, ClassReader.EXPAND_FRAMES);
          return visitor.instrumented ? writer.toByteArray() : null;
        }

        AbstractUnsafeShape shape = new AbstractUnsafeShape();
        reader.accept(
            shape, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        if (!shape.supportsInstrumentation()) {
          return null;
        }

        ClassWriter writer = new NonLoadingClassWriter(reader);
        AbstractUnsafeVisitor visitor = new AbstractUnsafeVisitor(writer);
        reader.accept(visitor, ClassReader.EXPAND_FRAMES);
        return visitor.instrumented ? writer.toByteArray() : null;
      } catch (Throwable ignored) {
        return null;
      }
    }
  }

  private static final class AbstractUnsafeShape extends ClassVisitor {
    private boolean hasOuterChannelField;
    private boolean hasConstructor;
    private boolean hasClose;
    private boolean hasCloseForcibly;

    AbstractUnsafeShape() {
      super(Opcodes.ASM9);
    }

    @Override
    public FieldVisitor visitField(
        int access, String name, String descriptor, String signature, Object value) {
      hasOuterChannelField =
          hasOuterChannelField
              || (ABSTRACT_UNSAFE_OUTER_CHANNEL_FIELD.equals(name)
                  && ABSTRACT_UNSAFE_OUTER_CHANNEL_DESCRIPTOR.equals(descriptor)
                  && (access & Opcodes.ACC_STATIC) == 0);
      return null;
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      if (!isConcreteInstanceMethod(access)) {
        return null;
      }
      if ("<init>".equals(name)) {
        hasConstructor = true;
      } else if ("close".equals(name) && CLOSE_DESCRIPTOR.equals(descriptor)) {
        hasClose = true;
      } else if ("closeForcibly".equals(name) && "()V".equals(descriptor)) {
        hasCloseForcibly = true;
      }
      return null;
    }

    boolean supportsInstrumentation() {
      return hasOuterChannelField && hasConstructor && hasClose && hasCloseForcibly;
    }
  }

  private static final class NonLoadingClassWriter extends ClassWriter {
    NonLoadingClassWriter(ClassReader reader) {
      super(reader, ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
    }

    @Override
    protected String getCommonSuperClass(String firstType, String secondType) {
      return firstType.equals(secondType) ? firstType : "java/lang/Object";
    }
  }

  private static final class NettySslHandlerVisitor extends ClassVisitor {
    private boolean instrumented;

    NettySslHandlerVisitor(ClassVisitor visitor) {
      super(Opcodes.ASM9, visitor);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor visitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      Type[] argumentTypes = Type.getArgumentTypes(descriptor);
      int argumentCount = argumentTypes.length;
      boolean handlerContext = argumentCount > 0 && argumentTypes[0].getSort() == Type.OBJECT;
      boolean instanceMethod = (access & Opcodes.ACC_STATIC) == 0;
      boolean concreteMethod = (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0;
      if (concreteMethod
          && instanceMethod
          && handlerContext
          && (("unwrap".equals(name) && argumentCount == 3)
              || ("wrap".equals(name) && argumentCount == 2))) {
        instrumented = true;
        return new ScopeAdvice(visitor);
      }
      return visitor;
    }
  }

  private static final class AbstractUnsafeVisitor extends ClassVisitor {
    private boolean instrumented;

    AbstractUnsafeVisitor(ClassVisitor visitor) {
      super(Opcodes.ASM9, visitor);
    }

    @Override
    public MethodVisitor visitMethod(
        int access, String name, String descriptor, String signature, String[] exceptions) {
      MethodVisitor visitor = super.visitMethod(access, name, descriptor, signature, exceptions);
      if (!isConcreteInstanceMethod(access)) {
        return visitor;
      }
      if ("<init>".equals(name)) {
        instrumented = true;
        return new RegisterCloseHookAdvice(visitor);
      }
      boolean terminalClose =
          ("close".equals(name) && CLOSE_DESCRIPTOR.equals(descriptor))
              || ("closeForcibly".equals(name) && "()V".equals(descriptor));
      if (terminalClose) {
        instrumented = true;
        return new CloseChannelAdvice(visitor);
      }
      return visitor;
    }
  }

  private static final class CloseChannelAdvice extends MethodVisitor {
    CloseChannelAdvice(MethodVisitor visitor) {
      super(Opcodes.ASM9, visitor);
    }

    @Override
    public void visitCode() {
      super.visitCode();
      visitVarInsn(Opcodes.ALOAD, 0);
      visitFieldInsn(
          Opcodes.GETFIELD,
          ABSTRACT_UNSAFE_INTERNAL_CLASS_NAME,
          ABSTRACT_UNSAFE_OUTER_CHANNEL_FIELD,
          ABSTRACT_UNSAFE_OUTER_CHANNEL_DESCRIPTOR);
      visitMethodInsn(
          Opcodes.INVOKESTATIC,
          SSL_STORAGE_INTERNAL_CLASS_NAME,
          CLOSE_NETTY_CHANNEL_METHOD,
          CLOSE_NETTY_CHANNEL_DESCRIPTOR,
          false);
    }
  }

  private static final class RegisterCloseHookAdvice extends MethodVisitor {
    RegisterCloseHookAdvice(MethodVisitor visitor) {
      super(Opcodes.ASM9, visitor);
    }

    @Override
    public void visitInsn(int opcode) {
      if (opcode == Opcodes.RETURN) {
        visitVarInsn(Opcodes.ALOAD, 0);
        visitFieldInsn(
            Opcodes.GETFIELD,
            ABSTRACT_UNSAFE_INTERNAL_CLASS_NAME,
            ABSTRACT_UNSAFE_OUTER_CHANNEL_FIELD,
            ABSTRACT_UNSAFE_OUTER_CHANNEL_DESCRIPTOR);
        visitMethodInsn(
            Opcodes.INVOKESTATIC,
            SSL_STORAGE_INTERNAL_CLASS_NAME,
            REGISTER_NETTY_CLOSE_HOOK_METHOD,
            REGISTER_NETTY_CLOSE_HOOK_DESCRIPTOR,
            false);
      }
      super.visitInsn(opcode);
    }
  }

  private static final class ScopeAdvice extends MethodVisitor {
    private final Label scopeStart = new Label();
    private final Label scopeEnd = new Label();
    private final Label scopeFailure = new Label();

    ScopeAdvice(MethodVisitor visitor) {
      super(Opcodes.ASM9, visitor);
    }

    @Override
    public void visitCode() {
      super.visitCode();
      visitVarInsn(Opcodes.ALOAD, 1);
      visitMethodInsn(
          Opcodes.INVOKESTATIC,
          SSL_STORAGE_INTERNAL_CLASS_NAME,
          BEGIN_SCOPE_METHOD,
          BEGIN_SCOPE_DESCRIPTOR,
          false);
      visitLabel(scopeStart);
    }

    @Override
    public void visitInsn(int opcode) {
      if (opcode != Opcodes.ATHROW && isReturn(opcode)) {
        endScope();
      }
      super.visitInsn(opcode);
    }

    @Override
    public void visitMaxs(int maxStack, int maxLocals) {
      visitLabel(scopeEnd);
      visitTryCatchBlock(scopeStart, scopeEnd, scopeFailure, "java/lang/Throwable");
      visitLabel(scopeFailure);
      endScope();
      visitInsn(Opcodes.ATHROW);

      super.visitMaxs(maxStack, maxLocals);
    }

    private static boolean isReturn(int opcode) {
      return opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN;
    }

    private void endScope() {
      visitMethodInsn(
          Opcodes.INVOKESTATIC,
          SSL_STORAGE_INTERNAL_CLASS_NAME,
          END_SCOPE_METHOD,
          END_SCOPE_DESCRIPTOR,
          false);
    }
  }

  private static boolean isConcreteInstanceMethod(int access) {
    return (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_STATIC)) == 0;
  }
}
