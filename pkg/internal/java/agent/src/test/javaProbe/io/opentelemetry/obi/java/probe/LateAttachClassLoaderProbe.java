/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.lang.management.ManagementFactory;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLClassLoader;
import javax.net.ssl.SSLEngine;

/** Standalone process probe for consumer-before-agent startup and class-loader reclamation. */
public final class LateAttachClassLoaderProbe {
  private static final String BRIDGE_CLASS = "io.opentelemetry.obi.java.bridge.RemoteParentBridge";
  private static final String CONNECTION_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.Connection";
  private static final String SSL_STORAGE_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.SSLStorage";
  private static final String TLS_MARKER_ATTEMPT_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$TlsConnectionMarkerAttempt";
  private static final String BUFFER_HANDOFF_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$BufferHandoff";
  private static final String CHANNEL_STATE_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$ChannelState";
  private static final String CONNECTION_OWNER_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$ConnectionOwner";
  private static final String EXACT_CONNECTION_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$ExactConnection";
  private static final String NETTY_CONNECTION_SCOPE_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$NettyConnectionScope";
  private static final String NETTY_HANDLER_SCOPE_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$NettyHandlerScope";
  private static final String REMOTE_PARENT_SOCKET_CONTEXT_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext";
  private static final String WEAK_IDENTITY_MAP_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityConcurrentMap";
  private static final String WEAK_IDENTITY_REFERENCE_CLASS =
      "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityConcurrentMap$IdentityWeakReference";
  private static final int STATUS_MISSING = 2;

  private LateAttachClassLoaderProbe() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      throw new IllegalArgumentException("expected the packaged agent path");
    }
    if (bootstrapBridgeAvailable()) {
      throw new AssertionError("bridge unexpectedly available before agent attachment");
    }

    WeakReference<ClassLoader> loader = exerciseStartupOrder(args[0]);
    awaitCollection(loader);

    Class<?> bridge = Class.forName(BRIDGE_CLASS, true, null);
    if (bridge.getClassLoader() != null || bridgeStatus(bridge) != STATUS_MISSING) {
      throw new AssertionError("bootstrap bridge did not survive isolated class-loader GC");
    }
    System.out.println("late-attach-classloader-probe passed");
  }

  private static WeakReference<ClassLoader> exerciseStartupOrder(String agentPath)
      throws Exception {
    URL classes =
        LateAttachClassLoaderProbe.class.getProtectionDomain().getCodeSource().getLocation();
    URLClassLoader loader = new URLClassLoader(new URL[] {classes}, null);
    Class<?> consumer =
        Class.forName("io.opentelemetry.obi.java.probe.IsolatedBridgeConsumer", true, loader);
    Method remoteParentStatus = consumer.getMethod("remoteParentStatus");
    Method newEngine = consumer.getMethod("newEngine");
    SSLEngine engine = (SSLEngine) newEngine.invoke(null);
    if ((Integer) remoteParentStatus.invoke(null) != -1) {
      throw new AssertionError("isolated consumer unexpectedly found the bridge before attachment");
    }

    attachAgent(agentPath);
    Class<?> bridge = Class.forName(BRIDGE_CLASS, true, null);
    if (bridge.getClassLoader() != null) {
      throw new AssertionError("remote-parent bridge is not bootstrap-defined");
    }
    assertBootstrapClass(TLS_MARKER_ATTEMPT_CLASS);
    assertBootstrapClass(BUFFER_HANDOFF_CLASS);
    assertBootstrapClass(CHANNEL_STATE_CLASS);
    assertBootstrapClass(CONNECTION_OWNER_CLASS);
    assertBootstrapClass(EXACT_CONNECTION_CLASS);
    assertBootstrapClass(NETTY_CONNECTION_SCOPE_CLASS);
    assertBootstrapClass(NETTY_HANDLER_SCOPE_CLASS);
    assertBootstrapClass(REMOTE_PARENT_SOCKET_CONTEXT_CLASS);
    assertBootstrapClass(WEAK_IDENTITY_MAP_CLASS);
    assertBootstrapClass(WEAK_IDENTITY_REFERENCE_CLASS);
    if ((Integer) remoteParentStatus.invoke(null) != STATUS_MISSING) {
      throw new AssertionError("pre-existing isolated consumer did not discover the late bridge");
    }
    cacheEngineInBootstrapStorage(engine);

    WeakReference<ClassLoader> reference = new WeakReference<ClassLoader>(loader);
    engine = null;
    newEngine = null;
    remoteParentStatus = null;
    consumer = null;
    loader.close();
    loader = null;
    return reference;
  }

  private static void cacheEngineInBootstrapStorage(SSLEngine engine) throws Exception {
    Class<?> connectionClass = Class.forName(CONNECTION_CLASS, true, null);
    Object connection =
        connectionClass
            .getConstructor(InetAddress.class, int.class, InetAddress.class, int.class, int.class)
            .newInstance(
                InetAddress.getLoopbackAddress(), 1234, InetAddress.getLoopbackAddress(), 5678, 7);
    Class<?> storage = Class.forName(SSL_STORAGE_CLASS, true, null);
    Object physicalOwner = new Object();
    Object associated =
        storage
            .getMethod("associateConnectionWithChannel", Object.class, connectionClass)
            .invoke(null, physicalOwner, connection);
    if (associated != connection) {
      throw new AssertionError("bootstrap helper did not bind the TLS connection to its transport");
    }
    storage
        .getMethod("setConnectionForSession", SSLEngine.class, connectionClass)
        .invoke(null, engine, connection);
    Object cached =
        storage.getMethod("getConnectionForSession", SSLEngine.class).invoke(null, engine);
    if (cached != connection) {
      throw new AssertionError("isolated TLS engine was not cached by the bootstrap helper");
    }

    storage.getMethod("beginNettyConnectionScope").invoke(null);
    try {
      if (!(Boolean)
          storage.getMethod("setCurrentNettyConnection", Object.class).invoke(null, connection)) {
        throw new AssertionError("bootstrap helper did not install the Netty connection scope");
      }
      if (storage.getMethod("currentScopedConnection").invoke(null) != connection) {
        throw new AssertionError("bootstrap helper did not resolve the Netty connection scope");
      }
    } finally {
      storage.getMethod("endNettyConnectionScope").invoke(null);
    }
    Method claimMarker =
        storage.getMethod(
            "claimTlsConnectionMarkerAttempt", SSLEngine.class, connectionClass, long.class);
    for (int attempt = 0; attempt < 8; attempt++) {
      boolean claimed = (Boolean) claimMarker.invoke(null, engine, connection, 11L);
      if (!claimed) {
        throw new AssertionError("isolated TLS engine marker burst ended early");
      }
    }
    if ((Boolean) claimMarker.invoke(null, engine, connection, 11L)) {
      throw new AssertionError("isolated TLS engine marker was not cached by the bootstrap helper");
    }
  }

  private static void attachAgent(String agentPath) throws Exception {
    String runtimeName = ManagementFactory.getRuntimeMXBean().getName();
    String processId = runtimeName.substring(0, runtimeName.indexOf('@'));
    Class<?> virtualMachine = Class.forName("com.sun.tools.attach.VirtualMachine");
    Object attached = virtualMachine.getMethod("attach", String.class).invoke(null, processId);
    try {
      virtualMachine
          .getMethod("loadAgent", String.class, String.class)
          .invoke(attached, agentPath, "remoteParentTransport=disabled");
    } finally {
      virtualMachine.getMethod("detach").invoke(attached);
    }
  }

  private static void assertBootstrapClass(String className) throws Exception {
    if (Class.forName(className, false, null).getClassLoader() != null) {
      throw new AssertionError(className + " is not bootstrap-defined");
    }
  }

  private static boolean bootstrapBridgeAvailable() {
    try {
      Class.forName(BRIDGE_CLASS, false, null);
      return true;
    } catch (ClassNotFoundException expected) {
      return false;
    }
  }

  private static int bridgeStatus(Class<?> bridge) throws Exception {
    Object record = bridge.getMethod("takeRemoteParent").invoke(null);
    return (Integer) record.getClass().getMethod("getStatus").invoke(record);
  }

  private static void awaitCollection(WeakReference<ClassLoader> reference) throws Exception {
    for (int attempt = 0; attempt < 200 && reference.get() != null; attempt++) {
      System.gc();
      System.runFinalization();
      byte[][] pressure = new byte[4][];
      for (int index = 0; index < pressure.length; index++) {
        pressure[index] = new byte[256 * 1024];
      }
      Thread.sleep(25);
    }
    if (reference.get() != null) {
      throw new AssertionError("isolated application class loader was retained");
    }
  }
}
