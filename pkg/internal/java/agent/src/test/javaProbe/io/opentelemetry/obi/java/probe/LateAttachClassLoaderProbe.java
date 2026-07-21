/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.lang.management.ManagementFactory;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

/** Standalone process probe for consumer-before-agent startup and class-loader reclamation. */
public final class LateAttachClassLoaderProbe {
  private static final String BRIDGE_CLASS = "io.opentelemetry.obi.java.bridge.RemoteParentBridge";
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
    if ((Integer) remoteParentStatus.invoke(null) != -1) {
      throw new AssertionError("isolated consumer unexpectedly found the bridge before attachment");
    }

    attachAgent(agentPath);
    Class<?> bridge = Class.forName(BRIDGE_CLASS, true, null);
    if (bridge.getClassLoader() != null) {
      throw new AssertionError("remote-parent bridge is not bootstrap-defined");
    }
    if ((Integer) remoteParentStatus.invoke(null) != STATUS_MISSING) {
      throw new AssertionError("pre-existing isolated consumer did not discover the late bridge");
    }

    WeakReference<ClassLoader> reference = new WeakReference<ClassLoader>(loader);
    remoteParentStatus = null;
    consumer = null;
    loader.close();
    loader = null;
    return reference;
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
