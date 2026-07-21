/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import java.io.*;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;

public class Loader {
  private static Class<?> agentClass;
  private static URLClassLoader agentClassLoader;

  public static void agentCaller(String function, String agentArgs, Instrumentation inst) {
    try {
      Class<?> mainClass = loadAgentClass();
      java.lang.reflect.Method mainMethod =
          mainClass.getMethod(function, String.class, Instrumentation.class);
      mainMethod.invoke(null, agentArgs, inst);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static synchronized Class<?> loadAgentClass() throws Exception {
    if (agentClass != null) {
      return agentClass;
    }

    String agentResourcePath = "agent/agent.zip";
    File tempAgentJar;
    try (InputStream agentJarStream =
        Loader.class.getClassLoader().getResourceAsStream(agentResourcePath)) {
      if (agentJarStream == null) {
        throw new FileNotFoundException("Resource not found: " + agentResourcePath);
      }

      tempAgentJar = Files.createTempFile("agent", ".jar").toFile();
      try (OutputStream out = Files.newOutputStream(tempAgentJar.toPath())) {
        byte[] buffer = new byte[8192];
        int len;
        while ((len = agentJarStream.read(buffer)) != -1) {
          out.write(buffer, 0, len);
        }
      }
    }

    URLClassLoader loader =
        new URLClassLoader(new URL[] {tempAgentJar.toURI().toURL()}, Loader.class.getClassLoader());
    try {
      agentClass = loader.loadClass("io.opentelemetry.obi.java.Agent");
      agentClassLoader = loader;
      tempAgentJar.deleteOnExit();
      return agentClass;
    } catch (Exception failure) {
      loader.close();
      if (!tempAgentJar.delete()) {
        tempAgentJar.deleteOnExit();
      }
      throw failure;
    }
  }

  public static void premain(String agentArgs, Instrumentation inst) {
    agentCaller("premain", agentArgs, inst);
  }

  public static void agentmain(String args, Instrumentation inst) {
    agentCaller("agentmain", args, inst);
  }

  // Just a test method functionality, not used in the Agent
  public static void main(String[] args) {
    premain(null, null);
  }
}
