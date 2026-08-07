/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class PackagedBootstrapHttp1AgentIntegrationTest {
  @Test
  void packagedAgentInjectsAndExecutesTheFramedReceiveClosure() throws Exception {
    File agent = new File(requiredProperty("obi.test.packaged.agent"));
    File probeClasses = new File(requiredProperty("obi.test.late.attach.probe.classes"));
    assertTrue(agent.isFile() && agent.length() > 0, "packaged Java agent is missing");
    assertTrue(probeClasses.isDirectory(), "bootstrap HTTP/1 probe classes are missing");

    List<String> command = new ArrayList<>();
    command.add(new File(System.getProperty("java.home"), "bin/java").getAbsolutePath());
    if (javaFeatureVersion() >= 9) {
      command.add("--add-opens=java.base/sun.nio.ch=ALL-UNNAMED");
    }
    command.add("-javaagent:" + agent.getAbsolutePath() + "=remoteParentTransport=disabled");
    command.add("-cp");
    command.add(probeClasses.getAbsolutePath());
    command.add("io.opentelemetry.obi.java.probe.BootstrapHttp1RuntimeProbe");

    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    Thread reader = copyOutput(process.getInputStream(), output);
    try {
      assertTrue(process.waitFor(30, TimeUnit.SECONDS), "bootstrap HTTP/1 probe timed out");
    } finally {
      if (process.isAlive()) {
        process.destroy();
        if (!process.waitFor(2, TimeUnit.SECONDS)) {
          process.destroyForcibly();
          process.waitFor(2, TimeUnit.SECONDS);
        }
      }
      reader.join(TimeUnit.SECONDS.toMillis(5));
    }

    String text = new String(output.toByteArray(), StandardCharsets.UTF_8);
    assertEquals(0, process.exitValue(), text);
    assertTrue(text.contains("bootstrap-http1-agent-probe passed"), text);
  }

  private static Thread copyOutput(InputStream input, ByteArrayOutputStream output) {
    Thread reader =
        new Thread(
            () -> {
              byte[] buffer = new byte[4096];
              int read;
              try {
                while ((read = input.read(buffer)) >= 0) {
                  output.write(buffer, 0, read);
                }
              } catch (Exception failure) {
                throw new AssertionError(failure);
              }
            },
            "bootstrap-http1-probe-output");
    reader.setDaemon(true);
    reader.start();
    return reader;
  }

  private static String requiredProperty(String name) {
    String value = System.getProperty(name);
    assertTrue(value != null && !value.isEmpty(), "missing system property " + name);
    return value;
  }

  private static int javaFeatureVersion() {
    String version = System.getProperty("java.specification.version");
    if (version.startsWith("1.")) {
      return Integer.parseInt(version.substring(2));
    }
    int separator = version.indexOf('.');
    return Integer.parseInt(separator < 0 ? version : version.substring(0, separator));
  }
}
