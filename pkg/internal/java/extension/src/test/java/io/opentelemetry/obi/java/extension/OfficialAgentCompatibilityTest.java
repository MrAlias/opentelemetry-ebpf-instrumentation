/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

class OfficialAgentCompatibilityTest {
  @Test
  void unmodifiedOpenTelemetryAgentLoadsTheExternalExtension() throws Exception {
    verifyAgent("OBI_TEST_OTEL_AGENT", "distribution=opentelemetry", "agent_version=2.28.1");
  }

  @Test
  void unmodifiedSplunkAgentLoadsTheExternalExtension() throws Exception {
    verifyAgent(
        "OBI_TEST_SPLUNK_AGENT", "distribution=splunk", "agent_version=splunk-2.28.0-otel-2.28.1");
  }

  private static void verifyAgent(String environmentName, String distribution, String version)
      throws Exception {
    String agentPath = System.getenv(environmentName);
    Assumptions.assumeTrue(
        agentPath != null && !agentPath.isEmpty(), environmentName + " is unset");

    File agent = new File(agentPath);
    File extension = new File(requiredProperty("obi.test.extension.jar"));
    assertTrue(agent.isFile() && agent.length() > 0, "official agent is missing: " + agent);
    assertTrue(
        extension.isFile() && extension.length() > 0, "OBI extension is missing: " + extension);
    String extensionVersion;
    try (JarFile extensionJar = new JarFile(extension)) {
      extensionVersion =
          extensionJar.getManifest().getMainAttributes().getValue("Implementation-Version");
    }
    assertTrue(
        extensionVersion != null && !extensionVersion.isEmpty(),
        "OBI extension version is missing");

    List<String> command = new ArrayList<>();
    command.add(new File(System.getProperty("java.home"), "bin/java").getAbsolutePath());
    command.add("-javaagent:" + agent.getAbsolutePath());
    command.add("-Dotel.javaagent.extensions=" + extension.getAbsolutePath());
    command.add("-Dotel.propagators=obi,tracecontext,baggage");
    command.add("-Dotel.traces.exporter=none");
    command.add("-Dotel.metrics.exporter=none");
    command.add("-Dotel.logs.exporter=none");

    String text = runAgent(command, true);
    assertTrue(text.contains("OBI remote-parent compatibility"), text);
    assertTrue(text.contains(distribution), text);
    assertTrue(text.contains(version), text);
    assertTrue(text.contains("api_version=1.62.0"), text);
    assertTrue(text.contains("api_version_source=agent_spi_alignment"), text);
    assertTrue(text.contains("spi_version=1.62.0"), text);
    assertTrue(text.contains("extension_version=" + extensionVersion), text);
    assertTrue(text.contains("provider=obi,supported=true,reason=compatible"), text);
    assertTrue(text.contains("OBI remote-parent propagator enabled"), text);
    assertTrue(text.contains("api_loader=bootstrap"), text);
    assertTrue(
        text.contains("spi_loader=io.opentelemetry.javaagent.bootstrap.AgentClassLoader"), text);
    assertTrue(
        text.contains("extension_loader=io.opentelemetry.javaagent.tooling.ExtensionClassLoader"),
        text);
    assertFalse(text.contains("OBI remote-parent propagator disabled by compatibility gate"), text);
    assertFalse(text.contains("OBI remote-parent propagator disabled by configuration"), text);

    String disabledText = runAgent(command, false);
    assertTrue(disabledText.contains("OBI remote-parent compatibility"), disabledText);
    assertTrue(
        disabledText.contains("provider=obi,supported=true,reason=compatible"), disabledText);
    assertTrue(
        disabledText.contains("OBI remote-parent propagator disabled by configuration"),
        disabledText);
    assertFalse(disabledText.contains("OBI remote-parent propagator enabled"), disabledText);
    assertFalse(
        disabledText.contains("OBI remote-parent propagator disabled by compatibility gate"),
        disabledText);
  }

  private static String runAgent(List<String> baseCommand, boolean enabled) throws Exception {
    List<String> command = new ArrayList<>(baseCommand);
    command.add("-Dotel.obi.remote.parent.enabled=" + enabled);
    command.add("-version");

    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    Thread reader = copyOutput(process.getInputStream(), output);
    try {
      assertTrue(process.waitFor(30, TimeUnit.SECONDS), "official agent smoke test timed out");
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
    return text;
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
            "official-agent-compatibility-output");
    reader.setDaemon(true);
    reader.start();
    return reader;
  }

  private static String requiredProperty(String name) {
    String value = System.getProperty(name);
    assertTrue(value != null && !value.isEmpty(), "missing system property " + name);
    return value;
  }
}
