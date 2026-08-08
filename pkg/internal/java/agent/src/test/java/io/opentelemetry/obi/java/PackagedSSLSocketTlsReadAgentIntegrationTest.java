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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

class PackagedSSLSocketTlsReadAgentIntegrationTest {
  private static final String KEY_STORE_PASSWORD = "1234567";

  @TempDir Path temporaryDirectory;

  @Test
  @Timeout(value = 150, unit = TimeUnit.SECONDS)
  void packagedAgentFramesApplicationVisibleHttp1AcrossSupportedTlsProtocols() throws Exception {
    File agent = new File(requiredProperty("obi.test.packaged.agent"));
    File probeClasses = new File(requiredProperty("obi.test.late.attach.probe.classes"));
    assertTrue(agent.isFile() && agent.length() > 0, "packaged Java agent is missing");
    assertTrue(probeClasses.isDirectory(), "SSLSocket TLS-read probe classes are missing");

    Path keyStore = temporaryDirectory.resolve("server.p12");
    generateKeyStore(keyStore);
    String agentSha256 = sha256(agent.toPath());

    runProbe(agent, probeClasses, keyStore, agentSha256, "TLSv1.2");
    if (supportsTlsProtocol("TLSv1.3")) {
      runProbe(agent, probeClasses, keyStore, agentSha256, "TLSv1.3");
    } else {
      System.out.println(
          "OBI_SSLSOCKET_TLS_READ\tunsupported\tprotocol=TLSv1.3"
              + "\tscope=unprivileged_component"
              + "\tjava_vendor="
              + clean(System.getProperty("java.vendor"))
              + "\tjava_version="
              + clean(System.getProperty("java.version"))
              + "\treason=not_supported_by_target_jsse");
    }
  }

  private static void runProbe(
      File agent, File probeClasses, Path keyStore, String agentSha256, String protocol)
      throws Exception {
    List<String> command = new ArrayList<>();
    command.add(javaTool("java").getAbsolutePath());
    command.add("-javaagent:" + agent.getAbsolutePath() + "=remoteParentTransport=disabled");
    command.add("-Dobi.test.sslsocket.tls.key.store=" + keyStore.toAbsolutePath());
    command.add("-Dobi.test.sslsocket.tls.key.store.password=" + KEY_STORE_PASSWORD);
    command.add("-Dobi.test.sslsocket.tls.protocol=" + protocol);
    command.add("-Dobi.test.packaged.agent.sha256=" + agentSha256);
    command.add("-cp");
    command.add(probeClasses.getAbsolutePath());
    command.add("io.opentelemetry.obi.java.probe.SSLSocketTlsReadRuntimeProbe");

    String output = run(command, 45, "SSLSocket " + protocol + " TLS-read probe");
    String marker = "OBI_SSLSOCKET_TLS_READ\tpassed\tprotocol=" + protocol + "\t";
    assertTrue(output.contains(marker), output);
    System.out.print(output);
  }

  private static void generateKeyStore(Path keyStore) throws Exception {
    List<String> command = new ArrayList<>();
    command.add(javaTool("keytool").getAbsolutePath());
    command.add("-genkeypair");
    command.add("-alias");
    command.add("obi-sslsocket");
    command.add("-keyalg");
    command.add("RSA");
    command.add("-keysize");
    command.add("2048");
    command.add("-sigalg");
    command.add("SHA256withRSA");
    command.add("-storetype");
    command.add("PKCS12");
    command.add("-keystore");
    command.add(keyStore.toAbsolutePath().toString());
    command.add("-storepass");
    command.add(KEY_STORE_PASSWORD);
    command.add("-keypass");
    command.add(KEY_STORE_PASSWORD);
    command.add("-dname");
    command.add("CN=127.0.0.1");
    command.add("-validity");
    command.add("2");
    command.add("-ext");
    command.add("SAN=IP:127.0.0.1");
    command.add("-noprompt");

    run(command, 30, "SSLSocket TLS-read keytool");
    assertTrue(Files.isRegularFile(keyStore) && Files.size(keyStore) > 0, keyStore.toString());
  }

  private static File javaTool(String name) {
    String executable = isWindows() ? name + ".exe" : name;
    File javaHome = new File(System.getProperty("java.home"));
    File tool = new File(new File(javaHome, "bin"), executable);
    if (!tool.isFile() && javaHome.getParentFile() != null) {
      tool = new File(new File(javaHome.getParentFile(), "bin"), executable);
    }
    assertTrue(tool.isFile(), "missing " + name + " under " + javaHome);
    return tool;
  }

  private static String run(List<String> command, long timeoutSeconds, String label)
      throws Exception {
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    AtomicReference<Throwable> readerFailure = new AtomicReference<>();
    Thread reader = copyOutput(process.getInputStream(), output, readerFailure, label);
    boolean finished = false;
    try {
      finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
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
    assertTrue(!reader.isAlive(), label + " output reader did not stop\n" + text);
    if (readerFailure.get() != null) {
      throw new AssertionError(label + " output reader failed\n" + text, readerFailure.get());
    }
    assertTrue(finished, label + " timed out\n" + text);
    assertEquals(0, process.exitValue(), label + " failed\n" + text);
    return text;
  }

  private static Thread copyOutput(
      InputStream input,
      ByteArrayOutputStream output,
      AtomicReference<Throwable> failure,
      String label) {
    Thread reader =
        new Thread(
            () -> {
              byte[] buffer = new byte[4096];
              int read;
              try {
                while ((read = input.read(buffer)) >= 0) {
                  output.write(buffer, 0, read);
                }
              } catch (Throwable current) {
                failure.compareAndSet(null, current);
              }
            },
            "sslsocket-tls-read-output-" + label.replace(' ', '-'));
    reader.setDaemon(true);
    reader.start();
    return reader;
  }

  private static String sha256(Path path) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (InputStream input = Files.newInputStream(path)) {
      byte[] buffer = new byte[8192];
      int read;
      while ((read = input.read(buffer)) >= 0) {
        digest.update(buffer, 0, read);
      }
    }
    char[] hex = "0123456789abcdef".toCharArray();
    StringBuilder result = new StringBuilder(64);
    for (byte value : digest.digest()) {
      result.append(hex[(value >>> 4) & 0x0f]);
      result.append(hex[value & 0x0f]);
    }
    return result.toString();
  }

  private static String requiredProperty(String name) {
    String value = System.getProperty(name);
    assertTrue(value != null && !value.isEmpty(), "missing system property " + name);
    return value;
  }

  private static boolean supportsTlsProtocol(String expected) throws Exception {
    String[] supported = SSLContext.getDefault().getSupportedSSLParameters().getProtocols();
    for (String protocol : supported) {
      if (expected.equals(protocol)) {
        return true;
      }
    }
    return false;
  }

  private static String clean(String value) {
    return value == null ? "" : value.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
  }

  private static boolean isWindows() {
    return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win");
  }
}
