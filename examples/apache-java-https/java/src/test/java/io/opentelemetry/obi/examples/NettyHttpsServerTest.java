// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

@Timeout(20)
class NettyHttpsServerTest {
  private static final String KEYSTORE_PASSWORD = "netty-test";

  @TempDir static Path temporaryDirectory;

  private static Path keyStore;

  @BeforeAll
  static void createKeyStore() throws Exception {
    keyStore = temporaryDirectory.resolve("netty.p12");
    String executable =
        Path.of(
                System.getProperty("java.home"),
                "bin",
                isWindows() ? "keytool.exe" : "keytool")
            .toString();
    Process process =
        new ProcessBuilder(
                executable,
                "-genkeypair",
                "-alias",
                "netty",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-storetype",
                "PKCS12",
                "-keystore",
                keyStore.toString(),
                "-storepass",
                KEYSTORE_PASSWORD,
                "-keypass",
                KEYSTORE_PASSWORD,
                "-dname",
                "CN=localhost",
                "-ext",
                "SAN=ip:127.0.0.1",
                "-validity",
                "2",
                "-noprompt")
            .redirectErrorStream(true)
            .start();
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (InputStream input = process.getInputStream()) {
      input.transferTo(output);
    }
    assertTrue(process.waitFor(30, TimeUnit.SECONDS), "keytool timed out");
    assertEquals(0, process.exitValue(), output.toString(StandardCharsets.UTF_8));
  }

  @Test
  void servesValidatedRequestsOverTls() throws Exception {
    for (String protocol : List.of("TLSv1.2", "TLSv1.3")) {
      try (NettyHttpsServer server = start(protocol)) {
        String response = request(server, protocol, "netty-marker");

        assertTrue(response.startsWith("HTTP/1.1 200 "), response);
        assertTrue(response.contains("\"marker\":\"netty-marker\""), response);
        assertTrue(response.contains("\"secure\":true"), response);
        assertTrue(response.contains("\"tls_protocol\":\"" + protocol + "\""), response);
        assertTrue(response.contains("\"backend_kind\":\"netty\""), response);
        assertTrue(response.matches("(?s).*\"backend_connection_id\":[1-9][0-9]*.*"), response);
        assertTrue(response.matches("(?s).*\"backend_remote_port\":[1-9][0-9]*.*"), response);
      }
    }
  }

  @Test
  void rejectsRequestsWithoutTheRequiredMarker() throws Exception {
    try (NettyHttpsServer server = start("TLSv1.3")) {
      String response = request(server, "TLSv1.3", null);

      assertTrue(response.startsWith("HTTP/1.1 400 "), response);
    }
  }

  @Test
  void rejectsRequestsWithAnInvalidMarker() throws Exception {
    try (NettyHttpsServer server = start("TLSv1.3")) {
      String response = request(server, "TLSv1.3", "not a valid marker");

      assertTrue(response.startsWith("HTTP/1.1 400 "), response);
    }
  }

  @Test
  void rejectsAClientThatOnlyOffersAnotherTlsVersion() throws Exception {
    try (NettyHttpsServer server = start("TLSv1.2")) {
      assertThrows(IOException.class, () -> connect(server, "TLSv1.3"));
    }
  }

  @Test
  void closeIsIdempotent() throws Exception {
    NettyHttpsServer server = start("TLSv1.3");

    server.close();
    server.close();

    assertTrue(server.isTerminated());
  }

  private static NettyHttpsServer start(String protocol) throws Exception {
    return NettyHttpsServer.start(0, keyStore, KEYSTORE_PASSWORD, protocol);
  }

  private static String request(NettyHttpsServer server, String protocol, String marker)
      throws Exception {
    TlsContextFactory.Contexts contexts =
        TlsContextFactory.load(keyStore, KEYSTORE_PASSWORD, protocol);
    try (SSLSocket socket = (SSLSocket) contexts.clientSocketFactory().createSocket()) {
      connect(server, socket, protocol);
      String headers = marker == null ? "" : "X-OBI-Demo-ID: " + marker + "\r\n";
      String request =
          "GET "
              + NettyHttpsServer.API_PATH
              + " HTTP/1.1\r\nHost: localhost\r\n"
              + headers
              + "Connection: close\r\n\r\n";
      OutputStream output = socket.getOutputStream();
      output.write(request.getBytes(StandardCharsets.US_ASCII));
      output.flush();
      return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static void connect(NettyHttpsServer server, String protocol) throws Exception {
    TlsContextFactory.Contexts contexts =
        TlsContextFactory.load(keyStore, KEYSTORE_PASSWORD, protocol);
    try (SSLSocket socket = (SSLSocket) contexts.clientSocketFactory().createSocket()) {
      connect(server, socket, protocol);
    }
  }

  private static void connect(NettyHttpsServer server, SSLSocket socket, String protocol)
      throws IOException {
    socket.setEnabledProtocols(new String[] {protocol});
    socket.connect(new InetSocketAddress("127.0.0.1", server.port()), 5_000);
    socket.startHandshake();
  }

  private static boolean isWindows() {
    return File.separatorChar == '\\';
  }
}
