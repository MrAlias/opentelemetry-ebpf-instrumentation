/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/** Exercises the primary remote-parent bridge through a real directly owned JSSE receive. */
public final class RemoteParentDirectSSLSocketProbe {
  private static final byte[] REQUEST =
      ascii(
          "GET /direct-jsse-bpf HTTP/1.1\r\n"
              + "Host: 127.0.0.1\r\n"
              + "Connection: close\r\n\r\n");

  private RemoteParentDirectSSLSocketProbe() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      throw new IllegalArgumentException("expected TLS protocol, key store, and password");
    }

    String requestedProtocol = args[0];
    File keyStoreFile = new File(args[1]);
    char[] password = args[2].toCharArray();
    require(keyStoreFile.isFile() && keyStoreFile.length() > 0, "missing TLS key store");

    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream input = new FileInputStream(keyStoreFile)) {
      keyStore.load(input, password);
    }
    Certificate certificate = firstKeyCertificate(keyStore);
    require(certificate != null, "missing server certificate");

    KeyManagerFactory keyManagers =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagers.init(keyStore, password);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(keyManagers.getKeyManagers(), null, new SecureRandom());

    Class<?> nativeBridge = Class.forName("io.opentelemetry.obi.java.BootstrapNative", true, null);
    Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
    Method socketFileDescriptor = nativeBridge.getMethod("socketFileDescriptor", Socket.class);
    Method directSocketFileDescriptor =
        nativeBridge.getMethod("directSocketFileDescriptor", Socket.class);
    Method currentSocketLifecycle =
        nativeBridge.getMethod("currentRemoteParentSocketLifecycle", Socket.class);
    Method gettid = nativeBridge.getMethod("gettid");
    Method retainedSocketFileDescriptor = threadInfo.getMethod("remoteParentSocketFileDescriptor");
    Method lookupSource = threadInfo.getMethod("remoteParentLookupSource");
    BufferedReader commands =
        new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    InetAddress loopback = InetAddress.getByName("127.0.0.1");
    try (SSLServerSocket listener =
        (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 8, loopback)) {
      listener.setEnabledProtocols(new String[] {requestedProtocol});
      listener.setSoTimeout(10_000);
      System.out.println(
          "LISTEN port="
              + listener.getLocalPort()
              + " protocol="
              + requestedProtocol
              + " certSha256="
              + sha256(certificate.getEncoded())
              + " requestBytes="
              + REQUEST.length
              + " requestSha256="
              + sha256(REQUEST));

      try (SSLSocket socket = (SSLSocket) listener.accept()) {
        socket.setUseClientMode(false);
        socket.setEnabledProtocols(new String[] {requestedProtocol});
        socket.setSoTimeout(10_000);
        socket.startHandshake();
        require(
            requestedProtocol.equals(socket.getSession().getProtocol()),
            "negotiated TLS protocol changed");

        int descriptor = intValue(socketFileDescriptor.invoke(null, socket));
        int directDescriptor = intValue(directSocketFileDescriptor.invoke(null, socket));
        require(descriptor >= 0, "accepted JSSE socket has no descriptor");
        require(descriptor == directDescriptor, "accepted JSSE socket is not its direct owner");
        int tid = intValue(gettid.invoke(null));
        require(tid > 0, "native thread identity is unavailable");
        require(
            currentSocketLifecycle.invoke(null, socket) == null,
            "TLS handshake created an application receive generation");
        require(
            intValue(retainedSocketFileDescriptor.invoke(null)) == -1,
            "TLS handshake retained a receive socket descriptor");

        System.out.println(
            "READY tid="
                + tid
                + " fd="
                + descriptor
                + " directFd="
                + directDescriptor
                + " protocol="
                + socket.getSession().getProtocol()
                + " cipher="
                + socket.getSession().getCipherSuite());

        awaitCommand(commands, "READ");
        byte[] received = new byte[REQUEST.length];
        int offset = 0;
        int reads = 0;
        InputStream input = socket.getInputStream();
        while (offset < received.length) {
          int count = input.read(received, offset, received.length - offset);
          require(count > 0, "unexpected EOF while reading TLS plaintext");
          offset += count;
          reads++;
        }
        require(Arrays.equals(REQUEST, received), "application-visible HTTP request changed");
        require(
            currentSocketLifecycle.invoke(null, socket) != null,
            "application read created no receive generation");

        int descriptorBeforeTake = intValue(retainedSocketFileDescriptor.invoke(null));
        int sourceBeforeTake = intValue(lookupSource.invoke(null));
        require(descriptorBeforeTake == directDescriptor, "native ACK did not retain direct FD");
        require(sourceBeforeTake == 1, "native ACK did not establish direct lookup authority");
        System.out.println(
            "ACK fdBeforeTake="
                + descriptorBeforeTake
                + " lookupSource="
                + sourceBeforeTake
                + " bytes="
                + received.length
                + " reads="
                + reads
                + " requestSha256="
                + sha256(received));

        awaitCommand(commands, "TAKE");
        Object record =
            Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", true, null)
                .getMethod("takeRemoteParent")
                .invoke(null);
        int status = intValue(record.getClass().getMethod("getStatus").invoke(record));
        int flags = intValue(record.getClass().getMethod("getTraceFlags").invoke(record));
        String traceId = stringValue(record.getClass().getMethod("getTraceIdHex").invoke(record));
        String parentSpanId =
            stringValue(record.getClass().getMethod("getParentSpanIdHex").invoke(record));
        long generation = longValue(record.getClass().getMethod("getGeneration").invoke(record));
        long observed =
            longValue(record.getClass().getMethod("getObservedMonotonicNanos").invoke(record));
        int descriptorAfterTake = intValue(retainedSocketFileDescriptor.invoke(null));
        System.out.println(
            "RESULT status="
                + status
                + " flags="
                + flags
                + " trace="
                + traceId
                + " span="
                + parentSpanId
                + " generation="
                + Long.toUnsignedString(generation)
                + " observed="
                + Long.toUnsignedString(observed)
                + " fdAfter="
                + descriptorAfterTake);
      }
    }
  }

  private static Certificate firstKeyCertificate(KeyStore keyStore) throws Exception {
    Enumeration<String> aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      if (keyStore.isKeyEntry(alias)) {
        return keyStore.getCertificate(alias);
      }
    }
    return null;
  }

  private static void awaitCommand(BufferedReader input, String expected) throws Exception {
    String command = input.readLine();
    if (!expected.equals(command)) {
      throw new IllegalStateException("expected " + expected + " command");
    }
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static String sha256(byte[] value) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
    char[] alphabet = "0123456789abcdef".toCharArray();
    char[] result = new char[digest.length * 2];
    for (int index = 0; index < digest.length; index++) {
      int current = digest[index] & 0xff;
      result[index * 2] = alphabet[current >>> 4];
      result[index * 2 + 1] = alphabet[current & 0x0f];
    }
    return new String(result);
  }

  private static int intValue(Object value) {
    return ((Number) value).intValue();
  }

  private static long longValue(Object value) {
    return ((Number) value).longValue();
  }

  private static String stringValue(Object value) {
    return value == null ? "-" : value.toString();
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new IllegalStateException(message);
    }
  }
}
