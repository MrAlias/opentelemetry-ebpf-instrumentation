/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/** Exercises a real stock-JSSE handshake and application-visible HTTP/1 receive. */
public final class SSLSocketTlsReadRuntimeProbe {
  private static final String KEY_STORE_PROPERTY = "obi.test.sslsocket.tls.key.store";
  private static final String KEY_STORE_PASSWORD_PROPERTY =
      "obi.test.sslsocket.tls.key.store.password";
  private static final String PROTOCOL_PROPERTY = "obi.test.sslsocket.tls.protocol";
  private static final String AGENT_SHA256_PROPERTY = "obi.test.packaged.agent.sha256";
  private static final String KEY_ALIAS = "obi-sslsocket";
  private static final byte[] REQUEST_FIRST = ascii("GET /direct-jsse HTTP/1.1\r\nHo");
  private static final byte[] REQUEST_SECOND = ascii("st: 127.0.0.1\r\nConnection: close\r\n\r\n");

  private SSLSocketTlsReadRuntimeProbe() {}

  public static void main(String[] args) throws Exception {
    String protocol = requiredProperty(PROTOCOL_PROPERTY);
    String agentSha256 = requiredProperty(AGENT_SHA256_PROPERTY);
    char[] password = requiredProperty(KEY_STORE_PASSWORD_PROPERTY).toCharArray();
    File keyStoreFile = new File(requiredProperty(KEY_STORE_PROPERTY));
    require(keyStoreFile.isFile() && keyStoreFile.length() > 0, "missing TLS key store");

    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream input = new FileInputStream(keyStoreFile)) {
      keyStore.load(input, password);
    }
    Certificate serverCertificate = keyStore.getCertificate(KEY_ALIAS);
    require(serverCertificate != null, "missing server certificate");

    KeyManagerFactory keyManagers =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagers.init(keyStore, password);
    SSLContext serverContext = SSLContext.getInstance("TLS");
    serverContext.init(keyManagers.getKeyManagers(), null, new SecureRandom());

    KeyStore trustStore = KeyStore.getInstance("JKS");
    trustStore.load(null, null);
    trustStore.setCertificateEntry(KEY_ALIAS, serverCertificate);
    TrustManagerFactory trustManagers =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagers.init(trustStore);
    SSLContext clientContext = SSLContext.getInstance("TLS");
    clientContext.init(null, trustManagers.getTrustManagers(), new SecureRandom());

    Class<?> bootstrapNative =
        Class.forName("io.opentelemetry.obi.java.BootstrapNative", true, null);
    Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
    Class<?> remoteParentBootstrap =
        Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBootstrap", true, null);
    Class<?> receiveContext =
        Class.forName(
            "io.opentelemetry.obi.java.instrumentations.data."
                + "RemoteParentSocketContext$ReceiveContext",
            true,
            null);

    Method socketFileDescriptor = bootstrapNative.getMethod("socketFileDescriptor", Socket.class);
    Method directSocketFileDescriptor =
        bootstrapNative.getMethod("directSocketFileDescriptor", Socket.class);
    Method currentSocketLifecycle =
        bootstrapNative.getMethod("currentRemoteParentSocketLifecycle", Socket.class);
    Method setRemoteParentEnabled = threadInfo.getMethod("setRemoteParentEnabled", boolean.class);
    Method advanceBridgeEpoch = threadInfo.getMethod("advanceRemoteParentBridgeEpoch");
    Method lookupSource = threadInfo.getMethod("remoteParentLookupSource");
    Method takeReceiveContext = threadInfo.getMethod("takeRemoteParentReceiveContext");
    Method finishExtraction =
        threadInfo.getMethod("finishRemoteParentExtractionAndValidate", receiveContext);
    Method remoteParentSocketFileDescriptor =
        threadInfo.getMethod("remoteParentSocketFileDescriptor");
    Method tlsReadEvents = remoteParentBootstrap.getMethod("tlsReadEvents");
    Method tlsReadBytes = remoteParentBootstrap.getMethod("tlsReadBytes");

    CountDownLatch clientHandshakeComplete = new CountDownLatch(1);
    CountDownLatch allowFirstWrite = new CountDownLatch(1);
    CountDownLatch firstWritten = new CountDownLatch(1);
    CountDownLatch firstRead = new CountDownLatch(1);
    CountDownLatch secondWritten = new CountDownLatch(1);
    CountDownLatch serverDone = new CountDownLatch(1);
    ExecutorService executor =
        Executors.newSingleThreadExecutor(
            new ThreadFactory() {
              @Override
              public Thread newThread(Runnable task) {
                Thread thread = new Thread(task, "sslsocket-tls-read-client");
                thread.setDaemon(true);
                return thread;
              }
            });
    Future<ClientObservation> client = null;
    InetAddress loopback = InetAddress.getByName("127.0.0.1");

    setRemoteParentEnabled.invoke(null, false);
    advanceBridgeEpoch.invoke(null);
    try (SSLServerSocket listener =
        (SSLServerSocket)
            serverContext.getServerSocketFactory().createServerSocket(0, 8, loopback)) {
      listener.setEnabledProtocols(new String[] {protocol});
      listener.setSoTimeout(10_000);
      int port = listener.getLocalPort();
      client =
          executor.submit(
              client(
                  clientContext,
                  loopback,
                  port,
                  protocol,
                  clientHandshakeComplete,
                  allowFirstWrite,
                  firstWritten,
                  firstRead,
                  secondWritten,
                  serverDone));

      try (SSLSocket socket = (SSLSocket) listener.accept()) {
        socket.setUseClientMode(false);
        socket.setEnabledProtocols(new String[] {protocol});
        socket.setSoTimeout(10_000);

        long eventsBeforeHandshake = number(tlsReadEvents.invoke(null));
        long bytesBeforeHandshake = number(tlsReadBytes.invoke(null));
        socket.startHandshake();
        await(clientHandshakeComplete, "client handshake");
        require(protocol.equals(socket.getSession().getProtocol()), "server protocol mismatch");
        require(
            number(tlsReadEvents.invoke(null)) == eventsBeforeHandshake,
            "TLS handshake was counted as an application read");
        require(
            number(tlsReadBytes.invoke(null)) == bytesBeforeHandshake,
            "TLS handshake bytes were counted as application plaintext");
        require(takeReceiveContext.invoke(null) == null, "handshake published a receive context");
        require(
            currentSocketLifecycle.invoke(null, socket) == null,
            "TLS handshake created an application receive generation");
        require(
            number(remoteParentSocketFileDescriptor.invoke(null)) == -1L,
            "TLS handshake retained a receive socket descriptor");

        int descriptor = descriptor(socketFileDescriptor, socket);
        require(descriptor >= 0, "accepted JSSE socket has no descriptor");
        require(
            descriptor(directSocketFileDescriptor, socket) == descriptor,
            "accepted JSSE socket was not classified as its direct owner");

        setRemoteParentEnabled.invoke(null, true);
        long eventsBeforeRead = number(tlsReadEvents.invoke(null));
        long bytesBeforeRead = number(tlsReadBytes.invoke(null));
        allowFirstWrite.countDown();
        await(firstWritten, "first request fragment");

        InputStream input = socket.getInputStream();
        ReadResult first = readExact(input, REQUEST_FIRST.length);
        require(Arrays.equals(REQUEST_FIRST, first.bytes), "first plaintext fragment changed");
        require(
            takeReceiveContext.invoke(null) == null,
            "incomplete HTTP/1 headers published a receive context");
        Object receiveLifecycle = currentSocketLifecycle.invoke(null, socket);
        require(receiveLifecycle != null, "first plaintext read created no receive generation");
        firstRead.countDown();
        await(secondWritten, "second request fragment");

        ReadResult second = readExact(input, REQUEST_SECOND.length);
        require(Arrays.equals(REQUEST_SECOND, second.bytes), "second plaintext fragment changed");
        int applicationReads = first.calls + second.calls;
        int applicationBytes = first.bytes.length + second.bytes.length;
        long eventDelta = number(tlsReadEvents.invoke(null)) - eventsBeforeRead;
        long byteDelta = number(tlsReadBytes.invoke(null)) - bytesBeforeRead;
        require(eventDelta == applicationReads, "TLS read event count duplicated or missed a read");
        require(byteDelta == applicationBytes, "TLS read byte count changed application bytes");
        require(
            number(lookupSource.invoke(null)) == 1L, "receive did not establish direct authority");
        require(
            number(remoteParentSocketFileDescriptor.invoke(null)) == -1L,
            "unacknowledged receive retained a socket descriptor");

        Object context = takeReceiveContext.invoke(null);
        require(context != null, "complete HTTP/1 headers did not publish a receive context");
        require(
            takeReceiveContext.invoke(null) == null,
            "complete HTTP/1 headers published more than one receive context");
        require(
            number(context.getClass().getMethod("requestSequence").invoke(context)) == 1L,
            "unexpected request sequence");
        require(
            context.getClass().getMethod("lifecycle").invoke(context) == receiveLifecycle,
            "receive context lost its exact socket lifecycle");
        require(
            currentSocketLifecycle.invoke(null, socket) == receiveLifecycle,
            "socket receive generation changed across split headers");
        require(
            Boolean.TRUE.equals(finishExtraction.invoke(null, context)),
            "receive context was not valid before extraction");
        require(
            number(lookupSource.invoke(null)) == 3L, "extraction did not consume direct authority");

        ClientObservation clientObservation;
        serverDone.countDown();
        try {
          clientObservation = client.get(15, TimeUnit.SECONDS);
        } finally {
          serverDone.countDown();
        }
        require(protocol.equals(clientObservation.protocol), "client protocol mismatch");
        require(
            socket.getSession().getCipherSuite().equals(clientObservation.cipher),
            "client and server cipher mismatch");

        System.out.println(
            "OBI_SSLSOCKET_TLS_READ\tpassed\tprotocol="
                + clean(protocol)
                + "\tscope=unprivileged_component"
                + "\tremote_parent_transport=disabled"
                + "\tbridge_enablement=reflective_test_override"
                + "\tebpf=not_asserted"
                + "\tcipher="
                + clean(socket.getSession().getCipherSuite())
                + "\tjava_vendor="
                + clean(System.getProperty("java.vendor"))
                + "\tjava_version="
                + clean(System.getProperty("java.version"))
                + "\tos="
                + clean(System.getProperty("os.name"))
                + "\tkernel="
                + clean(System.getProperty("os.version"))
                + "\tarch="
                + clean(System.getProperty("os.arch"))
                + "\tagent_sha256="
                + clean(agentSha256)
                + "\tagent_sha256_source=launcher"
                + "\tdirect_fd="
                + descriptor
                + "\treads="
                + applicationReads
                + "\tbytes="
                + applicationBytes
                + "\tnative_ack=absent");
      }
    } finally {
      allowFirstWrite.countDown();
      firstWritten.countDown();
      firstRead.countDown();
      secondWritten.countDown();
      serverDone.countDown();
      if (client != null && !client.isDone()) {
        client.cancel(true);
      }
      executor.shutdownNow();
      executor.awaitTermination(5, TimeUnit.SECONDS);
      setRemoteParentEnabled.invoke(null, false);
      advanceBridgeEpoch.invoke(null);
    }
  }

  private static Callable<ClientObservation> client(
      SSLContext context,
      InetAddress address,
      int port,
      String protocol,
      CountDownLatch handshakeComplete,
      CountDownLatch allowFirstWrite,
      CountDownLatch firstWritten,
      CountDownLatch firstRead,
      CountDownLatch secondWritten,
      CountDownLatch serverDone) {
    return () -> {
      try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket()) {
        socket.setUseClientMode(true);
        socket.setEnabledProtocols(new String[] {protocol});
        socket.setSoTimeout(10_000);
        socket.connect(new InetSocketAddress(address, port), 5_000);
        socket.startHandshake();
        handshakeComplete.countDown();
        await(allowFirstWrite, "permission to write first request fragment");

        OutputStream output = socket.getOutputStream();
        output.write(REQUEST_FIRST);
        output.flush();
        firstWritten.countDown();
        await(firstRead, "first request fragment read");
        output.write(REQUEST_SECOND);
        output.flush();
        secondWritten.countDown();
        await(serverDone, "server receive validation");
        return new ClientObservation(
            socket.getSession().getProtocol(), socket.getSession().getCipherSuite());
      } finally {
        handshakeComplete.countDown();
        firstWritten.countDown();
        secondWritten.countDown();
      }
    };
  }

  private static ReadResult readExact(InputStream input, int length) throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream(length);
    int calls = 0;
    while (output.size() < length) {
      byte[] fragment = new byte[length - output.size()];
      int read = input.read(fragment);
      require(read > 0, "unexpected EOF while reading TLS plaintext");
      output.write(fragment, 0, read);
      calls++;
    }
    return new ReadResult(output.toByteArray(), calls);
  }

  private static void await(CountDownLatch latch, String operation) throws Exception {
    require(latch.await(10, TimeUnit.SECONDS), operation + " timed out");
  }

  private static int descriptor(Method method, Socket socket) throws Exception {
    return ((Number) method.invoke(null, socket)).intValue();
  }

  private static long number(Object value) {
    return ((Number) value).longValue();
  }

  private static byte[] ascii(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private static String requiredProperty(String name) {
    String value = System.getProperty(name);
    require(value != null && !value.isEmpty(), "missing system property " + name);
    return value;
  }

  private static String clean(String value) {
    return value == null ? "" : value.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new IllegalStateException(message);
    }
  }

  private static final class ReadResult {
    private final byte[] bytes;
    private final int calls;

    private ReadResult(byte[] bytes, int calls) {
      this.bytes = bytes;
      this.calls = calls;
    }
  }

  private static final class ClientObservation {
    private final String protocol;
    private final String cipher;

    private ClientObservation(String protocol, String cipher) {
      this.protocol = protocol;
      this.cipher = cipher;
    }
  }
}
