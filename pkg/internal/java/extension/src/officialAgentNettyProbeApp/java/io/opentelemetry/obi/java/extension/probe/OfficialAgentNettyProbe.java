/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension.probe;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.ChannelGroupFuture;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.util.AttributeKey;
import io.netty.util.CharsetUtil;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.Future;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongBinaryOperator;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Isolated HTTPS Netty process used with an official Java agent and the OBI extension. */
public final class OfficialAgentNettyProbe {
  private static final String OUTPUT_PROPERTY = "obi.test.official.agent.probe.output";
  private static final String KEY_STORE_PROPERTY = "obi.test.official.agent.netty.probe.key.store";
  private static final char[] KEY_STORE_PASSWORD = "1234567".toCharArray();
  private static final String TLS_TO_INTERMEDIATE = "TLS_TO_INTERMEDIATE";
  private static final String INTERMEDIATE_TO_REQUEST = "INTERMEDIATE_TO_REQUEST";
  private static final AttributeKey<Long> TLS_THREAD = AttributeKey.valueOf("obi-tls-thread");
  private static final AttributeKey<Long> TLS_NATIVE_THREAD =
      AttributeKey.valueOf("obi-tls-native-thread");
  private static final AttributeKey<MultiHopState> MULTI_HOP_STATE =
      AttributeKey.valueOf("obi-multi-hop-state");
  private static final AtomicInteger TLS_EMITS = new AtomicInteger();
  private static final AtomicInteger TASK_CAPTURES = new AtomicInteger();
  private static final AtomicInteger TASK_RELAY_CAPTURES = new AtomicInteger();
  private static final AtomicInteger TASK_LINKS = new AtomicInteger();
  private static final AtomicInteger CLEANUPS = new AtomicInteger();
  private static final AtomicInteger TLS_CLEANUPS = new AtomicInteger();
  private static final AtomicInteger INTERMEDIATE_CLEANUPS = new AtomicInteger();
  private static final ConcurrentLinkedQueue<CleanupObservation> CLEANUP_OBSERVATIONS =
      new ConcurrentLinkedQueue<>();
  private static final Semaphore INTERMEDIATE_HANDOFF_PERMIT = new Semaphore(1, true);
  private static final ConcurrentMap<EventExecutor, TlsWorker> TLS_EXECUTORS =
      new ConcurrentHashMap<>();
  private static final ConcurrentMap<EventExecutor, WorkerBaseline> WORKER_BASELINES =
      new ConcurrentHashMap<>();
  private static final AtomicReference<EventExecutor> INTERMEDIATE_EXECUTOR =
      new AtomicReference<>();
  private static final ThreadLocal<EdgeLabel> ACTIVE_EDGE = new ThreadLocal<>();
  private static final ConcurrentMap<Long, EdgeCapture> LABELLED_EDGE_CAPTURES =
      new ConcurrentHashMap<>();
  private static final ConcurrentMap<Long, EdgeCapture> PENDING_EDGE_CAPTURES =
      new ConcurrentHashMap<>();
  private static final ConcurrentMap<String, EdgeCompletion> COMPLETED_EDGES =
      new ConcurrentHashMap<>();
  private static final AtomicLong TASK_EVENT_SEQUENCE = new AtomicLong();
  private static final AtomicReference<Throwable> EDGE_FAILURE = new AtomicReference<>();
  private static volatile Method getTid;

  private OfficialAgentNettyProbe() {}

  public static void main(String[] args) throws Exception {
    Path output = Paths.get(requiredProperty(OUTPUT_PROPERTY)).toAbsolutePath().normalize();
    File keyStoreFile = new File(requiredProperty(KEY_STORE_PROPERTY));
    require(keyStoreFile.isFile() && keyStoreFile.length() > 0, "missing TLS key store");

    HelperFixture fixture = HelperFixture.install();
    try {
      runServer(output, keyStoreFile);
    } finally {
      fixture.close();
    }
  }

  private static void runServer(Path output, File keyStoreFile) throws Exception {
    EventLoopGroup bossGroup = new NioEventLoopGroup(1, namedThreads("obi-netty-boss"));
    try {
      EventLoopGroup channelGroup = new NioEventLoopGroup(2, namedThreads("obi-netty-channel"));
      try {
        DefaultEventExecutorGroup tlsGroup =
            new DefaultEventExecutorGroup(2, namedThreads("obi-netty-tls"));
        try {
          DefaultEventExecutorGroup intermediateGroup =
              new DefaultEventExecutorGroup(1, namedThreads("obi-netty-intermediate"));
          try {
            serve(output, keyStoreFile, bossGroup, channelGroup, tlsGroup, intermediateGroup);
          } finally {
            shutdown(intermediateGroup, "intermediate executor");
          }
        } finally {
          shutdown(tlsGroup, "TLS executor");
        }
      } finally {
        shutdown(channelGroup, "channel event loop");
      }
    } finally {
      shutdown(bossGroup, "boss event loop");
    }
  }

  private static void serve(
      Path output,
      File keyStoreFile,
      EventLoopGroup bossGroup,
      EventLoopGroup channelGroup,
      DefaultEventExecutorGroup tlsGroup,
      DefaultEventExecutorGroup intermediateGroup)
      throws Exception {
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream input = Files.newInputStream(keyStoreFile.toPath())) {
      keyStore.load(input, KEY_STORE_PASSWORD);
    }
    KeyManagerFactory keyManager =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManager.init(keyStore, KEY_STORE_PASSWORD);
    SslContext sslContext = SslContextBuilder.forServer(keyManager).protocols("TLSv1.2").build();
    ChannelGroup childChannels = new DefaultChannelGroup(channelGroup.next());
    AtomicInteger connections = new AtomicInteger();
    Channel serverChannel = null;
    try {
      ServerBootstrap server =
          new ServerBootstrap()
              .group(bossGroup, channelGroup)
              .channel(NioServerSocketChannel.class)
              .childOption(ChannelOption.TCP_NODELAY, true)
              .childHandler(
                  new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel channel) throws Exception {
                      childChannels.add(channel);
                      boolean multiHop = connections.incrementAndGet() > 1;
                      ChannelPipeline pipeline =
                          channel
                              .pipeline()
                              .addLast(tlsGroup, "tls", sslContext.newHandler(channel.alloc()))
                              .addLast(
                                  tlsGroup,
                                  "request-frame",
                                  new DelimiterBasedFrameDecoder(
                                      8_192,
                                      false,
                                      Unpooled.copiedBuffer("\r\n\r\n", CharsetUtil.US_ASCII)))
                              .addLast(tlsGroup, "plaintext-marker", new PlaintextMarker(multiHop));
                      if (multiHop) {
                        pipeline.addLast(
                            intermediateGroup, "intermediate-marker", new IntermediateMarker());
                      }
                      pipeline
                          .addLast("http-codec", new HttpServerCodec())
                          .addLast("http-aggregate", new HttpObjectAggregator(8_192))
                          .addLast("request", new ProbeHandler());
                    }
                  });

      ChannelFuture bind = server.bind(new InetSocketAddress("127.0.0.1", 0));
      require(bind.await(5, TimeUnit.SECONDS), "Netty bind timed out");
      require(bind.isSuccess(), "Netty bind failed: " + bind.cause());
      serverChannel = bind.channel();
      int port = ((InetSocketAddress) serverChannel.localAddress()).getPort();
      require(port > 0, "Netty did not bind an ephemeral port");

      captureWorkerBaselines(channelGroup, tlsGroup, intermediateGroup);
      runRequests(port);
      verifyEdgeHandoffs();
      verifyCleanupObservations();
      closeChannels(childChannels);
      awaitServerSpans(output, 5, 10, TimeUnit.SECONDS);
      Class<?> bridge =
          Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", true, null);
      String diagnostics = (String) bridge.getMethod("diagnosticsSnapshot").invoke(null);
      require(TLS_EMITS.get() > 0, "Netty TLS plaintext fixture was not invoked");
      require(TASK_CAPTURES.get() > 0, "Netty handoff did not capture a task context");
      require(
          TASK_RELAY_CAPTURES.get() >= 2,
          "Netty multi-hop handoff did not capture relayed task contexts");
      require(TASK_LINKS.get() > 0, "Netty handoff did not link a task context");
      System.out.println("OBI_STOCK_NETTY_PROBE diagnostics=" + diagnostics);
      System.out.println(
          "OBI_STOCK_NETTY_PROBE tls_emits="
              + TLS_EMITS.get()
              + " task_captures="
              + TASK_CAPTURES.get()
              + " task_relay_captures="
              + TASK_RELAY_CAPTURES.get()
              + " task_links="
              + TASK_LINKS.get()
              + " cleanups="
              + CLEANUPS.get());
      System.out.println("OBI_STOCK_NETTY_PROBE passed");
    } finally {
      try {
        closeChannels(childChannels);
      } finally {
        closeChannel(serverChannel);
      }
    }
  }

  private static void runRequests(int port) throws Exception {
    try (SSLSocket socket = connect(port)) {
      BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
      OutputStream request = socket.getOutputStream();
      require("A:ok".equals(send(request, input, "A", false)), "request A failed");
      require("B:ok".equals(send(request, input, "B", false)), "request B failed");
      require("C:ok".equals(send(request, input, "C", true)), "request C failed");
    }
    sendParallel(port);
  }

  private static SSLSocket connect(int port) throws Exception {
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, new TrustManager[] {new LoopbackTrustManager()}, new SecureRandom());
    SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket();
    socket.connect(new InetSocketAddress("127.0.0.1", port), 5_000);
    socket.setEnabledProtocols(new String[] {"TLSv1.2"});
    socket.setSoTimeout(10_000);
    socket.startHandshake();
    return socket;
  }

  private static String send(
      OutputStream output, BufferedInputStream input, String id, boolean close) throws IOException {
    String request =
        "GET /probe/"
            + id
            + " HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Obi-Probe-Id: "
            + id
            + "\r\nConnection: "
            + (close ? "close" : "keep-alive")
            + "\r\n\r\n";
    output.write(request.getBytes(StandardCharsets.US_ASCII));
    output.flush();

    String status = readLine(input);
    require(status != null && status.startsWith("HTTP/1.1 200 "), "unexpected response " + status);
    int contentLength = -1;
    String line;
    while ((line = readLine(input)) != null && !line.isEmpty()) {
      int separator = line.indexOf(':');
      if (separator > 0
          && "content-length"
              .equals(line.substring(0, separator).trim().toLowerCase(Locale.ROOT))) {
        contentLength = Integer.parseInt(line.substring(separator + 1).trim());
      }
    }
    require(contentLength >= 0 && contentLength <= 64, "invalid response content length");
    byte[] body = new byte[contentLength];
    int offset = 0;
    while (offset < body.length) {
      int read = input.read(body, offset, body.length - offset);
      require(read >= 0, "truncated response body");
      offset += read;
    }
    return new String(body, StandardCharsets.UTF_8);
  }

  private static void sendParallel(int port) throws Exception {
    CountDownLatch ready = new CountDownLatch(2);
    CountDownLatch start = new CountDownLatch(1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Thread first = parallelRequest(port, "P", ready, start, failure);
    Thread second = parallelRequest(port, "Q", ready, start, failure);
    first.start();
    second.start();
    require(ready.await(5, TimeUnit.SECONDS), "parallel clients did not become ready");
    start.countDown();
    first.join(TimeUnit.SECONDS.toMillis(15));
    second.join(TimeUnit.SECONDS.toMillis(15));
    require(!first.isAlive() && !second.isAlive(), "parallel clients did not finish");
    Throwable problem = failure.get();
    if (problem != null) {
      throw new IllegalStateException("parallel request failed", problem);
    }
  }

  private static Thread parallelRequest(
      int port,
      String id,
      CountDownLatch ready,
      CountDownLatch start,
      AtomicReference<Throwable> failure) {
    return new Thread(
        () -> {
          ready.countDown();
          try {
            require(start.await(5, TimeUnit.SECONDS), "parallel start was not released");
            try (SSLSocket socket = connect(port)) {
              String response =
                  send(
                      socket.getOutputStream(),
                      new BufferedInputStream(socket.getInputStream()),
                      id,
                      true);
              require((id + ":ok").equals(response), "request " + id + " failed");
            }
          } catch (Throwable problem) {
            failure.compareAndSet(null, problem);
          }
        },
        "obi-official-agent-netty-parallel-" + id);
  }

  private static String readLine(InputStream input) throws IOException {
    StringBuilder line = new StringBuilder();
    boolean carriageReturn = false;
    while (true) {
      int value = input.read();
      if (value < 0) {
        return line.length() == 0 ? null : line.toString();
      }
      if (carriageReturn && value == '\n') {
        return line.toString();
      }
      if (carriageReturn) {
        line.append('\r');
      }
      carriageReturn = value == '\r';
      if (!carriageReturn) {
        line.append((char) value);
      }
      require(line.length() <= 8_192, "oversized response header line");
    }
  }

  private static void awaitServerSpans(Path output, int expected, long timeout, TimeUnit unit)
      throws Exception {
    long deadline = System.nanoTime() + unit.toNanos(timeout);
    while (System.nanoTime() - deadline < 0) {
      if (Files.isRegularFile(output)) {
        List<String> lines = Files.readAllLines(output, StandardCharsets.UTF_8);
        int count = 0;
        for (String line : lines) {
          if (line.startsWith("SPAN\t")) {
            count++;
          }
        }
        if (count >= expected) {
          return;
        }
      }
      Thread.sleep(25L);
    }
    throw new IllegalStateException("timed out waiting for Netty server spans");
  }

  private static void verifyEdgeHandoffs() {
    Throwable failure = EDGE_FAILURE.get();
    if (failure != null) {
      throw new IllegalStateException("Netty edge task ledger failed", failure);
    }
    require(
        LABELLED_EDGE_CAPTURES.size() == 4,
        "Netty edge capture token count mismatch: " + LABELLED_EDGE_CAPTURES.size());
    require(
        PENDING_EDGE_CAPTURES.isEmpty(),
        "Netty edge capture remained pending: " + PENDING_EDGE_CAPTURES.keySet());
    require(
        COMPLETED_EDGES.size() == 4,
        "Netty completed edge count mismatch: " + COMPLETED_EDGES.keySet());
    for (String id : new String[] {"P", "Q"}) {
      require(
          COMPLETED_EDGES.containsKey(edgeKey(id, TLS_TO_INTERMEDIATE)),
          "missing Netty TLS-to-intermediate edge for " + id);
      require(
          COMPLETED_EDGES.containsKey(edgeKey(id, INTERMEDIATE_TO_REQUEST)),
          "missing Netty intermediate-to-request edge for " + id);
    }
  }

  private static EdgeCompletion requiredEdge(String id, String edge) {
    EdgeCompletion completion = COMPLETED_EDGES.get(edgeKey(id, edge));
    require(completion != null, "missing Netty edge " + id + "/" + edge);
    return completion;
  }

  private static String edgeKey(String id, String edge) {
    return id + ":" + edge;
  }

  private static void captureWorkerBaselines(
      EventLoopGroup channelGroup,
      DefaultEventExecutorGroup tlsGroup,
      DefaultEventExecutorGroup intermediateGroup)
      throws Exception {
    require(WORKER_BASELINES.isEmpty(), "Netty worker baselines were already captured");
    require(
        captureWorkerBaselines(channelGroup, "request") == 2,
        "Netty request worker baseline count mismatch");
    require(
        captureWorkerBaselines(tlsGroup, "TLS") == 2, "Netty TLS worker baseline count mismatch");
    require(
        captureWorkerBaselines(intermediateGroup, "intermediate") == 1,
        "Netty intermediate worker baseline count mismatch");
    require(WORKER_BASELINES.size() == 5, "Netty worker baseline total mismatch");
  }

  private static int captureWorkerBaselines(Iterable<EventExecutor> executors, String workerKind)
      throws Exception {
    int count = 0;
    for (EventExecutor executor : executors) {
      int workerIndex = ++count;
      executeUntracked(
          executor,
          () -> {
            try {
              Authority authority = Authority.current();
              String worker = "Netty " + workerKind + " worker baseline " + workerIndex;
              assertTransportAuthorityAbsent(authority, worker);
              require(
                  !authority.taskRelayTransportReferencesPresent,
                  worker + " retained task relay transport references");
              WorkerBaseline baseline = new WorkerBaseline(authority);
              require(
                  WORKER_BASELINES.putIfAbsent(executor, baseline) == null,
                  worker + " was captured more than once");
            } catch (Exception failure) {
              throw new IllegalStateException(failure);
            }
          },
          "Netty " + workerKind + " worker baseline " + workerIndex);
    }
    return count;
  }

  private static void scheduleIntermediateCleanup(
      MultiHopState state, EventExecutor executor, long javaThread, long nativeThread)
      throws Exception {
    String id = state.id;
    CleanupObservation observation =
        submitUntracked(
            executor,
            () -> {
              try {
                Authority authority = Authority.current();
                boolean baselineRestored =
                    assertAuthorityAbsent(authority, executor, "Netty intermediate worker " + id);
                require(
                    Thread.currentThread().getId() == javaThread,
                    "Netty intermediate cleanup changed Java worker for " + id);
                long cleanupNativeThread = nativeThreadId();
                require(
                    cleanupNativeThread == nativeThread,
                    "Netty intermediate cleanup changed native worker for " + id);
                System.out.println(
                    "OBI_NETTY_INTERMEDIATE_CLEANUP\t"
                        + id
                        + "\t"
                        + javaThread
                        + "\t"
                        + authority.source
                        + "\t"
                        + authority.directAuthority
                        + "\tNONE\t"
                        + authority.socketFileDescriptor
                        + "\t"
                        + cleanupNativeThread
                        + "\t"
                        + authority.taskRelayState
                        + "\t"
                        + authority.exactTaskRelayState
                        + "\t"
                        + baselineRestored
                        + "\t"
                        + authority.socketContextPresent
                        + "\t"
                        + authority.receiveDepth);
                INTERMEDIATE_CLEANUPS.incrementAndGet();
              } catch (Exception failure) {
                throw new IllegalStateException(failure);
              } finally {
                state.releaseIntermediatePermit();
              }
            },
            "Netty intermediate cleanup probe " + id);
    CLEANUP_OBSERVATIONS.add(observation);
  }

  private static void scheduleRequestCleanup(ChannelHandlerContext context, String id)
      throws Exception {
    EventExecutor executor = context.executor();
    String channelId = context.channel().id().asLongText();
    CleanupObservation observation =
        submitUntracked(
            executor,
            () -> {
              try {
                Authority authority = Authority.current();
                boolean baselineRestored =
                    assertAuthorityAbsent(authority, executor, "Netty request worker " + id);
                System.out.println(
                    "OBI_NETTY_CLEANUP\t"
                        + id
                        + "\t"
                        + channelId
                        + "\t"
                        + Thread.currentThread().getId()
                        + "\t"
                        + authority.source
                        + "\t"
                        + authority.directAuthority
                        + "\tNONE\t"
                        + authority.socketFileDescriptor
                        + "\t"
                        + nativeThreadId()
                        + "\t"
                        + authority.taskRelayState
                        + "\t"
                        + authority.exactTaskRelayState
                        + "\t"
                        + baselineRestored
                        + "\t"
                        + authority.socketContextPresent
                        + "\t"
                        + authority.receiveDepth);
                CLEANUPS.incrementAndGet();
              } catch (Exception failure) {
                throw new IllegalStateException(failure);
              }
            },
            "Netty request cleanup probe " + id);
    CLEANUP_OBSERVATIONS.add(observation);
  }

  private static void scheduleTlsCleanup(TlsWorker worker) throws Exception {
    CleanupObservation observation =
        submitUntracked(
            worker.executor,
            () -> {
              try {
                Authority authority = Authority.current();
                boolean baselineRestored =
                    assertAuthorityAbsent(
                        authority, worker.executor, "Netty TLS worker " + worker.id);
                require(
                    Thread.currentThread().getId() == worker.javaThreadId,
                    "Netty TLS cleanup changed Java worker for " + worker.id);
                long nativeThread = nativeThreadId();
                require(
                    nativeThread == worker.nativeThreadId,
                    "Netty TLS cleanup changed native worker for " + worker.id);
                System.out.println(
                    "OBI_NETTY_TLS_CLEANUP\t"
                        + worker.id
                        + "\t"
                        + worker.javaThreadId
                        + "\t"
                        + authority.source
                        + "\t"
                        + authority.directAuthority
                        + "\tNONE\t"
                        + authority.socketFileDescriptor
                        + "\t"
                        + nativeThread
                        + "\t"
                        + authority.taskRelayState
                        + "\t"
                        + authority.exactTaskRelayState
                        + "\t"
                        + baselineRestored
                        + "\t"
                        + authority.socketContextPresent
                        + "\t"
                        + authority.receiveDepth);
                TLS_CLEANUPS.incrementAndGet();
              } catch (Exception failure) {
                throw new IllegalStateException(failure);
              }
            },
            "Netty TLS cleanup probe " + worker.id);
    CLEANUP_OBSERVATIONS.add(observation);
  }

  private static void verifyCleanupObservations() throws Exception {
    require(CLEANUP_OBSERVATIONS.size() == 9, "Netty cleanup observation count mismatch");
    CleanupObservation observation;
    while ((observation = CLEANUP_OBSERVATIONS.poll()) != null) {
      observation.await();
    }
    require(CLEANUPS.get() == 5, "Netty request cleanup probe count mismatch");
    require(TLS_CLEANUPS.get() == 2, "Netty TLS cleanup probe count mismatch");
    require(INTERMEDIATE_CLEANUPS.get() == 2, "Netty intermediate cleanup probe count mismatch");
    require(TLS_EXECUTORS.size() == 2, "Netty TLS worker count mismatch");
    require(INTERMEDIATE_EXECUTOR.get() != null, "Netty intermediate executor was not captured");
    require(
        INTERMEDIATE_HANDOFF_PERMIT.availablePermits() == 1
            && !INTERMEDIATE_HANDOFF_PERMIT.hasQueuedThreads(),
        "Netty intermediate handoff permit was not restored");
  }

  private static boolean assertAuthorityAbsent(
      Authority authority, EventExecutor executor, String worker) {
    assertTransportAuthorityAbsent(authority, worker);
    WorkerBaseline baseline = WORKER_BASELINES.get(executor);
    require(baseline != null, worker + " did not have a captured baseline");
    require(
        authority.source == baseline.lookupSource,
        worker + " did not restore its lookup source baseline");
    require(
        Objects.equals(authority.lookupOverride, baseline.lookupOverride),
        worker + " did not restore its raw lookup override baseline");
    require(
        authority.taskRelayStateObject == baseline.taskRelayStateObject,
        worker + " did not restore its task relay object baseline");
    require(
        authority.taskRelayFingerprint.equals(baseline.taskRelayFingerprint),
        worker
            + " did not restore its task relay frame baseline: expected "
            + baseline.taskRelayFingerprint
            + " but was "
            + authority.taskRelayFingerprint);
    require(
        !authority.taskRelayTransportReferencesPresent,
        worker + " retained task relay transport references");
    return true;
  }

  private static void assertTransportAuthorityAbsent(Authority authority, String worker) {
    require(authority.source != 2, worker + " retained a task lookup source");
    require(!authority.directAuthority, worker + " retained direct receive authority");
    require(
        authority.lookupOverride == null || Byte.valueOf((byte) 3).equals(authority.lookupOverride),
        worker + " retained a raw lookup override");
    require(!authority.lifecyclePresent, worker + " retained a socket lifecycle reference");
    require(!authority.exactTaskRelayState, worker + " retained exact task relay state");
    require(!authority.socketContextPresent, worker + " retained a socket context");
    require(authority.receiveDepthValue == null, worker + " retained a raw receive depth");
    require(authority.receiveDepth == 0, worker + " retained a receive depth");
    require(authority.socketFileDescriptor == -1, worker + " retained a socket descriptor");
    require(
        authority.sslStorageThreadLocalState.isEmpty(),
        worker + " retained SSL worker state: " + authority.sslStorageThreadLocalState);
  }

  private static void executeUntracked(EventExecutor executor, Runnable action, String name)
      throws Exception {
    submitUntracked(executor, action, name).await();
  }

  private static CleanupObservation submitUntracked(
      EventExecutor executor, Runnable action, String name) throws Exception {
    CleanupObservation result = new CleanupObservation(name);
    Runnable observation =
        () -> {
          try {
            action.run();
          } catch (Throwable problem) {
            result.failure.compareAndSet(null, problem);
          } finally {
            result.completed.countDown();
          }
        };

    Class<?> storage =
        Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
    Method beginSubmission = storage.getMethod("beginTaskSubmission", long.class, Object.class);
    Method endSubmission = storage.getMethod("endTaskSubmission", Object.class);
    int submissionOwner = storage.getField("SUBMISSION_OWNER").getInt(null);
    Class<?> executorAdvice =
        Class.forName(
            "io.opentelemetry.javaagent.bootstrap.executors.ExecutorAdviceHelper", true, null);
    Method disableOfficialPropagation = executorAdvice.getMethod("disablePropagation");
    Method enableOfficialPropagation = executorAdvice.getMethod("enablePropagation");
    Method officialPropagationDisabled = executorAdvice.getMethod("isPropagationDisabled");
    int submission =
        ((Integer) beginSubmission.invoke(null, nativeThreadId(), observation)).intValue();
    require(submission == submissionOwner, name + " could not reserve its observation task");
    require(
        !((Boolean) officialPropagationDisabled.invoke(null)).booleanValue(),
        name + " inherited disabled official-agent propagation");
    disableOfficialPropagation.invoke(null);
    try {
      // Remove the context before enqueueing while the submission guard still owns the identity.
      // OBI executor advice therefore sees a nested submission and cannot recapture it. Official
      // agent propagation is disabled around the same call so it cannot substitute a newly tracked
      // wrapper identity, even if the worker runs the observation before execute() returns.
      untrackTask(observation);
      executor.execute(observation);
      untrackTask(observation);
    } finally {
      try {
        enableOfficialPropagation.invoke(null);
      } finally {
        endSubmission.invoke(null, observation);
      }
    }
    require(
        !((Boolean) officialPropagationDisabled.invoke(null)).booleanValue(),
        name + " retained disabled official-agent propagation");
    require(
        Authority.threadLocalValue(storage, "activeTaskSubmissions") == null,
        name + " retained its submission guard");
    return result;
  }

  private static void untrackTask(Object task) throws Exception {
    Class<?> storage =
        Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
    storage.getMethod("untrackTask", Object.class).invoke(null, task);
    Object remaining = storage.getMethod("taskContext", Object.class).invoke(null, task);
    require(remaining == null, "Netty cleanup observation remained tracked");
  }

  private static void closeChannel(Channel channel) throws InterruptedException {
    if (channel == null) {
      return;
    }
    ChannelFuture close = channel.close();
    require(close.await(5, TimeUnit.SECONDS), "Netty server close timed out");
    require(close.isSuccess(), "Netty server close failed: " + close.cause());
  }

  private static void closeChannels(ChannelGroup channels) throws InterruptedException {
    ChannelGroupFuture close = channels.close();
    require(close.await(10, TimeUnit.SECONDS), "Netty child-channel close timed out");
    require(close.isSuccess(), "Netty child-channel close failed: " + close.cause());
  }

  private static void shutdown(EventLoopGroup group, String name) throws InterruptedException {
    Future<?> shutdown = group.shutdownGracefully(0, 5, TimeUnit.SECONDS);
    require(shutdown.await(10, TimeUnit.SECONDS), name + " shutdown timed out");
    require(shutdown.isSuccess(), name + " shutdown failed: " + shutdown.cause());
  }

  private static void shutdown(DefaultEventExecutorGroup group, String name)
      throws InterruptedException {
    Future<?> shutdown = group.shutdownGracefully(0, 5, TimeUnit.SECONDS);
    require(shutdown.await(10, TimeUnit.SECONDS), name + " shutdown timed out");
    require(shutdown.isSuccess(), name + " shutdown failed: " + shutdown.cause());
  }

  private static ThreadFactory namedThreads(String prefix) {
    AtomicInteger index = new AtomicInteger();
    return runnable -> {
      Thread thread = new Thread(runnable, prefix + "-" + index.incrementAndGet());
      thread.setDaemon(true);
      return thread;
    };
  }

  private static String requiredProperty(String name) {
    String value = System.getProperty(name);
    require(value != null && !value.isEmpty(), "missing system property " + name);
    return value;
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new IllegalStateException(message);
    }
  }

  private static int actualSocketFileDescriptor(Channel channel) throws Exception {
    Object javaChannel = invokeNoArg(channel, "javaChannel");
    require(
        javaChannel instanceof java.nio.channels.SocketChannel,
        "accepted Netty channel does not expose a JDK SocketChannel");
    Object descriptor = invokeNoArg(javaChannel, "getFDVal");
    return descriptor instanceof Number ? ((Number) descriptor).intValue() : -1;
  }

  private static Object invokeNoArg(Object target, String methodName) throws Exception {
    Class<?> type = target.getClass();
    while (type != null) {
      try {
        Method method = type.getDeclaredMethod(methodName);
        method.setAccessible(true);
        return method.invoke(target);
      } catch (NoSuchMethodException ignored) {
        type = type.getSuperclass();
      }
    }
    return null;
  }

  private static long nativeThreadId() {
    Method method = getTid;
    require(method != null, "BootstrapNative.gettid is unavailable");
    try {
      return ((Number) method.invoke(null)).longValue();
    } catch (ReflectiveOperationException failure) {
      throw new IllegalStateException("cannot resolve native thread id", failure);
    }
  }

  private static String requestId(Object message) {
    require(message instanceof ByteBuf, "Netty framed plaintext was not a ByteBuf");
    String request = ((ByteBuf) message).toString(CharsetUtil.US_ASCII);
    String prefix = "GET /probe/";
    require(request.startsWith(prefix), "invalid Netty request line");
    int separator = request.indexOf(' ', prefix.length());
    require(separator > prefix.length(), "missing Netty request identifier");
    String id = request.substring(prefix.length(), separator);
    require(
        "A".equals(id) || "B".equals(id) || "C".equals(id) || "P".equals(id) || "Q".equals(id),
        "invalid Netty framed request identifier");
    require(
        request.contains("\r\nX-Obi-Probe-Id: " + id + "\r\n"),
        "Netty request line/header identifier mismatch");
    require(request.endsWith("\r\n\r\n"), "Netty request frame lost its delimiter");
    return id;
  }

  private static void fireChannelReadWithEdge(
      ChannelHandlerContext context, Object message, EdgeLabel edge) {
    require(ACTIVE_EDGE.get() == null, "nested Netty edge label");
    ACTIVE_EDGE.set(edge);
    try {
      context.fireChannelRead(message);
    } finally {
      ACTIVE_EDGE.remove();
    }
  }

  private static final class PlaintextMarker extends ChannelInboundHandlerAdapter {
    private final boolean multiHop;

    private PlaintextMarker(boolean multiHop) {
      this.multiHop = multiHop;
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) throws Exception {
      String id = requestId(message);
      boolean expectedMultiHop = "P".equals(id) || "Q".equals(id);
      require(multiHop == expectedMultiHop, "Netty connection/request ordering changed for " + id);
      long javaThread = Thread.currentThread().getId();
      long nativeThread = nativeThreadId();
      context.channel().attr(TLS_THREAD).set(javaThread);
      context.channel().attr(TLS_NATIVE_THREAD).set(nativeThread);
      if (!multiHop) {
        context.fireChannelRead(message);
        return;
      }

      int channelFd = actualSocketFileDescriptor(context.channel());
      Authority authority = Authority.current();
      require(authority.source == 1, "Netty TLS plaintext lost direct lookup source");
      require(authority.directAuthority, "Netty TLS plaintext lost direct receive authority");
      require(
          authority.lifecyclePresent && authority.lifecycleActive,
          "Netty TLS plaintext lost its live socket lifecycle");
      require(
          authority.socketFileDescriptor == channelFd,
          "Netty TLS plaintext changed its socket descriptor");
      require(authority.socketContextPresent, "Netty TLS plaintext lost its socket context");
      require(
          context.channel().attr(MULTI_HOP_STATE).get() == null,
          "duplicate Netty multi-hop plaintext frame for " + id);

      TlsWorker worker = new TlsWorker(id, context.executor(), javaThread, nativeThread);
      require(
          TLS_EXECUTORS.putIfAbsent(context.executor(), worker) == null,
          "P/Q did not use distinct Netty TLS workers");
      require(
          INTERMEDIATE_HANDOFF_PERMIT.tryAcquire(5, TimeUnit.SECONDS),
          "Netty intermediate handoff permit timed out for " + id);
      MultiHopState state =
          new MultiHopState(
              id,
              context.channel().id().asLongText(),
              channelFd,
              javaThread,
              nativeThread,
              authority);
      boolean handedOff = false;
      try {
        scheduleTlsCleanup(worker);
        context.channel().attr(MULTI_HOP_STATE).set(state);
        fireChannelReadWithEdge(
            context,
            message,
            new EdgeLabel(id, state.channelId, TLS_TO_INTERMEDIATE, "TASK_CAPTURE", nativeThread));
        handedOff = true;
      } finally {
        if (!handedOff) {
          state.releaseIntermediatePermit();
        }
      }
    }
  }

  private static final class IntermediateMarker extends ChannelInboundHandlerAdapter {
    @Override
    public void channelRead(ChannelHandlerContext context, Object message) throws Exception {
      MultiHopState state = context.channel().attr(MULTI_HOP_STATE).get();
      boolean cleanupScheduled = false;
      try {
        require(state != null, "Netty intermediate handoff lost its channel state");
        require(state.intermediate == null, "duplicate Netty intermediate handoff for " + state.id);
        EventExecutor executor = context.executor();
        INTERMEDIATE_EXECUTOR.compareAndSet(null, executor);
        require(
            INTERMEDIATE_EXECUTOR.get() == executor,
            "P/Q did not share one Netty intermediate worker");

        Authority authority = Authority.current();
        long javaThread = Thread.currentThread().getId();
        long nativeThread = nativeThreadId();
        require(authority.source == 2, "Netty intermediate handoff lost task lookup authority");
        require(!authority.directAuthority, "Netty intermediate retained direct receive authority");
        require(
            authority.lifecyclePresent && authority.lifecycleActive,
            "Netty intermediate handoff lost its socket lifecycle");
        require(authority.taskRelayState, "Netty intermediate handoff lost task relay state");
        require(
            authority.exactTaskRelayState,
            "Netty intermediate handoff lost exact task relay state");
        require(
            authority.socketContextPresent, "Netty intermediate handoff lost its socket context");
        require(
            authority.lifecycleIdentity == state.tlsAuthority.lifecycleIdentity,
            "Netty intermediate handoff changed socket lifecycle");
        require(
            authority.socketFileDescriptor == state.channelFd,
            "Netty intermediate handoff changed socket descriptor");
        state.intermediate = new IntermediateHandoff(javaThread, nativeThread, authority);
        scheduleIntermediateCleanup(state, executor, javaThread, nativeThread);
        cleanupScheduled = true;
        fireChannelReadWithEdge(
            context,
            message,
            new EdgeLabel(
                state.id,
                state.channelId,
                INTERMEDIATE_TO_REQUEST,
                "TASK_RELAY_CAPTURE",
                nativeThread));
      } finally {
        if (!cleanupScheduled && state != null) {
          state.releaseIntermediatePermit();
        }
      }
    }
  }

  private static final class ProbeHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
    @Override
    protected void channelRead0(ChannelHandlerContext context, FullHttpRequest request)
        throws Exception {
      String id = request.headers().get("x-obi-probe-id");
      require(
          "A".equals(id) || "B".equals(id) || "C".equals(id) || "P".equals(id) || "Q".equals(id),
          "invalid Netty probe id");
      Long tlsThread = context.channel().attr(TLS_THREAD).get();
      Long tlsNativeThread = context.channel().attr(TLS_NATIVE_THREAD).get();
      int channelFd = actualSocketFileDescriptor(context.channel());
      Authority authority = Authority.current();
      long requestThread = Thread.currentThread().getId();
      long requestNativeThread = nativeThreadId();
      require(tlsThread != null && tlsThread.longValue() > 0, "missing TLS executor thread");
      require(
          tlsNativeThread != null && tlsNativeThread.longValue() > 0,
          "missing TLS executor native thread");
      require(channelFd >= 0, "cannot resolve accepted Netty socket descriptor");
      require(tlsThread.longValue() != requestThread, "Netty TLS handoff stayed on one thread");
      require(
          tlsNativeThread.longValue() != requestNativeThread,
          "Netty TLS handoff stayed on one native thread");
      require(authority.source == 3, "Netty handler did not block consumed lookup authority");
      require(!authority.directAuthority, "Netty handler retained direct receive authority");
      require(!authority.lifecyclePresent, "Netty handler retained its consumed socket lifecycle");
      require(authority.taskRelayState, "Netty handler lost its enclosing task relay state");
      require(
          authority.exactTaskRelayState, "Netty handler lost its enclosing exact task relay state");
      require(
          !authority.taskRelayTransportReferencesPresent,
          "Netty handler retained task relay transport references");
      require(authority.socketFileDescriptor == -1, "Netty handler retained a consumed socket");
      require(!authority.socketContextPresent, "Netty handler retained a consumed socket context");
      MultiHopState state = context.channel().attr(MULTI_HOP_STATE).get();
      IntermediateHandoff intermediate = state == null ? null : state.intermediate;
      boolean expectedIntermediate = "P".equals(id) || "Q".equals(id);
      require(
          expectedIntermediate == (intermediate != null),
          "unexpected Netty intermediate handoff for " + id);
      if (intermediate != null) {
        require(id.equals(state.id), "Netty multi-hop request identifier changed");
        require(
            context.channel().id().asLongText().equals(state.channelId),
            "Netty multi-hop channel identifier changed");
        require(channelFd == state.channelFd, "Netty multi-hop channel descriptor changed");
        require(tlsThread.longValue() == state.tlsJavaThread, "Netty TLS Java worker changed");
        require(
            tlsNativeThread.longValue() == state.tlsNativeThread,
            "Netty TLS native worker changed");
        require(
            tlsThread.longValue() != intermediate.threadId,
            "Netty TLS-to-intermediate handoff stayed on one thread");
        require(
            intermediate.threadId != requestThread,
            "Netty intermediate-to-request handoff stayed on one thread");
        require(
            intermediate.authority.socketFileDescriptor == channelFd,
            "Netty intermediate handoff changed socket descriptor");
        EdgeCompletion first = requiredEdge(id, TLS_TO_INTERMEDIATE);
        EdgeCompletion second = requiredEdge(id, INTERMEDIATE_TO_REQUEST);
        require(first.captureThreadId == state.tlsNativeThread, "Netty first capture TID changed");
        require(
            first.linkParentThreadId == state.tlsNativeThread,
            "Netty first link parent TID changed");
        require(
            first.linkChildThreadId == intermediate.nativeThreadId,
            "Netty first link child TID changed");
        require(
            second.captureThreadId == intermediate.nativeThreadId,
            "Netty relay capture TID changed");
        require(
            second.linkParentThreadId == intermediate.nativeThreadId,
            "Netty relay link parent TID changed");
        require(
            second.linkChildThreadId == requestNativeThread, "Netty relay link child TID changed");
        require(
            first.linkSequence < second.captureSequence,
            "Netty relay capture preceded first-hop entry");
        System.out.println(
            "OBI_NETTY_HANDOFF\t"
                + id
                + "\t"
                + context.channel().id().asLongText()
                + "\t"
                + channelFd
                + "\t"
                + intermediate.authority.lifecycleIdentity
                + "\t"
                + tlsThread
                + "\t"
                + intermediate.threadId
                + "\t"
                + requestThread
                + "\t"
                + state.tlsNativeThread
                + "\t"
                + intermediate.nativeThreadId
                + "\t"
                + requestNativeThread
                + "\t"
                + intermediate.authority.source
                + "\tLIVE\t"
                + intermediate.authority.socketFileDescriptor);
      }
      System.out.println(
          "OBI_NETTY_HANDLER\t"
              + id
              + "\t"
              + context.channel().id().asLongText()
              + "\t"
              + channelFd
              + "\t"
              + authority.lifecycleIdentity
              + "\t"
              + tlsThread
              + "\t"
              + requestThread
              + "\t"
              + authority.source
              + "\tNONE\t"
              + authority.socketFileDescriptor
              + "\t"
              + tlsNativeThread
              + "\t"
              + requestNativeThread);

      ByteBuf body = Unpooled.copiedBuffer(id + ":ok", CharsetUtil.UTF_8);
      FullHttpResponse response =
          new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, body);
      response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=utf-8");
      HttpUtil.setContentLength(response, body.readableBytes());
      boolean keepAlive = HttpUtil.isKeepAlive(request);
      if (keepAlive) {
        response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
      }
      scheduleRequestCleanup(context, id);
      ChannelFuture write = context.writeAndFlush(response);
      if (!keepAlive) {
        write.addListener(io.netty.channel.ChannelFutureListener.CLOSE);
      }
    }
  }

  private static final class CleanupObservation {
    private final String name;
    private final CountDownLatch completed = new CountDownLatch(1);
    private final AtomicReference<Throwable> failure = new AtomicReference<>();

    private CleanupObservation(String name) {
      this.name = name;
    }

    private void await() throws Exception {
      require(completed.await(5, TimeUnit.SECONDS), name + " timed out");
      Throwable problem = failure.get();
      if (problem != null) {
        throw new IllegalStateException(name + " failed", problem);
      }
    }
  }

  private static final class TlsWorker {
    private final String id;
    private final EventExecutor executor;
    private final long javaThreadId;
    private final long nativeThreadId;

    private TlsWorker(String id, EventExecutor executor, long javaThreadId, long nativeThreadId) {
      this.id = id;
      this.executor = executor;
      this.javaThreadId = javaThreadId;
      this.nativeThreadId = nativeThreadId;
    }
  }

  private static final class WorkerBaseline {
    private final int lookupSource;
    private final Object lookupOverride;
    private final Object taskRelayStateObject;
    private final String taskRelayFingerprint;

    private WorkerBaseline(Authority authority) {
      this.lookupSource = authority.source;
      this.lookupOverride = authority.lookupOverride;
      this.taskRelayStateObject = authority.taskRelayStateObject;
      this.taskRelayFingerprint = authority.taskRelayFingerprint;
    }
  }

  private static final class MultiHopState {
    private final String id;
    private final String channelId;
    private final int channelFd;
    private final long tlsJavaThread;
    private final long tlsNativeThread;
    private final Authority tlsAuthority;
    private final AtomicBoolean intermediatePermitHeld = new AtomicBoolean(true);
    private volatile IntermediateHandoff intermediate;

    private MultiHopState(
        String id,
        String channelId,
        int channelFd,
        long tlsJavaThread,
        long tlsNativeThread,
        Authority tlsAuthority) {
      this.id = id;
      this.channelId = channelId;
      this.channelFd = channelFd;
      this.tlsJavaThread = tlsJavaThread;
      this.tlsNativeThread = tlsNativeThread;
      this.tlsAuthority = tlsAuthority;
    }

    private void releaseIntermediatePermit() {
      if (intermediatePermitHeld.compareAndSet(true, false)) {
        INTERMEDIATE_HANDOFF_PERMIT.release();
      }
    }
  }

  private static final class IntermediateHandoff {
    private final long threadId;
    private final long nativeThreadId;
    private final Authority authority;

    private IntermediateHandoff(long threadId, long nativeThreadId, Authority authority) {
      this.threadId = threadId;
      this.nativeThreadId = nativeThreadId;
      this.authority = authority;
    }
  }

  private static final class EdgeLabel {
    private final String id;
    private final String channelId;
    private final String edge;
    private final String expectedCaptureOperation;
    private final long sourceThreadId;

    private EdgeLabel(
        String id,
        String channelId,
        String edge,
        String expectedCaptureOperation,
        long sourceThreadId) {
      this.id = id;
      this.channelId = channelId;
      this.edge = edge;
      this.expectedCaptureOperation = expectedCaptureOperation;
      this.sourceThreadId = sourceThreadId;
    }
  }

  private static final class EdgeCapture {
    private final EdgeLabel label;
    private final String operation;
    private final long token;
    private final long captureThreadId;
    private final long sequence;

    private EdgeCapture(
        EdgeLabel label, String operation, long token, long captureThreadId, long sequence) {
      this.label = label;
      this.operation = operation;
      this.token = token;
      this.captureThreadId = captureThreadId;
      this.sequence = sequence;
    }
  }

  private static final class EdgeCompletion {
    private final EdgeCapture capture;
    private final long captureThreadId;
    private final long captureSequence;
    private final long linkParentThreadId;
    private final long linkChildThreadId;
    private final long linkSequence;

    private EdgeCompletion(
        EdgeCapture capture, long linkParentThreadId, long linkChildThreadId, long linkSequence) {
      this.capture = capture;
      this.captureThreadId = capture.captureThreadId;
      this.captureSequence = capture.sequence;
      this.linkParentThreadId = linkParentThreadId;
      this.linkChildThreadId = linkChildThreadId;
      this.linkSequence = linkSequence;
    }
  }

  private static final class Authority {
    private final int source;
    private final boolean directAuthority;
    private final Object lookupOverride;
    private final boolean lifecyclePresent;
    private final boolean lifecycleActive;
    private final int lifecycleIdentity;
    private final int socketFileDescriptor;
    private final boolean taskRelayState;
    private final boolean exactTaskRelayState;
    private final Object taskRelayStateObject;
    private final String taskRelayFingerprint;
    private final boolean taskRelayTransportReferencesPresent;
    private final boolean socketContextPresent;
    private final Object receiveDepthValue;
    private final int receiveDepth;
    private final String sslStorageThreadLocalState;

    private Authority(
        int source,
        boolean directAuthority,
        Object lookupOverride,
        boolean lifecyclePresent,
        boolean lifecycleActive,
        int lifecycleIdentity,
        int socketFileDescriptor,
        boolean taskRelayState,
        boolean exactTaskRelayState,
        Object taskRelayStateObject,
        String taskRelayFingerprint,
        boolean taskRelayTransportReferencesPresent,
        boolean socketContextPresent,
        Object receiveDepthValue,
        int receiveDepth,
        String sslStorageThreadLocalState) {
      this.source = source;
      this.directAuthority = directAuthority;
      this.lookupOverride = lookupOverride;
      this.lifecyclePresent = lifecyclePresent;
      this.lifecycleActive = lifecycleActive;
      this.lifecycleIdentity = lifecycleIdentity;
      this.socketFileDescriptor = socketFileDescriptor;
      this.taskRelayState = taskRelayState;
      this.exactTaskRelayState = exactTaskRelayState;
      this.taskRelayStateObject = taskRelayStateObject;
      this.taskRelayFingerprint = taskRelayFingerprint;
      this.taskRelayTransportReferencesPresent = taskRelayTransportReferencesPresent;
      this.socketContextPresent = socketContextPresent;
      this.receiveDepthValue = receiveDepthValue;
      this.receiveDepth = receiveDepth;
      this.sslStorageThreadLocalState = sslStorageThreadLocalState;
    }

    private static Authority current() throws Exception {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      int source =
          ((Integer) threadInfo.getMethod("remoteParentLookupSource").invoke(null)).intValue();
      boolean directAuthority =
          ((Boolean) threadInfo.getMethod("hasRemoteParentDirectReceiveAuthority").invoke(null))
              .booleanValue();
      Object lookupOverride = threadLocalValue(threadInfo, "remoteParentLookupOverride");
      Object lifecycle = threadInfo.getMethod("remoteParentLookupLifecycle").invoke(null);
      boolean active =
          lifecycle != null
              && Boolean.TRUE.equals(lifecycle.getClass().getMethod("active").invoke(lifecycle));
      int socketFileDescriptor =
          ((Integer) threadInfo.getMethod("remoteParentSocketFileDescriptor").invoke(null))
              .intValue();
      Object relayState = threadLocalValue(threadInfo, "taskRelayState");
      TaskRelaySnapshot relay = TaskRelaySnapshot.capture(relayState);
      boolean socketContextPresent =
          threadLocalValue(threadInfo, "remoteParentSocketContext") != null;
      Object receiveDepth = threadLocalValue(threadInfo, "remoteParentReceiveDepth");
      return new Authority(
          source,
          directAuthority,
          lookupOverride,
          lifecycle != null,
          active,
          lifecycle == null ? 0 : System.identityHashCode(lifecycle),
          socketFileDescriptor,
          relay.depth > 0,
          relay.exactState,
          relayState,
          relay.fingerprint,
          relay.transportReferencesPresent,
          socketContextPresent,
          receiveDepth,
          receiveDepth instanceof Number ? ((Number) receiveDepth).intValue() : 0,
          SslStorageThreadLocals.present());
    }

    private static Object threadLocalValue(Class<?> owner, String name) throws Exception {
      Field field = owner.getDeclaredField(name);
      field.setAccessible(true);
      return ((ThreadLocal<?>) field.get(null)).get();
    }
  }

  private static final class SslStorageThreadLocals {
    private static final String[] NAMES = {
      "activeTaskSubmissions",
      "discardOldestQueues",
      "executorHookDepth",
      "executorTaskScopes",
      "virtualThreadTaskScope",
      "remoteParentUnwrapDepth",
      "nettyConnectionScopes",
      "nettyHandlerScopes",
      "unencrypted",
      "nettyConnection"
    };

    private static String present() throws Exception {
      Class<?> storage =
          Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
      StringBuilder present = new StringBuilder();
      for (String name : NAMES) {
        if (Authority.threadLocalValue(storage, name) != null) {
          if (present.length() > 0) {
            present.append(',');
          }
          present.append(name);
        }
      }
      return present.toString();
    }
  }

  private static final class TaskRelaySnapshot {
    private final int depth;
    private final boolean exactState;
    private final String fingerprint;
    private final boolean transportReferencesPresent;

    private TaskRelaySnapshot(
        int depth, boolean exactState, String fingerprint, boolean transportReferencesPresent) {
      this.depth = depth;
      this.exactState = exactState;
      this.fingerprint = fingerprint;
      this.transportReferencesPresent = transportReferencesPresent;
    }

    private static TaskRelaySnapshot capture(Object state) throws Exception {
      if (state == null) {
        return new TaskRelaySnapshot(0, false, "NONE", false);
      }

      int depth = intField(state, "depth");
      long[] previousParents = (long[]) fieldValue(state, "previousParents");
      long[] previousTokens = (long[]) fieldValue(state, "previousTokens");
      boolean[] previousExact = (boolean[]) fieldValue(state, "previousExact");
      byte[] previousLookupOverrides = (byte[]) fieldValue(state, "previousLookupOverrides");
      long[] previousReceiveEpochs = (long[]) fieldValue(state, "previousReceiveEpochs");
      Object[] previousLookupLifecycles = (Object[]) fieldValue(state, "previousLookupLifecycles");
      Object[] previousSocketContexts = (Object[]) fieldValue(state, "previousSocketContexts");
      require(depth >= 0, "Netty task relay depth was negative");
      require(
          depth <= previousParents.length
              && depth <= previousTokens.length
              && depth <= previousExact.length
              && depth <= previousLookupOverrides.length
              && depth <= previousReceiveEpochs.length
              && depth <= previousLookupLifecycles.length
              && depth <= previousSocketContexts.length,
          "Netty task relay depth exceeded its storage");

      boolean currentExact = booleanField(state, "currentExact");
      boolean exactState = currentExact;
      StringBuilder fingerprint =
          new StringBuilder()
              .append("depth=")
              .append(depth)
              .append(",threadId=")
              .append(longField(state, "threadId"))
              .append(",currentParent=")
              .append(longField(state, "currentParent"))
              .append(",currentExact=")
              .append(currentExact);
      for (int index = 0; index < depth; index++) {
        exactState |= previousExact[index];
        fingerprint
            .append("|frame=")
            .append(index)
            .append(',')
            .append(previousParents[index])
            .append(',')
            .append(previousTokens[index])
            .append(',')
            .append(previousExact[index])
            .append(',')
            .append(previousLookupOverrides[index])
            .append(',')
            .append(previousReceiveEpochs[index]);
      }
      boolean transportReferencesPresent =
          hasReference(previousLookupLifecycles)
              || hasReference(previousSocketContexts)
              || fieldValue(state, "exitLookupLifecycle") != null
              || fieldValue(state, "exitSocketContext") != null;
      return new TaskRelaySnapshot(
          depth, exactState, fingerprint.toString(), transportReferencesPresent);
    }

    private static Object fieldValue(Object target, String name) throws Exception {
      Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      return field.get(target);
    }

    private static int intField(Object target, String name) throws Exception {
      Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      return field.getInt(target);
    }

    private static long longField(Object target, String name) throws Exception {
      Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      return field.getLong(target);
    }

    private static boolean booleanField(Object target, String name) throws Exception {
      Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      return field.getBoolean(target);
    }

    private static boolean hasReference(Object[] values) {
      for (Object value : values) {
        if (value != null) {
          return true;
        }
      }
      return false;
    }
  }

  private static void recordTaskEvent(String operation, long value, long token) {
    long sequence = TASK_EVENT_SEQUENCE.incrementAndGet();
    try {
      EdgeLabel active = ACTIVE_EDGE.get();
      if (active != null
          && ("TASK_CAPTURE".equals(operation) || "TASK_RELAY_CAPTURE".equals(operation))) {
        require(
            active.expectedCaptureOperation.equals(operation),
            "wrong Netty capture operation for " + active.id + "/" + active.edge);
        require(value != 0L, "Netty edge capture token was zero");
        require(token == 0L, "Netty edge capture auxiliary token was nonzero");
        long captureThread = nativeThreadId();
        require(
            captureThread == active.sourceThreadId,
            "Netty edge capture ran on the wrong source thread");
        EdgeCapture capture = new EdgeCapture(active, operation, value, captureThread, sequence);
        require(
            LABELLED_EDGE_CAPTURES.putIfAbsent(value, capture) == null,
            "duplicate Netty edge capture token " + value);
        require(
            PENDING_EDGE_CAPTURES.putIfAbsent(value, capture) == null,
            "duplicate pending Netty edge capture token " + value);
        return;
      }

      if ("TASK_LINK".equals(operation)) {
        EdgeCapture capture = LABELLED_EDGE_CAPTURES.get(token);
        if (capture == null) {
          return;
        }
        require(
            PENDING_EDGE_CAPTURES.remove(token, capture),
            "duplicate Netty edge link for token " + token);
        long childThread = nativeThreadId();
        require(
            value == capture.captureThreadId,
            "Netty edge link parent did not match capture thread");
        EdgeCompletion completion = new EdgeCompletion(capture, value, childThread, sequence);
        require(
            COMPLETED_EDGES.putIfAbsent(edgeKey(capture.label.id, capture.label.edge), completion)
                == null,
            "duplicate Netty edge completion for " + capture.label.id + "/" + capture.label.edge);
        System.out.println(
            "OBI_NETTY_EDGE\t"
                + capture.label.id
                + "\t"
                + capture.label.channelId
                + "\t"
                + capture.label.edge
                + "\t"
                + capture.operation
                + "\t"
                + capture.token
                + "\t"
                + capture.captureThreadId
                + "\t"
                + value
                + "\t"
                + childThread
                + "\t"
                + capture.sequence
                + "\t"
                + sequence);
        return;
      }

      if ("TASK_CANCEL".equals(operation) && LABELLED_EDGE_CAPTURES.containsKey(value)) {
        PENDING_EDGE_CAPTURES.remove(value);
        throw new IllegalStateException("Netty edge token was cancelled: " + value);
      }
    } catch (Throwable failure) {
      EDGE_FAILURE.compareAndSet(null, failure);
    }
  }

  private static final class HelperFixture implements AutoCloseable {
    private final Method setEmitData;
    private final Method setTaskEmitter;
    private final Method setRemoteParentEnabled;
    private final Method clearLookup;
    private final Method clearSocket;

    private HelperFixture(
        Method setEmitData,
        Method setTaskEmitter,
        Method setRemoteParentEnabled,
        Method clearLookup,
        Method clearSocket) {
      this.setEmitData = setEmitData;
      this.setTaskEmitter = setTaskEmitter;
      this.setRemoteParentEnabled = setRemoteParentEnabled;
      this.clearLookup = clearLookup;
      this.clearSocket = clearSocket;
    }

    private static HelperFixture install() throws Exception {
      Class<?> bootstrapNative =
          Class.forName("io.opentelemetry.obi.java.BootstrapNative", true, null);
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      Class<?> taskEmitter =
          Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo$TaskContextEmitter", true, null);
      require(bootstrapNative.getClassLoader() == null, "BootstrapNative is not bootstrap loaded");
      require(threadInfo.getClassLoader() == null, "ThreadInfo is not bootstrap loaded");
      require(taskEmitter.getClassLoader() == null, "task emitter is not bootstrap loaded");
      getTid = bootstrapNative.getMethod("gettid");

      Method setEmitData =
          bootstrapNative.getDeclaredMethod("setEmitDataOnSocketForTest", LongBinaryOperator.class);
      setEmitData.setAccessible(true);
      LongBinaryOperator emitter =
          (socketFileDescriptor, address) -> {
            TLS_EMITS.incrementAndGet();
            return 1L;
          };
      setEmitData.invoke(null, emitter);

      Method setTaskEmitter =
          threadInfo.getDeclaredMethod("setTaskContextEmitterForTest", taskEmitter);
      setTaskEmitter.setAccessible(true);
      Object recorder =
          Proxy.newProxyInstance(
              null,
              new Class<?>[] {taskEmitter},
              (proxy, method, values) -> {
                if ("emit".equals(method.getName())) {
                  String operation = String.valueOf(values[0]);
                  long value = ((Number) values[1]).longValue();
                  long token = ((Number) values[2]).longValue();
                  if ("TASK_CAPTURE".equals(operation)) {
                    TASK_CAPTURES.incrementAndGet();
                  } else if ("TASK_RELAY_CAPTURE".equals(operation)) {
                    TASK_RELAY_CAPTURES.incrementAndGet();
                  } else if ("TASK_LINK".equals(operation)) {
                    TASK_LINKS.incrementAndGet();
                  }
                  recordTaskEvent(operation, value, token);
                  System.out.println("OBI_NETTY_TASK\t" + operation + "\t" + value + "\t" + token);
                }
                return null;
              });
      setTaskEmitter.invoke(null, recorder);

      Method setRemoteParentEnabled = threadInfo.getMethod("setRemoteParentEnabled", boolean.class);
      Method clearLookup = threadInfo.getMethod("clearRemoteParentLookupSource");
      Method clearSocket = threadInfo.getMethod("clearRemoteParentSocketFileDescriptor");
      setRemoteParentEnabled.invoke(null, Boolean.TRUE);
      return new HelperFixture(
          setEmitData, setTaskEmitter, setRemoteParentEnabled, clearLookup, clearSocket);
    }

    @Override
    public void close() throws Exception {
      try {
        clearSocket.invoke(null);
        clearLookup.invoke(null);
        setRemoteParentEnabled.invoke(null, Boolean.FALSE);
      } finally {
        try {
          setTaskEmitter.invoke(null, new Object[] {null});
        } finally {
          try {
            setEmitData.invoke(null, new Object[] {null});
          } finally {
            getTid = null;
          }
        }
      }
    }
  }

  private static final class LoopbackTrustManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authenticationType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authenticationType) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}
