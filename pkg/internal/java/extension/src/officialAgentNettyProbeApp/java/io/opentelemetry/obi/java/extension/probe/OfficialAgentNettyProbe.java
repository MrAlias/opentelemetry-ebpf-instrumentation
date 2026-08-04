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
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.ChannelGroupFuture;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
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
import io.netty.util.concurrent.Future;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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
  private static final AttributeKey<Long> TLS_THREAD = AttributeKey.valueOf("obi-tls-thread");
  private static final AtomicInteger TLS_EMITS = new AtomicInteger();
  private static final AtomicInteger TASK_CAPTURES = new AtomicInteger();
  private static final AtomicInteger TASK_LINKS = new AtomicInteger();
  private static final AtomicInteger CLEANUPS = new AtomicInteger();
  private static final CountDownLatch CLEANUP_COMPLETE = new CountDownLatch(5);
  private static final AtomicReference<Throwable> CLEANUP_FAILURE = new AtomicReference<>();

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
          serve(output, keyStoreFile, bossGroup, channelGroup, tlsGroup);
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
      DefaultEventExecutorGroup tlsGroup)
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
                      channel
                          .pipeline()
                          .addLast(tlsGroup, "tls", sslContext.newHandler(channel.alloc()))
                          .addLast(tlsGroup, "plaintext-marker", new PlaintextMarker())
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

      runRequests(port);
      require(CLEANUP_COMPLETE.await(10, TimeUnit.SECONDS), "Netty cleanup probes timed out");
      Throwable cleanupFailure = CLEANUP_FAILURE.get();
      if (cleanupFailure != null) {
        throw new IllegalStateException("Netty task cleanup probe failed", cleanupFailure);
      }
      require(CLEANUPS.get() == 5, "Netty task cleanup probe count mismatch");
      awaitServerSpans(output, 5, 10, TimeUnit.SECONDS);
      Class<?> bridge =
          Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", true, null);
      String diagnostics = (String) bridge.getMethod("diagnosticsSnapshot").invoke(null);
      require(TLS_EMITS.get() > 0, "Netty TLS plaintext fixture was not invoked");
      require(TASK_CAPTURES.get() > 0, "Netty handoff did not capture a task context");
      require(TASK_LINKS.get() > 0, "Netty handoff did not link a task context");
      System.out.println("OBI_STOCK_NETTY_PROBE diagnostics=" + diagnostics);
      System.out.println(
          "OBI_STOCK_NETTY_PROBE tls_emits="
              + TLS_EMITS.get()
              + " task_captures="
              + TASK_CAPTURES.get()
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

  private static final class PlaintextMarker extends ChannelInboundHandlerAdapter {
    @Override
    public void channelRead(ChannelHandlerContext context, Object message) throws Exception {
      context.channel().attr(TLS_THREAD).set(Thread.currentThread().getId());
      context.fireChannelRead(message);
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
      int channelFd = actualSocketFileDescriptor(context.channel());
      Authority authority = Authority.current();
      long requestThread = Thread.currentThread().getId();
      require(tlsThread != null && tlsThread.longValue() > 0, "missing TLS executor thread");
      require(channelFd >= 0, "cannot resolve accepted Netty socket descriptor");
      require(tlsThread.longValue() != requestThread, "Netty TLS handoff stayed on one thread");
      require(authority.source == 2, "Netty handler lost task lookup authority");
      require(authority.lifecycleActive, "Netty handler lost its socket lifecycle");
      require(authority.socketFileDescriptor == -1, "Netty handler retained a consumed socket");
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
              + "\tLIVE\t"
              + authority.socketFileDescriptor);

      ByteBuf body = Unpooled.copiedBuffer(id + ":ok", CharsetUtil.UTF_8);
      FullHttpResponse response =
          new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, body);
      response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=utf-8");
      HttpUtil.setContentLength(response, body.readableBytes());
      boolean keepAlive = HttpUtil.isKeepAlive(request);
      if (keepAlive) {
        response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
      }
      ChannelFuture write = context.writeAndFlush(response);
      scheduleCleanup(context, id);
      if (!keepAlive) {
        write.addListener(io.netty.channel.ChannelFutureListener.CLOSE);
      }
    }

    private static void scheduleCleanup(ChannelHandlerContext context, String id) {
      String channelId = context.channel().id().asLongText();
      context
          .executor()
          .execute(
              () -> {
                try {
                  Authority authority = Authority.current();
                  require(authority.source != 2, "Netty task lookup authority leaked after exit");
                  require(
                      !authority.directAuthority,
                      "Netty direct receive authority leaked after task exit");
                  require(
                      !authority.lifecycleActive,
                      "Netty socket lifecycle authority leaked after task exit");
                  require(
                      authority.socketFileDescriptor == -1,
                      "Netty socket descriptor leaked after task exit");
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
                          + authority.socketFileDescriptor);
                  CLEANUPS.incrementAndGet();
                } catch (Throwable failure) {
                  CLEANUP_FAILURE.compareAndSet(null, failure);
                } finally {
                  CLEANUP_COMPLETE.countDown();
                }
              });
    }
  }

  private static final class Authority {
    private final int source;
    private final boolean directAuthority;
    private final boolean lifecycleActive;
    private final int lifecycleIdentity;
    private final int socketFileDescriptor;

    private Authority(
        int source,
        boolean directAuthority,
        boolean lifecycleActive,
        int lifecycleIdentity,
        int socketFileDescriptor) {
      this.source = source;
      this.directAuthority = directAuthority;
      this.lifecycleActive = lifecycleActive;
      this.lifecycleIdentity = lifecycleIdentity;
      this.socketFileDescriptor = socketFileDescriptor;
    }

    private static Authority current() throws Exception {
      Class<?> threadInfo = Class.forName("io.opentelemetry.obi.java.ebpf.ThreadInfo", true, null);
      int source =
          ((Integer) threadInfo.getMethod("remoteParentLookupSource").invoke(null)).intValue();
      boolean directAuthority =
          ((Boolean) threadInfo.getMethod("hasRemoteParentDirectReceiveAuthority").invoke(null))
              .booleanValue();
      Object lifecycle = threadInfo.getMethod("remoteParentLookupLifecycle").invoke(null);
      boolean active =
          lifecycle != null
              && Boolean.TRUE.equals(lifecycle.getClass().getMethod("active").invoke(lifecycle));
      int socketFileDescriptor =
          ((Integer) threadInfo.getMethod("remoteParentSocketFileDescriptor").invoke(null))
              .intValue();
      return new Authority(
          source,
          directAuthority,
          active,
          lifecycle == null ? 0 : System.identityHashCode(lifecycle),
          socketFileDescriptor);
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
                  if ("TASK_CAPTURE".equals(operation)) {
                    TASK_CAPTURES.incrementAndGet();
                  } else if ("TASK_LINK".equals(operation)) {
                    TASK_LINKS.incrementAndGet();
                  }
                  System.out.println(
                      "OBI_NETTY_TASK\t" + operation + "\t" + values[1] + "\t" + values[2]);
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
          setEmitData.invoke(null, new Object[] {null});
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
