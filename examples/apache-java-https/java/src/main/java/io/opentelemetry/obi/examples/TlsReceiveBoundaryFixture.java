// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
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
import io.netty.handler.ssl.SslHandler;
import io.netty.util.CharsetUtil;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** Opt-in loopback fixture for observing decrypted TLS callback boundaries. */
final class TlsReceiveBoundaryFixture implements AutoCloseable {
  static final int MAX_HTTP_BYTES = 16 * 1024;
  private static final Duration EXERCISE_TIMEOUT = Duration.ofSeconds(5);
  private static final int MAX_RESPONSE_LINE_BYTES = 4096;
  private static final int MAX_RESPONSE_HEADERS = 64;
  private static final int MAX_RESPONSE_BODY_BYTES = 1024;
  private static final String FIXTURE_PATH_PREFIX = "/obi-tls-boundary/";
  private static final Pattern MARKER_PATTERN = Pattern.compile("[a-zA-Z0-9._:-]{1,128}");

  enum Mode {
    SPLIT("split", 1),
    COALESCED("coalesced", 2);

    private final String queryValue;
    private final int requestCount;

    Mode(String queryValue, int requestCount) {
      this.queryValue = queryValue;
      this.requestCount = requestCount;
    }

    static Mode parse(String value) {
      for (Mode mode : values()) {
        if (mode.queryValue.equals(value)) {
          return mode;
        }
      }
      throw new IllegalArgumentException("mode must be split or coalesced");
    }

    String queryValue() {
      return queryValue;
    }

    int requestCount() {
      return requestCount;
    }
  }

  static final class Evidence {
    private final Mode mode;
    private final List<Integer> expectedPlaintextCallbackLengths;
    private final List<Integer> actualPlaintextCallbackLengths;
    private final List<Long> decryptThreadIDs;
    private final List<Long> parserThreadIDs;
    private final List<Integer> requestOrder;
    private final List<Integer> responseOrder;
    private final boolean buffersForwardedUnchanged;
    private final boolean handoffBeforeParse;
    private final boolean connectionClosed;

    private Evidence(
        Mode mode,
        List<Integer> expectedPlaintextCallbackLengths,
        List<Integer> actualPlaintextCallbackLengths,
        List<Long> decryptThreadIDs,
        List<Long> parserThreadIDs,
        List<Integer> requestOrder,
        List<Integer> responseOrder,
        boolean buffersForwardedUnchanged,
        boolean handoffBeforeParse,
        boolean connectionClosed) {
      this.mode = mode;
      this.expectedPlaintextCallbackLengths = List.copyOf(expectedPlaintextCallbackLengths);
      this.actualPlaintextCallbackLengths = List.copyOf(actualPlaintextCallbackLengths);
      this.decryptThreadIDs = List.copyOf(decryptThreadIDs);
      this.parserThreadIDs = List.copyOf(parserThreadIDs);
      this.requestOrder = List.copyOf(requestOrder);
      this.responseOrder = List.copyOf(responseOrder);
      this.buffersForwardedUnchanged = buffersForwardedUnchanged;
      this.handoffBeforeParse = handoffBeforeParse;
      this.connectionClosed = connectionClosed;
    }

    boolean passed() {
      return shapeExact()
          && buffersForwardedUnchanged
          && handoffBeforeParse
          && requestOrder.equals(expectedOrder(mode.requestCount()))
          && responseOrder.equals(expectedOrder(mode.requestCount()))
          && connectionClosed;
    }

    boolean shapeExact() {
      return actualPlaintextCallbackLengths.equals(expectedPlaintextCallbackLengths);
    }

    List<Integer> expectedPlaintextCallbackLengths() {
      return expectedPlaintextCallbackLengths;
    }

    List<Integer> actualPlaintextCallbackLengths() {
      return actualPlaintextCallbackLengths;
    }

    List<Long> decryptThreadIDs() {
      return decryptThreadIDs;
    }

    List<Long> parserThreadIDs() {
      return parserThreadIDs;
    }

    List<Integer> requestOrder() {
      return requestOrder;
    }

    List<Integer> responseOrder() {
      return responseOrder;
    }

    boolean buffersForwardedUnchanged() {
      return buffersForwardedUnchanged;
    }

    boolean handoffBeforeParse() {
      return handoffBeforeParse;
    }

    boolean connectionClosed() {
      return connectionClosed;
    }

    String toJson() {
      return String.format(
          Locale.ROOT,
          "{\"mode\":\"%s\",\"passed\":%s,\"shape_exact\":%s,"
              + "\"expected_plaintext_callback_lengths\":%s,"
              + "\"actual_plaintext_callback_lengths\":%s,"
              + "\"request_order\":%s,\"response_order\":%s,"
              + "\"buffers_forwarded_unchanged\":%s,"
              + "\"handoff_before_parse\":%s,\"connection_closed\":%s}%n",
          mode.queryValue(),
          passed(),
          shapeExact(),
          integerListJson(expectedPlaintextCallbackLengths),
          integerListJson(actualPlaintextCallbackLengths),
          integerListJson(requestOrder),
          integerListJson(responseOrder),
          buffersForwardedUnchanged,
          handoffBeforeParse,
          connectionClosed);
    }
  }

  private final SslContext serverSslContext;
  private final SSLSocketFactory clientSocketFactory;
  private final String tlsProtocol;
  private final EventLoopGroup eventLoop;
  private final DefaultEventExecutorGroup parserExecutor;
  private final AtomicReference<RunState> activeRun = new AtomicReference<>();
  private final AtomicBoolean closed = new AtomicBoolean();
  private final Set<Channel> childChannels = Collections.synchronizedSet(new HashSet<>());
  private final Channel serverChannel;
  private final int port;

  static TlsReceiveBoundaryFixture start(
      Path keyStorePath, String keyStorePassword, String tlsProtocol) throws Exception {
    TlsContextFactory.Contexts contexts =
        TlsContextFactory.load(keyStorePath, keyStorePassword, tlsProtocol);
    return new TlsReceiveBoundaryFixture(
        contexts.serverContext(), contexts.clientSocketFactory(), tlsProtocol);
  }

  private TlsReceiveBoundaryFixture(
      SslContext serverSslContext, SSLSocketFactory clientSocketFactory, String tlsProtocol)
      throws InterruptedException {
    this.serverSslContext = serverSslContext;
    this.clientSocketFactory = clientSocketFactory;
    this.tlsProtocol = tlsProtocol;
    eventLoop = new NioEventLoopGroup(1, namedThreadFactory("obi-tls-boundary-io-"));
    parserExecutor =
        new DefaultEventExecutorGroup(1, namedThreadFactory("obi-tls-boundary-parser-"));

    Channel bound = null;
    try {
      ServerBootstrap bootstrap = new ServerBootstrap();
      bootstrap
          .group(eventLoop)
          .channel(NioServerSocketChannel.class)
          .childOption(ChannelOption.AUTO_READ, true)
          .childHandler(
              new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel channel) {
                  RunState state = activeRun.get();
                  if (state == null || !state.claimConnection()) {
                    channel.close();
                    return;
                  }
                  childChannels.add(channel);
                  channel.closeFuture().addListener(ignored -> childChannels.remove(channel));

                  SslHandler sslHandler = serverSslContext.newHandler(channel.alloc());
                  sslHandler.setHandshakeTimeoutMillis(EXERCISE_TIMEOUT.toMillis());
                  channel.pipeline().addLast("tls", sslHandler);
                  channel.pipeline().addLast("decrypted-boundary", new BoundaryRecorder(state));
                  channel.pipeline().addLast(parserExecutor, "parser-thread", new ParserRecorder(state));
                  channel.pipeline().addLast(parserExecutor, "http-codec", new HttpServerCodec());
                  channel
                      .pipeline()
                      .addLast(
                          parserExecutor,
                          "http-aggregate",
                          new HttpObjectAggregator(MAX_HTTP_BYTES));
                  channel
                      .pipeline()
                      .addLast(parserExecutor, "fixture-response", new ResponseHandler(state));
                }
              });
      bound = bootstrap.bind(new InetSocketAddress("127.0.0.1", 0)).sync().channel();
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw interrupted;
    } catch (RuntimeException failure) {
      shutdownExecutors();
      throw failure;
    }
    serverChannel = bound;
    port = ((InetSocketAddress) serverChannel.localAddress()).getPort();
  }

  synchronized Evidence exercise(Mode mode, String marker) throws IOException {
    if (closed.get()) {
      throw new IllegalStateException("TLS receive-boundary fixture is closed");
    }
    if (marker == null || !MARKER_PATTERN.matcher(marker).matches()) {
      throw new IllegalArgumentException("marker contains unsupported characters");
    }

    RequestPlan plan = RequestPlan.create(mode, marker, port);
    RunState state = new RunState(plan);
    if (!activeRun.compareAndSet(null, state)) {
      throw new IllegalStateException("TLS receive-boundary fixture is already active");
    }

    List<Integer> responseOrder = new ArrayList<>(mode.requestCount());
    long deadlineNanos = System.nanoTime() + EXERCISE_TIMEOUT.toNanos();
    boolean clientClosed = false;
    try {
      try (SSLSocket socket =
          (SSLSocket) clientSocketFactory.createSocket()) {
        socket.setEnabledProtocols(new String[] {tlsProtocol});
        socket.connect(
            new InetSocketAddress("127.0.0.1", port), remainingMillis(deadlineNanos));
        socket.setSoTimeout(remainingMillis(deadlineNanos));
        socket.startHandshake();

        OutputStream output = socket.getOutputStream();
        InputStream input = new BufferedInputStream(socket.getInputStream());
        for (int index = 0; index < plan.writes.size(); index++) {
          output.write(plan.writes.get(index));
          output.flush();
          if (mode == Mode.SPLIT && index == 0) {
            state.awaitFirstPlaintext(deadlineNanos);
          }
        }

        for (int expected = 1; expected <= mode.requestCount(); expected++) {
          socket.setSoTimeout(remainingMillis(deadlineNanos));
          responseOrder.add(readResponseSequence(input));
        }
        socket.setSoTimeout(remainingMillis(deadlineNanos));
        if (input.read() != -1) {
          throw new IOException("fixture server sent bytes after the final response");
        }
      } finally {
        clientClosed = true;
      }

      state.awaitRequests(deadlineNanos);
      state.awaitConnectionClosed(deadlineNanos);
      state.throwIfFailed();
      return state.evidence(responseOrder, clientClosed);
    } finally {
      activeRun.compareAndSet(state, null);
    }
  }

  int port() {
    return port;
  }

  boolean isTerminated() {
    return eventLoop.isTerminated() && parserExecutor.isTerminated();
  }

  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }

    RunState state = activeRun.getAndSet(null);
    if (state != null) {
      state.fail(new IOException("fixture closed during an active exercise"));
    }
    synchronized (childChannels) {
      for (Channel child : childChannels) {
        child.close().awaitUninterruptibly(EXERCISE_TIMEOUT.toMillis());
      }
      childChannels.clear();
    }
    serverChannel.close().awaitUninterruptibly(EXERCISE_TIMEOUT.toMillis());
    shutdownExecutors();
  }

  private void shutdownExecutors() {
    parserExecutor
        .shutdownGracefully(0, 2, TimeUnit.SECONDS)
        .awaitUninterruptibly(EXERCISE_TIMEOUT.toMillis());
    eventLoop
        .shutdownGracefully(0, 2, TimeUnit.SECONDS)
        .awaitUninterruptibly(EXERCISE_TIMEOUT.toMillis());
  }

  private static int remainingMillis(long deadlineNanos) throws SocketTimeoutException {
    long remainingNanos = deadlineNanos - System.nanoTime();
    if (remainingNanos <= 0) {
      throw new SocketTimeoutException("TLS receive-boundary fixture timed out");
    }
    return (int) Math.max(1, TimeUnit.NANOSECONDS.toMillis(remainingNanos));
  }

  private static int readResponseSequence(InputStream input) throws IOException {
    String statusLine = readAsciiLine(input);
    if (!statusLine.startsWith("HTTP/1.1 200 ")) {
      throw new IOException("fixture returned an unexpected HTTP status");
    }

    int contentLength = -1;
    boolean headersComplete = false;
    for (int count = 0; count < MAX_RESPONSE_HEADERS; count++) {
      String line = readAsciiLine(input);
      if (line.isEmpty()) {
        headersComplete = true;
        break;
      }
      int separator = line.indexOf(':');
      if (separator <= 0) {
        throw new IOException("fixture returned a malformed HTTP header");
      }
      if (line.substring(0, separator).equalsIgnoreCase("content-length")) {
        try {
          contentLength = Integer.parseInt(line.substring(separator + 1).trim());
        } catch (NumberFormatException invalid) {
          throw new IOException("fixture returned an invalid content length", invalid);
        }
      }
    }
    if (!headersComplete) {
      throw new IOException("fixture response contains too many HTTP headers");
    }
    if (contentLength < 0 || contentLength > MAX_RESPONSE_BODY_BYTES) {
      throw new IOException("fixture returned an invalid response body size");
    }

    byte[] body = input.readNBytes(contentLength);
    if (body.length != contentLength) {
      throw new EOFException("fixture response body ended early");
    }
    String value = new String(body, StandardCharsets.US_ASCII);
    String prefix = "boundary-response-";
    if (!value.startsWith(prefix) || !value.endsWith("\n")) {
      throw new IOException("fixture returned an unexpected response body");
    }
    try {
      return Integer.parseInt(value.substring(prefix.length(), value.length() - 1));
    } catch (NumberFormatException invalid) {
      throw new IOException("fixture response sequence is invalid", invalid);
    }
  }

  private static String readAsciiLine(InputStream input) throws IOException {
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    boolean carriageReturn = false;
    while (line.size() < MAX_RESPONSE_LINE_BYTES) {
      int next = input.read();
      if (next < 0) {
        throw new EOFException("fixture response ended before a complete line");
      }
      if (carriageReturn) {
        if (next == '\n') {
          return line.toString(StandardCharsets.US_ASCII);
        }
        line.write('\r');
        carriageReturn = false;
      }
      if (next == '\r') {
        carriageReturn = true;
      } else {
        line.write(next);
      }
    }
    throw new IOException("fixture response line exceeds the configured limit");
  }

  private static ThreadFactory namedThreadFactory(String prefix) {
    AtomicInteger sequence = new AtomicInteger();
    return task -> {
      Thread thread = new Thread(task, prefix + sequence.incrementAndGet());
      thread.setDaemon(true);
      return thread;
    };
  }

  private static List<Integer> expectedOrder(int count) {
    List<Integer> order = new ArrayList<>(count);
    for (int sequence = 1; sequence <= count; sequence++) {
      order.add(sequence);
    }
    return order;
  }

  private static String integerListJson(List<Integer> values) {
    return values.toString().replace(" ", "");
  }

  private static final class RequestPlan {
    private final Mode mode;
    private final String marker;
    private final List<byte[]> writes;
    private final List<Integer> expectedCallbackLengths;

    private RequestPlan(Mode mode, String marker, List<byte[]> writes) {
      this.mode = mode;
      this.marker = marker;
      this.writes = List.copyOf(writes);
      List<Integer> lengths = new ArrayList<>(writes.size());
      for (byte[] write : writes) {
        lengths.add(write.length);
      }
      expectedCallbackLengths = List.copyOf(lengths);
    }

    private static RequestPlan create(Mode mode, String marker, int port) {
      byte[] first = requestBytes(1, marker, port, mode == Mode.SPLIT);
      if (mode == Mode.SPLIT) {
        String request = new String(first, StandardCharsets.US_ASCII);
        int splitOffset = request.indexOf("HTTP/1.1") + 2;
        if (splitOffset <= 1 || splitOffset >= first.length) {
          throw new IllegalStateException("unable to split the fixture request line");
        }
        return new RequestPlan(
            mode,
            marker,
            List.of(
                Arrays.copyOfRange(first, 0, splitOffset),
                Arrays.copyOfRange(first, splitOffset, first.length)));
      }

      byte[] second = requestBytes(2, marker, port, true);
      byte[] combined = Arrays.copyOf(first, first.length + second.length);
      System.arraycopy(second, 0, combined, first.length, second.length);
      return new RequestPlan(mode, marker, List.of(combined));
    }

    private static byte[] requestBytes(int sequence, String marker, int port, boolean close) {
      String request =
          "GET "
              + FIXTURE_PATH_PREFIX
              + sequence
              + " HTTP/1.1\r\nHost: 127.0.0.1:"
              + port
              + "\r\nX-OBI-Demo-ID: "
              + marker
              + "\r\nContent-Length: 0\r\nConnection: "
              + (close ? "close" : "keep-alive")
              + "\r\n\r\n";
      byte[] bytes = request.getBytes(StandardCharsets.US_ASCII);
      if (bytes.length > MAX_HTTP_BYTES) {
        throw new IllegalArgumentException("fixture request exceeds the configured limit");
      }
      return bytes;
    }
  }

  private static final class BufferObservation {
    private final Object message;
    private final int readerIndex;
    private final int writerIndex;
    private final int readableBytes;
    private final long threadID;
    private final int eventSequence;

    private BufferObservation(ByteBuf message, int eventSequence) {
      this.message = message;
      readerIndex = message.readerIndex();
      writerIndex = message.writerIndex();
      readableBytes = message.readableBytes();
      threadID = Thread.currentThread().getId();
      this.eventSequence = eventSequence;
    }
  }

  private static final class ParserObservation {
    private final long threadID;
    private final int eventSequence;

    private ParserObservation(int eventSequence) {
      threadID = Thread.currentThread().getId();
      this.eventSequence = eventSequence;
    }
  }

  private static final class RunState {
    private final RequestPlan plan;
    private final CountDownLatch firstPlaintext = new CountDownLatch(1);
    private final CountDownLatch requests;
    private final CountDownLatch connectionClosed = new CountDownLatch(1);
    private final List<BufferObservation> boundaries = new ArrayList<>();
    private final List<ParserObservation> parsers = new ArrayList<>();
    private final List<Integer> requestOrder = new ArrayList<>();
    private final AtomicInteger eventSequence = new AtomicInteger();
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    private boolean connectionClaimed;
    private boolean buffersForwardedUnchanged = true;

    private RunState(RequestPlan plan) {
      this.plan = plan;
      requests = new CountDownLatch(plan.mode.requestCount());
    }

    private synchronized boolean claimConnection() {
      if (connectionClaimed) {
        return false;
      }
      connectionClaimed = true;
      return true;
    }

    private synchronized void recordBoundary(ByteBuf message) {
      boundaries.add(new BufferObservation(message, eventSequence.incrementAndGet()));
      firstPlaintext.countDown();
    }

    private synchronized void recordParser(Object message) {
      int index = parsers.size();
      ParserObservation parser = new ParserObservation(eventSequence.incrementAndGet());
      parsers.add(parser);
      if (index >= boundaries.size() || !(message instanceof ByteBuf)) {
        buffersForwardedUnchanged = false;
        return;
      }
      ByteBuf buffer = (ByteBuf) message;
      BufferObservation boundary = boundaries.get(index);
      if (boundary.message != message
          || boundary.readerIndex != buffer.readerIndex()
          || boundary.writerIndex != buffer.writerIndex()
          || boundary.readableBytes != buffer.readableBytes()) {
        buffersForwardedUnchanged = false;
      }
    }

    private synchronized int recordRequest(FullHttpRequest request) {
      String path = request.uri();
      if (!path.startsWith(FIXTURE_PATH_PREFIX)) {
        fail(new IOException("fixture received an unexpected request path"));
        return -1;
      }
      int sequence;
      try {
        sequence = Integer.parseInt(path.substring(FIXTURE_PATH_PREFIX.length()));
      } catch (NumberFormatException invalid) {
        fail(new IOException("fixture received an invalid request sequence", invalid));
        return -1;
      }
      if (!plan.marker.equals(request.headers().get("x-obi-demo-id"))) {
        fail(new IOException("fixture received an unexpected request marker"));
        return -1;
      }
      requestOrder.add(sequence);
      requests.countDown();
      return sequence;
    }

    private void recordConnectionClosed() {
      connectionClosed.countDown();
    }

    private void fail(Throwable cause) {
      failure.compareAndSet(null, cause);
      while (requests.getCount() > 0) {
        requests.countDown();
      }
      firstPlaintext.countDown();
      connectionClosed.countDown();
    }

    private void awaitFirstPlaintext(long deadlineNanos) throws IOException {
      await(firstPlaintext, deadlineNanos, "first decrypted callback");
      throwIfFailed();
    }

    private void awaitRequests(long deadlineNanos) throws IOException {
      await(requests, deadlineNanos, "parsed requests");
      throwIfFailed();
    }

    private void awaitConnectionClosed(long deadlineNanos) throws IOException {
      await(connectionClosed, deadlineNanos, "connection close");
      throwIfFailed();
    }

    private void throwIfFailed() throws IOException {
      Throwable cause = failure.get();
      if (cause == null) {
        return;
      }
      if (cause instanceof IOException) {
        throw (IOException) cause;
      }
      throw new IOException("TLS receive-boundary fixture failed", cause);
    }

    private synchronized Evidence evidence(List<Integer> responseOrder, boolean clientClosed) {
      List<Integer> actualLengths = new ArrayList<>(boundaries.size());
      List<Long> decryptThreadIDs = new ArrayList<>(boundaries.size());
      for (BufferObservation boundary : boundaries) {
        actualLengths.add(boundary.readableBytes);
        decryptThreadIDs.add(boundary.threadID);
      }
      List<Long> parserThreadIDs = new ArrayList<>(parsers.size());
      for (ParserObservation parser : parsers) {
        parserThreadIDs.add(parser.threadID);
      }

      boolean handoff = boundaries.size() == parsers.size() && !boundaries.isEmpty();
      for (int index = 0; handoff && index < boundaries.size(); index++) {
        BufferObservation boundary = boundaries.get(index);
        ParserObservation parser = parsers.get(index);
        handoff =
            boundary.eventSequence < parser.eventSequence
                && boundary.threadID != parser.threadID;
      }
      return new Evidence(
          plan.mode,
          plan.expectedCallbackLengths,
          actualLengths,
          decryptThreadIDs,
          parserThreadIDs,
          requestOrder,
          responseOrder,
          buffersForwardedUnchanged,
          handoff,
          clientClosed && connectionClosed.getCount() == 0);
    }

    private static void await(CountDownLatch latch, long deadlineNanos, String operation)
        throws IOException {
      long remaining = deadlineNanos - System.nanoTime();
      if (remaining <= 0) {
        throw new SocketTimeoutException("fixture timed out waiting for " + operation);
      }
      try {
        if (!latch.await(remaining, TimeUnit.NANOSECONDS)) {
          throw new SocketTimeoutException("fixture timed out waiting for " + operation);
        }
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        throw new IOException("fixture interrupted while waiting for " + operation, interrupted);
      }
    }
  }

  private static final class BoundaryRecorder extends ChannelInboundHandlerAdapter {
    private final RunState state;

    private BoundaryRecorder(RunState state) {
      this.state = state;
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) {
      if (message instanceof ByteBuf) {
        state.recordBoundary((ByteBuf) message);
      }
      context.fireChannelRead(message);
    }

    @Override
    public void channelInactive(ChannelHandlerContext context) {
      state.recordConnectionClosed();
      context.fireChannelInactive();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      state.fail(cause);
      context.close();
    }
  }

  private static final class ParserRecorder extends ChannelInboundHandlerAdapter {
    private final RunState state;

    private ParserRecorder(RunState state) {
      this.state = state;
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) {
      state.recordParser(message);
      context.fireChannelRead(message);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      state.fail(cause);
      context.close();
    }
  }

  private static final class ResponseHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
    private final RunState state;

    private ResponseHandler(RunState state) {
      this.state = state;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext context, FullHttpRequest request) {
      int sequence = state.recordRequest(request);
      if (sequence < 1) {
        context.close();
        return;
      }

      ByteBuf content =
          Unpooled.copiedBuffer("boundary-response-" + sequence + "\n", CharsetUtil.US_ASCII);
      FullHttpResponse response =
          new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, content);
      response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
      response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=us-ascii");

      boolean keepAlive = HttpUtil.isKeepAlive(request);
      if (keepAlive) {
        response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        context.writeAndFlush(response);
      } else {
        response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
        context.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
      }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      state.fail(cause);
      context.close();
    }
  }
}
