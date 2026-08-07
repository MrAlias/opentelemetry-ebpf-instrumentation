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
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;
import io.netty.util.CharsetUtil;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import io.netty.util.concurrent.GlobalEventExecutor;
import io.netty.util.concurrent.ScheduledFuture;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSession;

/**
 * Isolated HTTPS endpoints that observe TLS receive boundaries on the same Apache-proxied request
 * whose Java server span is checked by the acceptance scenario.
 */
final class TlsBoundaryHttpsServer implements AutoCloseable {
  static final String SPLIT_API_PATH = "/api/tls-boundary/split";
  static final String COALESCED_API_PATH = "/api/tls-boundary/coalesced";
  static final int MIN_HEADER_BYTES = (1 << 14) + 1;
  static final int MIN_BODY_BYTES = 32 * 1024;
  static final int PADDING_HEADER_COUNT = 3;
  static final int PADDING_HEADER_VALUE_BYTES = 6000;
  static final String SEQUENCE_HEADER = "x-obi-boundary-sequence";

  private static final int MAX_INITIAL_LINE_BYTES = 4096;
  private static final int MAX_HEADER_BYTES = 32 * 1024;
  private static final int MAX_BODY_BYTES = 40 * 1024;
  private static final int MAX_REQUEST_BYTES = MAX_HEADER_BYTES + MAX_BODY_BYTES;
  private static final int MAX_HTTP_CHUNK_BYTES = 8192;
  private static final int MAX_TLS_RECORDS = 32;
  private static final int MAX_ACTIVE_CHANNELS = 256;
  private static final int REQUEST_DEADLINE_SECONDS = 5;
  static final long COALESCING_GRACE_MILLIS = 150;
  private static final long MAX_COALESCING_GRACE_MILLIS = 1000;
  private static final int MAX_TLS_RECORD_OVERHEAD_BYTES = 256;
  private static final int MAX_TLS_FRAME_BYTES =
      TlsRecordObserver.TLS_HEADER_BYTES + TlsRecordObserver.MAX_TLS_RECORD_PAYLOAD_BYTES;
  private static final long SHUTDOWN_TIMEOUT_SECONDS = 5;
  private static final Pattern MARKER_PATTERN = Pattern.compile("[a-zA-Z0-9._:-]{1,128}");
  private static final AttributeKey<Long> CONNECTION_ID =
      AttributeKey.valueOf(TlsBoundaryHttpsServer.class, "connectionID");
  private static final AtomicLong NEXT_CONNECTION_ID = new AtomicLong(1);

  enum Mode {
    SPLIT("split", SPLIT_API_PATH, 1),
    COALESCED("coalesced", COALESCED_API_PATH, 2);

    private final String value;
    private final String path;
    private final int requestCount;

    Mode(String value, String path, int requestCount) {
      this.value = value;
      this.path = path;
      this.requestCount = requestCount;
    }

    String value() {
      return value;
    }

    String path() {
      return path;
    }

    int requestCount() {
      return requestCount;
    }

    int maxPlaintextBytes() {
      return requestCount * MAX_REQUEST_BYTES;
    }
  }

  private enum DeliveryShape {
    SPLIT("split"),
    PARSER_COALESCED("parser_coalesced"),
    SERIALIZED_PROXY_FALLBACK("serialized_proxy_fallback");

    private final String value;

    DeliveryShape(String value) {
      this.value = value;
    }

    private String value() {
      return value;
    }
  }

  private final EventLoopGroup acceptor;
  private final EventLoopGroup eventLoop;
  private final DefaultEventExecutorGroup parserExecutor;
  private final ChannelGroup childChannels;
  private final Channel splitServerChannel;
  private final Channel coalescedServerChannel;
  private final AtomicBoolean closed = new AtomicBoolean();

  static TlsBoundaryHttpsServer start(
      int splitPort,
      int coalescedPort,
      Path keyStorePath,
      String keyStorePassword,
      String tlsProtocol)
      throws Exception {
    return start(
        splitPort,
        coalescedPort,
        keyStorePath,
        keyStorePassword,
        tlsProtocol,
        COALESCING_GRACE_MILLIS);
  }

  static TlsBoundaryHttpsServer start(
      int splitPort,
      int coalescedPort,
      Path keyStorePath,
      String keyStorePassword,
      String tlsProtocol,
      long coalescingGraceMillis)
      throws Exception {
    if (coalescingGraceMillis <= 0
        || coalescingGraceMillis > MAX_COALESCING_GRACE_MILLIS) {
      throw new IllegalArgumentException("coalescing grace is outside the supported bound");
    }
    TlsContextFactory.Contexts contexts =
        TlsContextFactory.load(keyStorePath, keyStorePassword, tlsProtocol);
    EventLoopGroup acceptor =
        new NioEventLoopGroup(1, namedThreadFactory("obi-tls-boundary-accept-"));
    EventLoopGroup eventLoop =
        new NioEventLoopGroup(1, namedThreadFactory("obi-tls-boundary-io-"));
    DefaultEventExecutorGroup parserExecutor =
        new DefaultEventExecutorGroup(1, namedThreadFactory("obi-tls-boundary-parser-"));
    ChannelGroup childChannels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
    Channel split = null;
    Channel coalesced = null;
    try {
      split =
          bind(
              splitPort,
              Mode.SPLIT,
              contexts,
              tlsProtocol,
              acceptor,
              eventLoop,
              parserExecutor,
              childChannels,
              coalescingGraceMillis);
      coalesced =
          bind(
              coalescedPort,
              Mode.COALESCED,
              contexts,
              tlsProtocol,
              acceptor,
              eventLoop,
              parserExecutor,
              childChannels,
              coalescingGraceMillis);
      return new TlsBoundaryHttpsServer(
          acceptor, eventLoop, parserExecutor, childChannels, split, coalesced);
    } catch (Exception failure) {
      if (failure instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      closeChannel(coalesced);
      closeChannel(split);
      childChannels.close().awaitUninterruptibly(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
      shutdown(parserExecutor);
      shutdown(acceptor);
      shutdown(eventLoop);
      throw failure;
    }
  }

  private TlsBoundaryHttpsServer(
      EventLoopGroup acceptor,
      EventLoopGroup eventLoop,
      DefaultEventExecutorGroup parserExecutor,
      ChannelGroup childChannels,
      Channel splitServerChannel,
      Channel coalescedServerChannel) {
    this.acceptor = acceptor;
    this.eventLoop = eventLoop;
    this.parserExecutor = parserExecutor;
    this.childChannels = childChannels;
    this.splitServerChannel = splitServerChannel;
    this.coalescedServerChannel = coalescedServerChannel;
  }

  int port(Mode mode) {
    Channel channel = mode == Mode.SPLIT ? splitServerChannel : coalescedServerChannel;
    return ((InetSocketAddress) channel.localAddress()).getPort();
  }

  boolean isTerminated() {
    return acceptor.isTerminated() && eventLoop.isTerminated() && parserExecutor.isTerminated();
  }

  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    closeChannel(coalescedServerChannel);
    closeChannel(splitServerChannel);
    childChannels.close().awaitUninterruptibly(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    shutdown(parserExecutor);
    shutdown(acceptor);
    shutdown(eventLoop);
  }

  private static Channel bind(
      int port,
      Mode mode,
      TlsContextFactory.Contexts contexts,
      String tlsProtocol,
      EventLoopGroup acceptor,
      EventLoopGroup eventLoop,
      DefaultEventExecutorGroup parserExecutor,
      ChannelGroup childChannels,
      long coalescingGraceMillis)
      throws InterruptedException {
    ServerBootstrap bootstrap = new ServerBootstrap();
    bootstrap
        .group(acceptor, eventLoop)
        .channel(NioServerSocketChannel.class)
        .childOption(ChannelOption.AUTO_READ, true)
        .childHandler(
            new ChannelInitializer<SocketChannel>() {
              @Override
              protected void initChannel(SocketChannel channel) {
                if (childChannels.size() >= MAX_ACTIVE_CHANNELS) {
                  channel.close();
                  return;
                }
                childChannels.add(channel);
                BoundaryState state = new BoundaryState(mode, coalescingGraceMillis);
                SslHandler tls = contexts.serverContext().newHandler(channel.alloc());
                tls.setHandshakeTimeoutMillis(TimeUnit.SECONDS.toMillis(5));
                channel
                    .pipeline()
                    .addLast("request-read-timeout", new ReadTimeoutHandler(10, TimeUnit.SECONDS));
                channel
                    .pipeline()
                    .addLast(
                        "tls-record-frame",
                        new LengthFieldBasedFrameDecoder(
                            MAX_TLS_FRAME_BYTES,
                            3,
                            2,
                            0,
                            0,
                            true));
                channel.pipeline().addLast("tls-record", new TlsRecordHandler(state));
                channel.pipeline().addLast("tls", tls);
                channel.pipeline().addLast("tls-handshake", new HandshakeHandler(state));
                channel
                    .pipeline()
                    .addLast(
                        "decrypted-boundary",
                        new DecryptedBoundaryHandler(state, coalescingGraceMillis));
                channel
                    .pipeline()
                    .addLast(parserExecutor, "parser-boundary", new ParserBoundaryHandler(state));
                channel
                    .pipeline()
                    .addLast(
                        parserExecutor,
                        "http-codec",
                        new HttpServerCodec(
                            MAX_INITIAL_LINE_BYTES,
                            MAX_HEADER_BYTES,
                            MAX_HTTP_CHUNK_BYTES));
                channel
                    .pipeline()
                    .addLast(
                        parserExecutor,
                        "http-request-emission",
                        new HttpRequestEmissionHandler(state));
                channel
                    .pipeline()
                    .addLast(
                        parserExecutor,
                        "http-aggregate",
                        new HttpObjectAggregator(MAX_BODY_BYTES));
                channel
                    .pipeline()
                    .addLast(
                        parserExecutor,
                        "request",
                        new RequestHandler(state, mode, tlsProtocol));
              }
            });
    return bootstrap.bind(new InetSocketAddress("127.0.0.1", port)).sync().channel();
  }

  private static void closeChannel(Channel channel) {
    if (channel != null) {
      channel.close().awaitUninterruptibly(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }
  }

  private static void shutdown(EventLoopGroup group) {
    group
        .shutdownGracefully(0, SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .awaitUninterruptibly(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
  }

  private static void shutdown(DefaultEventExecutorGroup group) {
    group
        .shutdownGracefully(0, SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .awaitUninterruptibly(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
  }

  private static ThreadFactory namedThreadFactory(String prefix) {
    AtomicInteger sequence = new AtomicInteger();
    return task -> {
      Thread thread = new Thread(task, prefix + sequence.incrementAndGet());
      thread.setDaemon(true);
      return thread;
    };
  }

  private static final class TlsRecordHandler extends ChannelInboundHandlerAdapter {
    private final BoundaryState state;

    private TlsRecordHandler(BoundaryState state) {
      this.state = state;
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) {
      if (!(message instanceof ByteBuf)) {
        state.fail("unexpected_tls_message");
        ReferenceCountUtil.release(message);
        context.close();
        return;
      }
      ByteBuf frame = (ByteBuf) message;
      BoundaryState.WireToken token = state.beginWire(frame);
      try {
        context.fireChannelRead(message);
      } finally {
        state.endWire(token);
      }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      state.fail("tls_record_error");
      context.close();
    }
  }

  private static final class HandshakeHandler extends ChannelInboundHandlerAdapter {
    private final BoundaryState state;

    private HandshakeHandler(BoundaryState state) {
      this.state = state;
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext context, Object event) {
      if (event instanceof SslHandshakeCompletionEvent) {
        SslHandshakeCompletionEvent completion = (SslHandshakeCompletionEvent) event;
        if (completion.isSuccess()) {
          state.handshakeComplete(context);
        } else {
          state.fail("tls_handshake_failed");
        }
      }
      context.fireUserEventTriggered(event);
    }
  }

  private static final class DecryptedBoundaryHandler extends ChannelInboundHandlerAdapter {
    private final BoundaryState state;
    private final long coalescingGraceMillis;
    private ByteBuf aggregate;
    private ByteBuf verificationAggregate;
    private MessageDigest inputDigest;
    private ScheduledFuture<?> coalescingGrace;
    private int firstRequestBytes;
    private boolean serializedFallback;
    private boolean fastPathCommitted;
    private boolean pairEmitted;

    private DecryptedBoundaryHandler(BoundaryState state, long coalescingGraceMillis) {
      this.state = state;
      this.coalescingGraceMillis = coalescingGraceMillis;
      if (state.mode == Mode.COALESCED) {
        inputDigest = sha256();
      }
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) {
      if (!(message instanceof ByteBuf)) {
        state.fail("unexpected_plaintext_message");
        ReferenceCountUtil.release(message);
        context.close();
        return;
      }
      ByteBuf plaintext = (ByteBuf) message;
      if (!state.recordDecrypted(plaintext)) {
        ReferenceCountUtil.release(message);
        context.close();
        return;
      }
      if (state.mode == Mode.SPLIT) {
        context.fireChannelRead(message);
        return;
      }
      coalesce(context, plaintext);
    }

    private void coalesce(ChannelHandlerContext context, ByteBuf plaintext) {
      try {
        if (pairEmitted) {
          state.fail("plaintext_after_request_pair");
          context.close();
          return;
        }
        int readable = plaintext.readableBytes();
        int aggregateBytes = aggregate == null ? 0 : aggregate.readableBytes();
        if (readable <= 0 || aggregateBytes > state.mode.maxPlaintextBytes() - readable) {
          state.fail("request_pair_too_large");
          context.close();
          return;
        }
        updateDigest(inputDigest, plaintext);
        if (aggregate == null) {
          aggregate =
              context
                  .alloc()
                  .buffer(
                      Math.min(state.mode.maxPlaintextBytes(), Math.max(4096, readable)),
                      state.mode.maxPlaintextBytes());
        }
        aggregate.writeBytes(plaintext, plaintext.readerIndex(), readable);

        if (serializedFallback) {
          completeSerializedSecondRequest(context);
          return;
        }

        FrameResult framing = frameRequests(aggregate, state.mode.requestCount());
        if (framing.failure != null) {
          state.fail(framing.failure);
          context.close();
          return;
        }
        if (!framing.complete) {
          observeIncompletePair(context, framing);
          return;
        }

        completeParserCoalescedPair(context, framing);
      } finally {
        ReferenceCountUtil.release(plaintext);
      }
    }

    private void observeIncompletePair(ChannelHandlerContext context, FrameResult framing) {
      if (framing.frames.size() != 1) {
        return;
      }
      int firstBytes = framing.frames.get(0).totalBytes;
      if (aggregate.readableBytes() == firstBytes && !fastPathCommitted) {
        scheduleCoalescingGrace(context);
        return;
      }
      fastPathCommitted = true;
      cancelCoalescingGrace();
    }

    private void scheduleCoalescingGrace(ChannelHandlerContext context) {
      if (coalescingGrace != null) {
        return;
      }
      coalescingGrace =
          context
              .executor()
              .schedule(
                  () -> beginSerializedFallback(context),
                  coalescingGraceMillis,
                  TimeUnit.MILLISECONDS);
    }

    private void beginSerializedFallback(ChannelHandlerContext context) {
      coalescingGrace = null;
      if (pairEmitted
          || serializedFallback
          || fastPathCommitted
          || aggregate == null
          || !context.channel().isActive()) {
        return;
      }
      FrameResult first = frameRequests(aggregate, 1);
      if (first.failure != null || !first.complete || first.frames.size() != 1) {
        state.fail("coalescing_grace_state_mismatch");
        context.close();
        return;
      }

      ByteBuf complete = aggregate;
      aggregate = null;
      boolean forwarded = false;
      try {
        firstRequestBytes = complete.readableBytes();
        verificationAggregate =
            context
                .alloc()
                .buffer(
                    Math.max(4096, firstRequestBytes), state.mode.maxPlaintextBytes());
        verificationAggregate.writeBytes(
            complete, complete.readerIndex(), complete.readableBytes());
        boolean firstCopyExact =
            MessageDigest.isEqual(digest(complete), digest(verificationAggregate));
        serializedFallback = true;
        if (!state.recordSerializedFirstFrame(
            first.frames.get(0), firstCopyExact, verificationAggregate.readableBytes())) {
          context.close();
          return;
        }
        forwarded = true;
      } finally {
        if (!forwarded) {
          complete.release();
          releaseVerificationAggregate();
        }
      }
      context.fireChannelRead(complete);
    }

    private void completeParserCoalescedPair(
        ChannelHandlerContext context, FrameResult framing) {
      cancelCoalescingGrace();
      ByteBuf complete = aggregate;
      aggregate = null;
      boolean forwarded = false;
      try {
        pairEmitted = true;
        byte[] before = inputDigest.digest();
        byte[] after = digest(complete);
        if (!state.recordParserCoalescedFrames(
            framing.frames,
            MessageDigest.isEqual(before, after),
            complete.readableBytes())) {
          context.close();
          return;
        }
        forwarded = true;
      } finally {
        if (!forwarded) {
          complete.release();
        }
      }
      context.fireChannelRead(complete);
    }

    private void completeSerializedSecondRequest(ChannelHandlerContext context) {
      FrameResult second = frameRequests(aggregate, 1);
      if (second.failure != null) {
        state.fail(second.failure);
        context.close();
        return;
      }
      if (!second.complete) {
        return;
      }
      if (verificationAggregate == null
          || verificationAggregate.readableBytes() != firstRequestBytes
          || second.frames.size() != 1) {
        state.fail("serialized_verification_state_mismatch");
        context.close();
        return;
      }

      ByteBuf complete = aggregate;
      aggregate = null;
      boolean forwarded = false;
      try {
        verificationAggregate.writeBytes(
            complete, complete.readerIndex(), complete.readableBytes());
        byte[] before = inputDigest.digest();
        byte[] after = digest(verificationAggregate);
        RequestFrame unshifted = second.frames.get(0);
        RequestFrame shifted =
            new RequestFrame(
                firstRequestBytes + unshifted.startOffset,
                unshifted.headerBytes,
                unshifted.bodyBytes);
        int verificationBytes = verificationAggregate.readableBytes();
        releaseVerificationAggregate();
        pairEmitted = true;
        if (!state.recordSerializedSecondFrame(
            shifted, MessageDigest.isEqual(before, after), verificationBytes)) {
          context.close();
          return;
        }
        forwarded = true;
      } finally {
        if (!forwarded) {
          complete.release();
          releaseVerificationAggregate();
        }
      }
      context.fireChannelRead(complete);
    }

    @Override
    public void channelInactive(ChannelHandlerContext context) {
      cancelCoalescingGrace();
      releaseBuffers();
      state.connectionTerminated();
      context.fireChannelInactive();
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext context) {
      cancelCoalescingGrace();
      releaseBuffers();
      state.connectionTerminated();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      state.fail("decrypted_boundary_error");
      cancelCoalescingGrace();
      releaseBuffers();
      context.close();
    }

    private void cancelCoalescingGrace() {
      if (coalescingGrace != null) {
        coalescingGrace.cancel(false);
        coalescingGrace = null;
      }
    }

    private void releaseBuffers() {
      if (aggregate != null) {
        aggregate.release();
        aggregate = null;
      }
      releaseVerificationAggregate();
    }

    private void releaseVerificationAggregate() {
      if (verificationAggregate != null) {
        verificationAggregate.release();
        verificationAggregate = null;
      }
    }
  }

  private static final class ParserBoundaryHandler extends ChannelInboundHandlerAdapter {
    private final BoundaryState state;

    private ParserBoundaryHandler(BoundaryState state) {
      this.state = state;
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) {
      if (!(message instanceof ByteBuf)) {
        state.fail("invalid_parser_buffer");
        ReferenceCountUtil.release(message);
        context.close();
        return;
      }
      BoundaryState.ParserToken token = state.beginParser((ByteBuf) message);
      if (token == null) {
        ReferenceCountUtil.release(message);
        context.close();
        return;
      }
      try {
        context.fireChannelRead(message);
      } finally {
        state.endParser(token);
      }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      state.fail("parser_boundary_error");
      context.close();
    }
  }

  private static final class HttpRequestEmissionHandler extends ChannelInboundHandlerAdapter {
    private final BoundaryState state;

    private HttpRequestEmissionHandler(BoundaryState state) {
      this.state = state;
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) {
      if (message instanceof HttpRequest
          && !state.recordHttpRequestEmission((HttpRequest) message)) {
        ReferenceCountUtil.release(message);
        context.close();
        return;
      }
      context.fireChannelRead(message);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      state.fail("http_request_emission_error");
      context.close();
    }
  }

  private static final class RequestHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
    private final BoundaryState state;
    private final Mode mode;
    private final String configuredProtocol;
    private final List<PendingRequest> pending = new ArrayList<>();

    private RequestHandler(BoundaryState state, Mode mode, String configuredProtocol) {
      this.state = state;
      this.mode = mode;
      this.configuredProtocol = configuredProtocol;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext context, FullHttpRequest request) {
      if (pending.size() >= mode.requestCount()) {
        reject(context, "trailing_http_request", HttpResponseStatus.BAD_REQUEST);
        return;
      }
      if (!request.decoderResult().isSuccess()
          || request.method() != HttpMethod.POST
          || !mode.path().equals(request.uri())) {
        reject(context, "invalid_http_request", HttpResponseStatus.NOT_FOUND);
        return;
      }

      int sequence = requestSequence(request);
      int expectedSequence = pending.size() + 1;
      if (sequence != expectedSequence || sequence > mode.requestCount()) {
        reject(context, "invalid_request_sequence", HttpResponseStatus.BAD_REQUEST);
        return;
      }
      String marker = request.headers().get("x-obi-demo-id");
      if (marker == null || !MARKER_PATTERN.matcher(marker).matches()) {
        reject(context, "invalid_marker", HttpResponseStatus.BAD_REQUEST);
        return;
      }
      for (PendingRequest accepted : pending) {
        if (accepted.marker.equals(marker)) {
          reject(context, "duplicate_marker", HttpResponseStatus.BAD_REQUEST);
          return;
        }
      }
      boolean keepAlive = HttpUtil.isKeepAlive(request);
      if ((mode == Mode.SPLIT && keepAlive)
          || (mode == Mode.COALESCED && sequence == 1 && !keepAlive)) {
        reject(context, "invalid_connection_lifecycle", HttpResponseStatus.BAD_REQUEST);
        return;
      }
      if (HttpUtil.isTransferEncodingChunked(request)
          || request.headers().getAll(HttpHeaderNames.CONTENT_LENGTH).size() != 1
          || HttpUtil.getContentLength(request, -1) != MIN_BODY_BYTES
          || !validPaddingHeaders(request)) {
        reject(context, "invalid_boundary_request_shape", HttpResponseStatus.BAD_REQUEST);
        return;
      }
      int bodyBytes = request.content().readableBytes();
      if (!state.recordParsedRequest(sequence, bodyBytes)) {
        context.close();
        return;
      }
      pending.add(new PendingRequest(marker));

      if (state.isSerializedFallback()) {
        boolean close = sequence == mode.requestCount();
        if (!state.recordResponse(sequence, close)) {
          context.close();
          return;
        }
        if (close) {
          state.requestFinished();
        }
        BoundaryEvidence evidence = state.evidence();
        sendEvidenceResponses(
            context,
            List.of(pending.get(sequence - 1)),
            List.of(close),
            evidence,
            !close);
        return;
      }

      if (pending.size() != mode.requestCount()) {
        return;
      }

      List<Boolean> responseClose = expectedResponseClose(mode);
      for (int index = 0; index < responseClose.size(); index++) {
        if (!state.recordResponse(index + 1, responseClose.get(index))) {
          context.close();
          return;
        }
      }
      state.requestFinished();
      BoundaryEvidence evidence = state.evidence();
      sendEvidenceResponses(context, pending, responseClose, evidence, false);
    }

    private void sendEvidenceResponses(
        ChannelHandlerContext context,
        List<PendingRequest> requests,
        List<Boolean> closeOrder,
        BoundaryEvidence evidence,
        boolean flushKeepAlive) {
      SslHandler tls = context.pipeline().get(SslHandler.class);
      SSLSession session = tls == null ? null : tls.engine().getSession();
      String protocol = session == null ? configuredProtocol : session.getProtocol();
      String cipher = session == null ? "" : session.getCipherSuite();
      long connectionID = connectionID(context.channel());
      int remotePort = remotePort(context.channel().remoteAddress());
      long tlsReadEvents = ApacheJavaHttpsBackend.bridgeCounter("tlsReadEvents");
      long tlsReadBytes = ApacheJavaHttpsBackend.bridgeCounter("tlsReadBytes");
      String evidenceJson = evidence.toJson();
      HttpResponseStatus status =
          evidence.passed || evidence.partial()
              ? HttpResponseStatus.OK
              : HttpResponseStatus.CONFLICT;
      for (int index = 0; index < requests.size(); index++) {
        PendingRequest accepted = requests.get(index);
        String body =
            responseBody(
                accepted.marker,
                protocol,
                cipher,
                connectionID,
                remotePort,
                tlsReadEvents,
                tlsReadBytes,
                evidenceJson);
        boolean close = closeOrder.get(index);
        FullHttpResponse response = response(status, body, close);
        if (close) {
          context.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        } else if (flushKeepAlive && index == requests.size() - 1) {
          context.writeAndFlush(response);
        } else {
          context.write(response);
        }
      }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      state.fail("request_handler_error");
      context.close();
    }

    private void reject(
        ChannelHandlerContext context, String reason, HttpResponseStatus splitStatus) {
      state.fail(reason);
      if (mode == Mode.SPLIT) {
        context.writeAndFlush(response(splitStatus, "boundary request rejected\n", true))
            .addListener(ChannelFutureListener.CLOSE);
      } else {
        context.close();
      }
    }

    private static long connectionID(Channel channel) {
      Attribute<Long> attribute = channel.attr(CONNECTION_ID);
      Long existing = attribute.get();
      if (existing != null) {
        return existing;
      }
      long created = NEXT_CONNECTION_ID.getAndIncrement();
      if (created <= 0) {
        throw new IllegalStateException("TLS boundary connection identifier exhausted");
      }
      if (attribute.compareAndSet(null, created)) {
        return created;
      }
      return attribute.get();
    }

    private static int remotePort(SocketAddress address) {
      if (address instanceof InetSocketAddress) {
        return ((InetSocketAddress) address).getPort();
      }
      return 0;
    }

    private static boolean validPaddingHeaders(FullHttpRequest request) {
      for (int index = 0; index < PADDING_HEADER_COUNT; index++) {
        List<String> values = request.headers().getAll(paddingHeaderName(index));
        if (values.size() != 1 || values.get(0).length() != PADDING_HEADER_VALUE_BYTES) {
          return false;
        }
        String value = values.get(0);
        for (int offset = 0; offset < value.length(); offset++) {
          if (value.charAt(offset) != 'p') {
            return false;
          }
        }
      }
      return true;
    }

    private static String responseBody(
        String marker,
        String protocol,
        String cipher,
        long connectionID,
        int remotePort,
        long tlsReadEvents,
        long tlsReadBytes,
        String evidenceJson) {
      return String.format(
          Locale.ROOT,
          "{\"marker\":\"%s\",\"secure\":true,\"protocol\":\"HTTP/1.1\","
              + "\"tls_protocol\":\"%s\",\"tls_cipher\":\"%s\","
              + "\"backend_connection_id\":%d,\"backend_remote_port\":%d,"
              + "\"backend_socket_fd\":0,\"tls_read_events\":%d,"
              + "\"tls_read_bytes\":%d,\"backend_kind\":\"netty-tls-boundary\","
              + "\"tls_boundary\":%s}%n",
          ApacheJavaHttpsBackend.jsonEscape(marker),
          ApacheJavaHttpsBackend.jsonEscape(protocol),
          ApacheJavaHttpsBackend.jsonEscape(cipher),
          connectionID,
          remotePort,
          tlsReadEvents,
          tlsReadBytes,
          evidenceJson);
    }

    private static FullHttpResponse response(
        HttpResponseStatus status, String body, boolean close) {
      ByteBuf content = Unpooled.copiedBuffer(body, CharsetUtil.UTF_8);
      FullHttpResponse response =
          new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, content);
      response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
      response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json; charset=utf-8");
      response.headers().set(HttpHeaderNames.CACHE_CONTROL, HttpHeaderValues.NO_STORE);
      response
          .headers()
          .set(
              HttpHeaderNames.CONNECTION,
              close ? HttpHeaderValues.CLOSE : HttpHeaderValues.KEEP_ALIVE);
      return response;
    }

    private static final class PendingRequest {
      private final String marker;

      private PendingRequest(String marker) {
        this.marker = marker;
      }
    }
  }

  private static final class BoundaryState {
    private final Mode mode;
    private final long coalescingGraceMillis;
    private final List<BufferObservation> decrypted = new ArrayList<>();
    private final List<ParserObservation> parsers = new ArrayList<>();
    private final List<Integer> emissionOrder = new ArrayList<>();
    private final List<Integer> emissionParserOrder = new ArrayList<>();
    private final List<Integer> requestOrder = new ArrayList<>();
    private final List<Integer> parsedBodyBytes = new ArrayList<>();
    private final List<Integer> responseOrder = new ArrayList<>();
    private final List<Boolean> responseClose = new ArrayList<>();
    private List<RequestFrame> framedRequests = List.of();
    private DeliveryShape deliveryShape;
    private int eventSequence;
    private int observedPlaintextBytes;
    private int pairVerificationBufferBytes;
    private int headerBytes;
    private int headerWindow;
    private int headerWindowBytes;
    private boolean handshakeComplete;
    private WireToken activeWire;
    private ParserToken activeParser;
    private boolean splitBuffersUnchanged = true;
    private boolean coalescedBytesPreserved;
    private boolean pairVerificationDigestExact;
    private ScheduledFuture<?> requestDeadline;
    private boolean terminal;
    private String failure = "none";

    private BoundaryState(Mode mode, long coalescingGraceMillis) {
      this.mode = mode;
      this.coalescingGraceMillis =
          mode == Mode.COALESCED ? coalescingGraceMillis : 0;
      coalescedBytesPreserved = mode == Mode.SPLIT;
      deliveryShape = mode == Mode.SPLIT ? DeliveryShape.SPLIT : null;
    }

    private synchronized void handshakeComplete(ChannelHandlerContext context) {
      handshakeComplete = true;
      if (terminal || requestDeadline != null) {
        fail("invalid_request_deadline_state");
        context.close();
        return;
      }
      requestDeadline =
          context
              .executor()
              .schedule(
                  () -> {
                    synchronized (BoundaryState.this) {
                      if (terminal) {
                        return;
                      }
                      terminal = true;
                      fail("request_deadline_exceeded");
                    }
                    context.close();
                  },
                  REQUEST_DEADLINE_SECONDS,
                  TimeUnit.SECONDS);
    }

    private synchronized WireToken beginWire(ByteBuf frame) {
      if (activeWire != null) {
        fail("nested_tls_record");
        return null;
      }
      if (frame.readableBytes() < TlsRecordObserver.TLS_HEADER_BYTES) {
        fail("short_tls_record");
        return null;
      }
      int index = frame.readerIndex();
      int type = frame.getUnsignedByte(index);
      int legacyVersion = frame.getUnsignedShort(index + 1);
      int payloadLength = frame.getUnsignedShort(index + 3);
      if (frame.readableBytes() != TlsRecordObserver.TLS_HEADER_BYTES + payloadLength) {
        fail("invalid_tls_record_length");
        return null;
      }
      if (!handshakeComplete || type != TlsRecordObserver.TLS_APPLICATION_DATA) {
        return null;
      }
      activeWire = new WireToken(legacyVersion, payloadLength);
      return activeWire;
    }

    private synchronized void endWire(WireToken token) {
      if (token != null && activeWire != token) {
        fail("tls_record_scope_mismatch");
      }
      if (activeWire != null && !activeWire.used) {
        fail("tls_record_without_plaintext");
      }
      activeWire = null;
    }

    private synchronized boolean recordDecrypted(ByteBuf buffer) {
      if (activeWire == null || activeWire.used || !handshakeComplete) {
        fail("plaintext_without_tls_record");
        return false;
      }
      int length = buffer.readableBytes();
      if (length <= 0
          || decrypted.size() >= MAX_TLS_RECORDS
          || observedPlaintextBytes > mode.maxPlaintextBytes() - length) {
        fail("invalid_plaintext_callback");
        return false;
      }
      if (activeWire.legacyVersion
              != TlsRecordObserver.TLS_APPLICATION_DATA_LEGACY_VERSION
          || activeWire.payloadLength <= length
          || activeWire.payloadLength > length + MAX_TLS_RECORD_OVERHEAD_BYTES
          || activeWire.payloadLength > TlsRecordObserver.MAX_TLS_RECORD_PAYLOAD_BYTES) {
        fail("tls_plaintext_pair_mismatch");
        return false;
      }
      activeWire.used = true;
      decrypted.add(
          new BufferObservation(
              buffer,
              activeWire.legacyVersion,
              activeWire.payloadLength,
              ++eventSequence));
      if (mode == Mode.SPLIT) {
        observeSplitHeader(buffer);
      }
      observedPlaintextBytes += length;
      return "none".equals(failure);
    }

    private synchronized ParserToken beginParser(ByteBuf buffer) {
      if (activeParser != null || parsers.size() >= MAX_TLS_RECORDS) {
        fail("too_many_parser_callbacks");
        return null;
      }
      ParserObservation parser = new ParserObservation(buffer, ++eventSequence);
      parsers.add(parser);
      ParserToken token = new ParserToken(parsers.size());
      activeParser = token;
      if (mode == Mode.SPLIT) {
        int index = parsers.size() - 1;
        if (index >= decrypted.size() || !decrypted.get(index).sameBuffer(buffer)) {
          splitBuffersUnchanged = false;
          fail("split_buffer_changed");
        }
      } else if (deliveryShape == DeliveryShape.PARSER_COALESCED) {
        if (parsers.size() != 1) {
          fail("coalesced_parser_callback_count");
        }
      } else if (deliveryShape == DeliveryShape.SERIALIZED_PROXY_FALLBACK) {
        if (parsers.size() > mode.requestCount()) {
          fail("serialized_parser_callback_count");
        }
      } else {
        fail("parser_before_delivery_shape");
      }
      return "none".equals(failure) ? token : null;
    }

    private synchronized void endParser(ParserToken token) {
      if (activeParser != token) {
        fail("parser_scope_mismatch");
      }
      activeParser = null;
    }

    private synchronized boolean recordParserCoalescedFrames(
        List<RequestFrame> frames, boolean preserved, int verificationBytes) {
      if (mode != Mode.COALESCED
          || deliveryShape != null
          || !framedRequests.isEmpty()
          || frames.size() != mode.requestCount()
          || sumRequestBytes(frames) != observedPlaintextBytes
          || verificationBytes != observedPlaintextBytes) {
        fail("invalid_coalesced_request_frames");
        return false;
      }
      deliveryShape = DeliveryShape.PARSER_COALESCED;
      framedRequests = List.copyOf(frames);
      coalescedBytesPreserved = preserved;
      pairVerificationBufferBytes = verificationBytes;
      pairVerificationDigestExact = preserved;
      if (!preserved) {
        fail("coalesced_bytes_changed");
      }
      return "none".equals(failure);
    }

    private synchronized boolean recordSerializedFirstFrame(
        RequestFrame frame, boolean copyExact, int verificationBytes) {
      if (mode != Mode.COALESCED
          || deliveryShape != null
          || !framedRequests.isEmpty()
          || frame.startOffset != 0
          || frame.totalBytes != observedPlaintextBytes
          || verificationBytes != frame.totalBytes) {
        fail("invalid_serialized_first_frame");
        return false;
      }
      deliveryShape = DeliveryShape.SERIALIZED_PROXY_FALLBACK;
      framedRequests = List.of(frame);
      coalescedBytesPreserved = copyExact;
      pairVerificationBufferBytes = verificationBytes;
      if (!copyExact) {
        fail("serialized_first_copy_changed");
      }
      return "none".equals(failure);
    }

    private synchronized boolean recordSerializedSecondFrame(
        RequestFrame frame, boolean preserved, int verificationBytes) {
      if (mode != Mode.COALESCED
          || deliveryShape != DeliveryShape.SERIALIZED_PROXY_FALLBACK
          || framedRequests.size() != 1
          || frame.startOffset != framedRequests.get(0).totalBytes
          || framedRequests.get(0).totalBytes + frame.totalBytes != observedPlaintextBytes
          || verificationBytes != observedPlaintextBytes) {
        fail("invalid_serialized_second_frame");
        return false;
      }
      framedRequests = List.of(framedRequests.get(0), frame);
      coalescedBytesPreserved = preserved;
      pairVerificationBufferBytes = verificationBytes;
      pairVerificationDigestExact = preserved;
      if (!preserved) {
        fail("serialized_pair_bytes_changed");
      }
      return "none".equals(failure);
    }

    private synchronized boolean isSerializedFallback() {
      return deliveryShape == DeliveryShape.SERIALIZED_PROXY_FALLBACK;
    }

    private synchronized boolean recordHttpRequestEmission(HttpRequest request) {
      int sequence = requestSequence(request);
      int expected = emissionOrder.size() + 1;
      int parserIndex = activeParser == null ? parsers.size() : activeParser.index;
      if (parserIndex <= 0
          || sequence != expected
          || sequence > mode.requestCount()
          || emissionOrder.size() >= mode.requestCount()) {
        fail("invalid_http_request_emission");
        return false;
      }
      emissionOrder.add(sequence);
      emissionParserOrder.add(parserIndex);
      if (mode == Mode.SPLIT && (headerBytes == 0 || decrypted.size() < 2)) {
        fail("request_emitted_before_header_boundaries");
      }
      if (mode == Mode.COALESCED) {
        int expectedParserIndex =
            deliveryShape == DeliveryShape.PARSER_COALESCED ? 1 : sequence;
        if (deliveryShape == null || parserIndex != expectedParserIndex) {
          fail("coalesced_request_emitted_from_wrong_parser_callback");
        }
      }
      return "none".equals(failure);
    }

    private synchronized boolean recordParsedRequest(int sequence, int bodyBytes) {
      int expected = requestOrder.size() + 1;
      if (sequence != expected
          || sequence > mode.requestCount()
          || bodyBytes != MIN_BODY_BYTES
          || emissionOrder.size() < sequence
          || emissionOrder.get(sequence - 1) != sequence) {
        fail("invalid_parsed_request");
        return false;
      }
      if (mode == Mode.SPLIT && framedRequests.isEmpty()) {
        if (headerBytes < MIN_HEADER_BYTES
            || observedPlaintextBytes != headerBytes + bodyBytes) {
          fail("invalid_split_request_frame");
          return false;
        }
        framedRequests = List.of(new RequestFrame(0, headerBytes, bodyBytes));
      }
      if (deliveryShape == null
          || framedRequests.size() < sequence
          || framedRequests.get(sequence - 1).bodyBytes != bodyBytes) {
        fail("parsed_request_frame_mismatch");
        return false;
      }
      requestOrder.add(sequence);
      parsedBodyBytes.add(bodyBytes);
      return "none".equals(failure);
    }

    private synchronized boolean recordResponse(int sequence, boolean close) {
      int expected = responseOrder.size() + 1;
      List<Boolean> expectedClose = expectedResponseClose(mode);
      if (sequence != expected
          || sequence > mode.requestCount()
          || requestOrder.size() < sequence
          || requestOrder.get(sequence - 1) != sequence
          || close != expectedClose.get(sequence - 1)) {
        fail("invalid_response_order");
        return false;
      }
      responseOrder.add(sequence);
      responseClose.add(close);
      return "none".equals(failure);
    }

    private synchronized void requestFinished() {
      if (terminal
          || requestOrder.size() != mode.requestCount()
          || responseOrder.size() != mode.requestCount()) {
        fail("invalid_request_completion");
        return;
      }
      terminal = true;
      cancelRequestDeadline();
    }

    private synchronized void connectionTerminated() {
      if (!terminal) {
        fail("connection_before_request_set_complete");
      }
      terminal = true;
      cancelRequestDeadline();
    }

    private void cancelRequestDeadline() {
      if (requestDeadline != null) {
        requestDeadline.cancel(false);
        requestDeadline = null;
      }
    }

    private synchronized void fail(String reason) {
      if ("none".equals(failure)) {
        failure = reason;
      }
    }

    private synchronized BoundaryEvidence evidence() {
      boolean partialFallbackSnapshot =
          deliveryShape == DeliveryShape.SERIALIZED_PROXY_FALLBACK
              && responseOrder.equals(List.of(1));
      List<RequestFrame> evidenceFrames =
          partialFallbackSnapshot ? List.of(framedRequests.get(0)) : framedRequests;
      int evidencePlaintextBytes = sumRequestBytes(evidenceFrames);
      List<BufferObservation> evidenceDecrypted = new ArrayList<>();
      int evidenceDecryptedBytes = 0;
      for (BufferObservation observation : decrypted) {
        if (partialFallbackSnapshot && evidenceDecryptedBytes >= evidencePlaintextBytes) {
          break;
        }
        evidenceDecrypted.add(observation);
        evidenceDecryptedBytes += observation.readableBytes;
      }
      List<ParserObservation> evidenceParsers =
          partialFallbackSnapshot && parsers.size() > 1
              ? List.of(parsers.get(0))
              : parsers;
      List<Integer> evidenceEmissionOrder =
          prefix(emissionOrder, evidenceFrames.size());
      List<Integer> evidenceEmissionParserOrder =
          prefix(emissionParserOrder, evidenceFrames.size());
      List<Integer> evidenceRequestOrder = prefix(requestOrder, evidenceFrames.size());
      List<Integer> evidenceParsedBodyBytes =
          prefix(parsedBodyBytes, evidenceFrames.size());
      int evidenceVerificationBytes =
          partialFallbackSnapshot ? evidencePlaintextBytes : pairVerificationBufferBytes;
      boolean evidenceVerificationDigestExact =
          !partialFallbackSnapshot && pairVerificationDigestExact;

      List<Integer> versions = new ArrayList<>(evidenceDecrypted.size());
      List<Integer> payloadLengths = new ArrayList<>(evidenceDecrypted.size());
      List<Integer> decryptedLengths = new ArrayList<>(evidenceDecrypted.size());
      for (BufferObservation observation : evidenceDecrypted) {
        versions.add(observation.legacyVersion);
        payloadLengths.add(observation.payloadLength);
        decryptedLengths.add(observation.readableBytes);
      }
      List<Integer> parserLengths = new ArrayList<>(evidenceParsers.size());
      for (ParserObservation parser : evidenceParsers) {
        parserLengths.add(parser.readableBytes);
      }

      List<Integer> requestHeaderBytes = new ArrayList<>(evidenceFrames.size());
      List<Integer> requestBodyBytes = new ArrayList<>(evidenceFrames.size());
      List<Integer> requestTotalBytes = new ArrayList<>(evidenceFrames.size());
      List<Integer> requestHeaderCallbackCounts = new ArrayList<>(evidenceFrames.size());
      for (RequestFrame frame : evidenceFrames) {
        requestHeaderBytes.add(frame.headerBytes);
        requestBodyBytes.add(frame.bodyBytes);
        requestTotalBytes.add(frame.totalBytes);
        requestHeaderCallbackCounts.add(
            callbacksIntersecting(
                decryptedLengths,
                frame.startOffset,
                frame.startOffset + frame.headerBytes));
      }

      int decryptedTotalBytes = sum(decryptedLengths);
      int parserTotalBytes = sum(parserLengths);
      boolean wirePairsExact =
          decryptedLengths.size() >= 2
              && decryptedLengths.size() == versions.size()
              && decryptedLengths.size() == payloadLengths.size();
      boolean headersSpannedRecords = !evidenceFrames.isEmpty();
      for (int index = 0; headersSpannedRecords && index < evidenceFrames.size(); index++) {
        headersSpannedRecords =
            evidenceFrames.get(index).headerBytes >= MIN_HEADER_BYTES
                && requestHeaderCallbackCounts.get(index) >= 2;
      }
      boolean parserShapeExact;
      boolean handoffBeforeParse;
      if (mode == Mode.SPLIT) {
        parserShapeExact = splitBuffersUnchanged && parserLengths.equals(decryptedLengths);
        handoffBeforeParse = decrypted.size() == parsers.size() && !decrypted.isEmpty();
        for (int index = 0; handoffBeforeParse && index < decrypted.size(); index++) {
          handoffBeforeParse =
              decrypted.get(index).eventSequence < parsers.get(index).eventSequence
                  && decrypted.get(index).threadID != parsers.get(index).threadID;
        }
      } else if (deliveryShape == DeliveryShape.PARSER_COALESCED) {
        parserShapeExact =
            coalescedBytesPreserved
                && parserLengths.size() == 1
                && parserLengths.get(0) == decryptedTotalBytes;
        handoffBeforeParse = !decrypted.isEmpty() && parsers.size() == 1;
        for (BufferObservation observation : decrypted) {
          handoffBeforeParse =
              handoffBeforeParse
                  && observation.eventSequence < parsers.get(0).eventSequence
                  && observation.threadID != parsers.get(0).threadID;
        }
      } else if (deliveryShape == DeliveryShape.SERIALIZED_PROXY_FALLBACK) {
        parserShapeExact =
            coalescedBytesPreserved && parserLengths.size() == evidenceFrames.size();
        for (int index = 0; parserShapeExact && index < parserLengths.size(); index++) {
          parserShapeExact = parserLengths.get(index) == evidenceFrames.get(index).totalBytes;
        }
        handoffBeforeParse =
            serializedHandoffBeforeParse(
                evidenceFrames, evidenceDecrypted, evidenceParsers);
      } else {
        parserShapeExact = false;
        handoffBeforeParse = false;
      }
      List<Integer> expected = expectedOrder(mode.requestCount());
      boolean requestsEmittedFromSingleParserCallback =
          mode == Mode.SPLIT
              ? evidenceEmissionParserOrder.size() == 1
              : deliveryShape == DeliveryShape.PARSER_COALESCED
                  && evidenceEmissionParserOrder.equals(List.of(1, 1))
                  && evidenceParsers.size() == 1;
      boolean emissionParserShapeExact =
          mode == Mode.SPLIT
              ? evidenceEmissionParserOrder.size() == 1
              : deliveryShape == DeliveryShape.PARSER_COALESCED
                  ? evidenceEmissionParserOrder.equals(List.of(1, 1))
                  : evidenceEmissionParserOrder.equals(
                      expectedOrder(evidenceEmissionParserOrder.size()));
      boolean requestComplete =
          evidenceFrames.size() == mode.requestCount()
              && evidenceParsedBodyBytes.equals(requestBodyBytes)
              && sum(requestTotalBytes) == decryptedTotalBytes;
      boolean bytesPreserved =
          requestComplete
              && decryptedTotalBytes == parserTotalBytes
              && (mode == Mode.SPLIT ? splitBuffersUnchanged : coalescedBytesPreserved);
      boolean firstResponseKeepsAlive =
          mode == Mode.COALESCED && !responseClose.isEmpty() && !responseClose.get(0);
      boolean finalResponseCloses =
          responseClose.size() == mode.requestCount()
              && responseClose.get(responseClose.size() - 1);
      boolean pairVerificationBounded =
          mode == Mode.SPLIT
              || evidenceVerificationBytes <= mode.maxPlaintextBytes();
      boolean coalescedVerificationExact =
          mode == Mode.SPLIT
              || (evidenceVerificationDigestExact
                  && evidenceVerificationBytes == decryptedTotalBytes);
      String evidencePhase = requestComplete ? "final" : "partial";
      String fallbackReason =
          deliveryShape == DeliveryShape.SERIALIZED_PROXY_FALLBACK
              ? "coalescing_grace_expired"
              : "none";
      boolean passed =
          "none".equals(failure)
              && handshakeComplete
              && "final".equals(evidencePhase)
              && deliveryShape != null
              && evidenceEmissionOrder.equals(expected)
              && evidenceRequestOrder.equals(expected)
              && responseOrder.equals(expected)
              && wirePairsExact
              && headersSpannedRecords
              && parserShapeExact
              && emissionParserShapeExact
              && handoffBeforeParse
              && requestComplete
              && bytesPreserved
              && pairVerificationBounded
              && coalescedVerificationExact
              && finalResponseCloses
              && (mode == Mode.SPLIT || firstResponseKeepsAlive);
      return new BoundaryEvidence(
          mode,
          deliveryShape,
          evidencePhase,
          fallbackReason,
          coalescingGraceMillis,
          deliveryShape == DeliveryShape.SERIALIZED_PROXY_FALLBACK,
          passed,
          failure,
          requestComplete,
          evidenceFrames.size(),
          requestHeaderBytes,
          requestBodyBytes,
          requestTotalBytes,
          requestHeaderCallbackCounts,
          evidenceRequestOrder,
          evidenceEmissionOrder,
          evidenceEmissionParserOrder,
          responseOrder,
          responseClose,
          versions,
          payloadLengths,
          decryptedLengths,
          parserLengths,
          decryptedTotalBytes,
          parserTotalBytes,
          evidenceVerificationBytes,
          mode == Mode.COALESCED ? mode.maxPlaintextBytes() : 0,
          evidenceVerificationDigestExact,
          wirePairsExact,
          headersSpannedRecords,
          parserShapeExact,
          deliveryShape == DeliveryShape.PARSER_COALESCED,
          requestsEmittedFromSingleParserCallback,
          bytesPreserved,
          mode == Mode.SPLIT && splitBuffersUnchanged,
          handoffBeforeParse,
          firstResponseKeepsAlive,
          finalResponseCloses);
    }

    private boolean serializedHandoffBeforeParse(
        List<RequestFrame> frames,
        List<BufferObservation> callbacks,
        List<ParserObservation> parserCallbacks) {
      if (parserCallbacks.size() != frames.size() || parserCallbacks.isEmpty()) {
        return false;
      }
      for (int frameIndex = 0; frameIndex < frames.size(); frameIndex++) {
        RequestFrame frame = frames.get(frameIndex);
        ParserObservation parser = parserCallbacks.get(frameIndex);
        int callbackStart = 0;
        boolean observed = false;
        for (BufferObservation callback : callbacks) {
          int callbackEnd = callbackStart + callback.readableBytes;
          if (callbackEnd > frame.startOffset
              && callbackStart < frame.startOffset + frame.totalBytes) {
            observed = true;
            if (callback.eventSequence >= parser.eventSequence
                || callback.threadID == parser.threadID) {
              return false;
            }
          }
          callbackStart = callbackEnd;
        }
        if (!observed) {
          return false;
        }
      }
      return true;
    }

    private void observeSplitHeader(ByteBuf buffer) {
      if (headerBytes != 0) {
        return;
      }
      int start = buffer.readerIndex();
      int end = buffer.writerIndex();
      for (int index = start; index < end; index++) {
        headerWindow = (headerWindow << 8) | buffer.getUnsignedByte(index);
        if (headerWindowBytes < 4) {
          headerWindowBytes++;
        }
        if (headerWindowBytes == 4 && headerWindow == 0x0d0a0d0a) {
          headerBytes = observedPlaintextBytes + index - start + 1;
        }
        if (headerBytes == 0 && observedPlaintextBytes + index - start + 1 > MAX_HEADER_BYTES) {
          fail("headers_too_large");
          return;
        }
      }
    }

    private static final class WireToken {
      private final int legacyVersion;
      private final int payloadLength;
      private boolean used;

      private WireToken(int legacyVersion, int payloadLength) {
        this.legacyVersion = legacyVersion;
        this.payloadLength = payloadLength;
      }
    }

    private static final class ParserToken {
      private final int index;

      private ParserToken(int index) {
        this.index = index;
      }
    }
  }

  private static final class RequestFrame {
    private final int startOffset;
    private final int headerBytes;
    private final int bodyBytes;
    private final int totalBytes;

    private RequestFrame(int startOffset, int headerBytes, int bodyBytes) {
      this.startOffset = startOffset;
      this.headerBytes = headerBytes;
      this.bodyBytes = bodyBytes;
      totalBytes = headerBytes + bodyBytes;
    }
  }

  private static final class FrameResult {
    private final boolean complete;
    private final List<RequestFrame> frames;
    private final String failure;

    private FrameResult(boolean complete, List<RequestFrame> frames, String failure) {
      this.complete = complete;
      this.frames = List.copyOf(frames);
      this.failure = failure;
    }

    private static FrameResult incomplete(List<RequestFrame> frames) {
      return new FrameResult(false, frames, null);
    }

    private static FrameResult complete(List<RequestFrame> frames) {
      return new FrameResult(true, frames, null);
    }

    private static FrameResult failed(String failure) {
      return new FrameResult(false, List.of(), failure);
    }
  }

  private static final class BufferObservation {
    private final Object message;
    private final int readerIndex;
    private final int writerIndex;
    private final int readableBytes;
    private final int legacyVersion;
    private final int payloadLength;
    private final long threadID;
    private final int eventSequence;

    private BufferObservation(
        ByteBuf buffer, int legacyVersion, int payloadLength, int eventSequence) {
      message = buffer;
      readerIndex = buffer.readerIndex();
      writerIndex = buffer.writerIndex();
      readableBytes = buffer.readableBytes();
      this.legacyVersion = legacyVersion;
      this.payloadLength = payloadLength;
      threadID = Thread.currentThread().getId();
      this.eventSequence = eventSequence;
    }

    private boolean sameBuffer(ByteBuf buffer) {
      return message == buffer
          && readerIndex == buffer.readerIndex()
          && writerIndex == buffer.writerIndex()
          && readableBytes == buffer.readableBytes();
    }
  }

  private static final class ParserObservation {
    private final int readableBytes;
    private final long threadID;
    private final int eventSequence;

    private ParserObservation(ByteBuf buffer, int eventSequence) {
      readableBytes = buffer.readableBytes();
      threadID = Thread.currentThread().getId();
      this.eventSequence = eventSequence;
    }
  }

  private static final class BoundaryEvidence {
    private final Mode mode;
    private final DeliveryShape deliveryShape;
    private final String evidencePhase;
    private final String fallbackReason;
    private final long coalescingGraceMillis;
    private final boolean coalescingGraceExpired;
    private final boolean passed;
    private final String failure;
    private final boolean requestComplete;
    private final int requestCount;
    private final List<Integer> requestHeaderBytes;
    private final List<Integer> requestBodyBytes;
    private final List<Integer> requestTotalBytes;
    private final List<Integer> requestHeaderCallbackCounts;
    private final List<Integer> requestOrder;
    private final List<Integer> emissionOrder;
    private final List<Integer> emissionParserOrder;
    private final List<Integer> responseOrder;
    private final List<Boolean> responseClose;
    private final List<Integer> legacyVersions;
    private final List<Integer> payloadLengths;
    private final List<Integer> decryptedLengths;
    private final List<Integer> parserLengths;
    private final int decryptedTotalBytes;
    private final int parserTotalBytes;
    private final int verificationBufferBytes;
    private final int verificationBufferLimitBytes;
    private final boolean verificationPairDigestExact;
    private final boolean wirePairsExact;
    private final boolean headersSpannedRecords;
    private final boolean parserShapeExact;
    private final boolean parserFacingCoalesced;
    private final boolean requestsEmittedFromSingleParserCallback;
    private final boolean requestBytesPreserved;
    private final boolean splitBuffersUnchanged;
    private final boolean handoffBeforeParse;
    private final boolean firstResponseKeepsAlive;
    private final boolean finalResponseCloses;

    private BoundaryEvidence(
        Mode mode,
        DeliveryShape deliveryShape,
        String evidencePhase,
        String fallbackReason,
        long coalescingGraceMillis,
        boolean coalescingGraceExpired,
        boolean passed,
        String failure,
        boolean requestComplete,
        int requestCount,
        List<Integer> requestHeaderBytes,
        List<Integer> requestBodyBytes,
        List<Integer> requestTotalBytes,
        List<Integer> requestHeaderCallbackCounts,
        List<Integer> requestOrder,
        List<Integer> emissionOrder,
        List<Integer> emissionParserOrder,
        List<Integer> responseOrder,
        List<Boolean> responseClose,
        List<Integer> legacyVersions,
        List<Integer> payloadLengths,
        List<Integer> decryptedLengths,
        List<Integer> parserLengths,
        int decryptedTotalBytes,
        int parserTotalBytes,
        int verificationBufferBytes,
        int verificationBufferLimitBytes,
        boolean verificationPairDigestExact,
        boolean wirePairsExact,
        boolean headersSpannedRecords,
        boolean parserShapeExact,
        boolean parserFacingCoalesced,
        boolean requestsEmittedFromSingleParserCallback,
        boolean requestBytesPreserved,
        boolean splitBuffersUnchanged,
        boolean handoffBeforeParse,
        boolean firstResponseKeepsAlive,
        boolean finalResponseCloses) {
      this.mode = mode;
      this.deliveryShape = deliveryShape;
      this.evidencePhase = evidencePhase;
      this.fallbackReason = fallbackReason;
      this.coalescingGraceMillis = coalescingGraceMillis;
      this.coalescingGraceExpired = coalescingGraceExpired;
      this.passed = passed;
      this.failure = failure;
      this.requestComplete = requestComplete;
      this.requestCount = requestCount;
      this.requestHeaderBytes = List.copyOf(requestHeaderBytes);
      this.requestBodyBytes = List.copyOf(requestBodyBytes);
      this.requestTotalBytes = List.copyOf(requestTotalBytes);
      this.requestHeaderCallbackCounts = List.copyOf(requestHeaderCallbackCounts);
      this.requestOrder = List.copyOf(requestOrder);
      this.emissionOrder = List.copyOf(emissionOrder);
      this.emissionParserOrder = List.copyOf(emissionParserOrder);
      this.responseOrder = List.copyOf(responseOrder);
      this.responseClose = List.copyOf(responseClose);
      this.legacyVersions = List.copyOf(legacyVersions);
      this.payloadLengths = List.copyOf(payloadLengths);
      this.decryptedLengths = List.copyOf(decryptedLengths);
      this.parserLengths = List.copyOf(parserLengths);
      this.decryptedTotalBytes = decryptedTotalBytes;
      this.parserTotalBytes = parserTotalBytes;
      this.verificationBufferBytes = verificationBufferBytes;
      this.verificationBufferLimitBytes = verificationBufferLimitBytes;
      this.verificationPairDigestExact = verificationPairDigestExact;
      this.wirePairsExact = wirePairsExact;
      this.headersSpannedRecords = headersSpannedRecords;
      this.parserShapeExact = parserShapeExact;
      this.parserFacingCoalesced = parserFacingCoalesced;
      this.requestsEmittedFromSingleParserCallback =
          requestsEmittedFromSingleParserCallback;
      this.requestBytesPreserved = requestBytesPreserved;
      this.splitBuffersUnchanged = splitBuffersUnchanged;
      this.handoffBeforeParse = handoffBeforeParse;
      this.firstResponseKeepsAlive = firstResponseKeepsAlive;
      this.finalResponseCloses = finalResponseCloses;
    }

    private boolean partial() {
      return "partial".equals(evidencePhase);
    }

    private String toJson() {
      return String.format(
          Locale.ROOT,
          "{\"mode\":\"%s\",\"delivery_shape\":\"%s\","
              + "\"evidence_phase\":\"%s\",\"fallback_reason\":\"%s\","
              + "\"coalescing_grace_millis\":%d,\"coalescing_grace_expired\":%s,"
              + "\"passed\":%s,\"failure_reason\":\"%s\","
              + "\"request_complete\":%s,\"request_count\":%d,"
              + "\"request_header_bytes\":%s,\"request_body_bytes\":%s,"
              + "\"request_total_bytes\":%s,"
              + "\"request_header_decrypted_callback_counts\":%s,"
              + "\"request_order\":%s,\"emission_order\":%s,"
              + "\"emission_parser_callback_order\":%s,\"response_order\":%s,"
              + "\"response_connection_close\":%s,"
              + "\"tls_application_record_legacy_versions\":%s,"
              + "\"tls_application_record_payload_lengths\":%s,"
              + "\"decrypted_callback_lengths\":%s,\"parser_callback_lengths\":%s,"
              + "\"decrypted_total_bytes\":%d,\"parser_total_bytes\":%d,"
              + "\"parser_callback_count\":%d,"
              + "\"verification_buffer_bytes\":%d,"
              + "\"verification_buffer_limit_bytes\":%d,"
              + "\"verification_pair_digest_exact\":%s,"
              + "\"wire_decrypted_pairs_exact\":%s,\"headers_spanned_records\":%s,"
              + "\"parser_shape_exact\":%s,\"parser_facing_coalesced\":%s,"
              + "\"requests_emitted_from_single_parser_callback\":%s,"
              + "\"request_bytes_preserved\":%s,"
              + "\"split_buffers_forwarded_unchanged\":%s,"
              + "\"handoff_before_parse\":%s,\"first_response_keeps_alive\":%s,"
              + "\"response_forces_connection_close\":%s}",
          mode.value(),
          deliveryShape.value(),
          evidencePhase,
          fallbackReason,
          coalescingGraceMillis,
          coalescingGraceExpired,
          passed,
          failure,
          requestComplete,
          requestCount,
          integerListJson(requestHeaderBytes),
          integerListJson(requestBodyBytes),
          integerListJson(requestTotalBytes),
          integerListJson(requestHeaderCallbackCounts),
          integerListJson(requestOrder),
          integerListJson(emissionOrder),
          integerListJson(emissionParserOrder),
          integerListJson(responseOrder),
          booleanListJson(responseClose),
          integerListJson(legacyVersions),
          integerListJson(payloadLengths),
          integerListJson(decryptedLengths),
          integerListJson(parserLengths),
          decryptedTotalBytes,
          parserTotalBytes,
          parserLengths.size(),
          verificationBufferBytes,
          verificationBufferLimitBytes,
          verificationPairDigestExact,
          wirePairsExact,
          headersSpannedRecords,
          parserShapeExact,
          parserFacingCoalesced,
          requestsEmittedFromSingleParserCallback,
          requestBytesPreserved,
          splitBuffersUnchanged,
          handoffBeforeParse,
          firstResponseKeepsAlive,
          finalResponseCloses);
    }
  }

  private static FrameResult frameRequests(ByteBuf buffer, int expectedCount) {
    int base = buffer.readerIndex();
    int offset = base;
    List<RequestFrame> frames = new ArrayList<>(expectedCount);
    for (int index = 0; index < expectedCount; index++) {
      int available = buffer.writerIndex() - offset;
      int headerBytes = findHeaderBytes(buffer, offset);
      if (headerBytes < 0) {
        return available > MAX_HEADER_BYTES
            ? FrameResult.failed("headers_too_large")
            : FrameResult.incomplete(frames);
      }
      int bodyBytes = parseContentLength(buffer, offset, headerBytes);
      if (bodyBytes < 0 || bodyBytes > MAX_BODY_BYTES) {
        return FrameResult.failed("invalid_content_length");
      }
      RequestFrame frame = new RequestFrame(offset - base, headerBytes, bodyBytes);
      if (frame.totalBytes > MAX_REQUEST_BYTES) {
        return FrameResult.failed("request_too_large");
      }
      if (available < frame.totalBytes) {
        return FrameResult.incomplete(frames);
      }
      frames.add(frame);
      offset += frame.totalBytes;
    }
    if (offset != buffer.writerIndex()) {
      return FrameResult.failed("trailing_request_bytes");
    }
    return FrameResult.complete(frames);
  }

  private static int findHeaderBytes(ByteBuf buffer, int start) {
    int window = 0;
    int windowBytes = 0;
    int limit = Math.min(buffer.writerIndex(), start + MAX_HEADER_BYTES + 1);
    for (int index = start; index < limit; index++) {
      window = (window << 8) | buffer.getUnsignedByte(index);
      if (windowBytes < 4) {
        windowBytes++;
      }
      if (windowBytes == 4 && window == 0x0d0a0d0a) {
        return index - start + 1;
      }
    }
    return -1;
  }

  private static int parseContentLength(ByteBuf buffer, int start, int headerBytes) {
    int end = start + headerBytes;
    int lineStart = start;
    boolean firstLine = true;
    Integer contentLength = null;
    while (lineStart < end - 2) {
      int lineEnd = findCrlf(buffer, lineStart, end);
      if (lineEnd < 0) {
        return -1;
      }
      if (lineEnd == lineStart) {
        break;
      }
      if (firstLine) {
        firstLine = false;
        lineStart = lineEnd + 2;
        continue;
      }
      int colon = indexOf(buffer, (byte) ':', lineStart, lineEnd);
      if (colon <= lineStart) {
        return -1;
      }
      if (asciiEqualsIgnoreCase(buffer, lineStart, colon, "transfer-encoding")) {
        return -1;
      }
      if (asciiEqualsIgnoreCase(buffer, lineStart, colon, "content-length")) {
        if (contentLength != null) {
          return -1;
        }
        int valueStart = colon + 1;
        while (valueStart < lineEnd && isOptionalWhitespace(buffer.getByte(valueStart))) {
          valueStart++;
        }
        int valueEnd = lineEnd;
        while (valueEnd > valueStart && isOptionalWhitespace(buffer.getByte(valueEnd - 1))) {
          valueEnd--;
        }
        if (valueStart == valueEnd) {
          return -1;
        }
        int parsed = 0;
        for (int index = valueStart; index < valueEnd; index++) {
          int digit = buffer.getUnsignedByte(index) - '0';
          if (digit < 0 || digit > 9 || parsed > (MAX_BODY_BYTES - digit) / 10) {
            return -1;
          }
          parsed = parsed * 10 + digit;
        }
        contentLength = parsed;
      }
      lineStart = lineEnd + 2;
    }
    return contentLength == null ? -1 : contentLength;
  }

  private static int findCrlf(ByteBuf buffer, int start, int end) {
    for (int index = start; index + 1 < end; index++) {
      if (buffer.getByte(index) == '\r' && buffer.getByte(index + 1) == '\n') {
        return index;
      }
    }
    return -1;
  }

  private static int indexOf(ByteBuf buffer, byte value, int start, int end) {
    for (int index = start; index < end; index++) {
      if (buffer.getByte(index) == value) {
        return index;
      }
    }
    return -1;
  }

  private static boolean asciiEqualsIgnoreCase(
      ByteBuf buffer, int start, int end, String expected) {
    if (end - start != expected.length()) {
      return false;
    }
    for (int index = 0; index < expected.length(); index++) {
      int actual = buffer.getUnsignedByte(start + index);
      int wanted = expected.charAt(index);
      if (actual >= 'A' && actual <= 'Z') {
        actual += 'a' - 'A';
      }
      if (actual != wanted) {
        return false;
      }
    }
    return true;
  }

  private static boolean isOptionalWhitespace(byte value) {
    return value == ' ' || value == '\t';
  }

  private static MessageDigest sha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException("SHA-256 is unavailable", impossible);
    }
  }

  private static void updateDigest(MessageDigest digest, ByteBuf buffer) {
    for (int index = buffer.readerIndex(); index < buffer.writerIndex(); index++) {
      digest.update(buffer.getByte(index));
    }
  }

  private static byte[] digest(ByteBuf buffer) {
    MessageDigest digest = sha256();
    updateDigest(digest, buffer);
    return digest.digest();
  }

  private static int sum(List<Integer> values) {
    int total = 0;
    for (int value : values) {
      total += value;
    }
    return total;
  }

  private static List<Integer> prefix(List<Integer> values, int limit) {
    return List.copyOf(values.subList(0, Math.min(values.size(), limit)));
  }

  private static int sumRequestBytes(List<RequestFrame> frames) {
    int total = 0;
    for (RequestFrame frame : frames) {
      total += frame.totalBytes;
    }
    return total;
  }

  private static int callbacksIntersecting(List<Integer> lengths, int start, int end) {
    if (start < 0 || end <= start) {
      return 0;
    }
    int callbacks = 0;
    int offset = 0;
    for (int length : lengths) {
      int callbackEnd = offset + length;
      if (callbackEnd > start && offset < end) {
        callbacks++;
      }
      offset = callbackEnd;
      if (offset >= end) {
        break;
      }
    }
    return callbacks;
  }

  private static int requestSequence(HttpRequest request) {
    List<String> values = request.headers().getAll(SEQUENCE_HEADER);
    if (values.size() != 1) {
      return -1;
    }
    if ("1".equals(values.get(0))) {
      return 1;
    }
    if ("2".equals(values.get(0))) {
      return 2;
    }
    return -1;
  }

  private static List<Integer> expectedOrder(int count) {
    List<Integer> order = new ArrayList<>(count);
    for (int sequence = 1; sequence <= count; sequence++) {
      order.add(sequence);
    }
    return List.copyOf(order);
  }

  private static List<Boolean> expectedResponseClose(Mode mode) {
    return mode == Mode.SPLIT ? List.of(true) : List.of(false, true);
  }

  private static String integerListJson(List<Integer> values) {
    return values.toString().replace(" ", "");
  }

  private static String booleanListJson(List<Boolean> values) {
    return values.toString().replace(" ", "");
  }

  private static String paddingHeaderName(int index) {
    return "Z-OBI-Boundary-Pad-" + index;
  }
}
