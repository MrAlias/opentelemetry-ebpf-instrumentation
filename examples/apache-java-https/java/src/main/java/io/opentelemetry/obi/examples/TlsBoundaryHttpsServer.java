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

  private static final int MAX_INITIAL_LINE_BYTES = 4096;
  private static final int MAX_HEADER_BYTES = 32 * 1024;
  private static final int MAX_BODY_BYTES = 40 * 1024;
  private static final int MAX_REQUEST_BYTES = MAX_HEADER_BYTES + MAX_BODY_BYTES;
  private static final int MAX_HTTP_CHUNK_BYTES = 8192;
  private static final int MAX_TLS_RECORDS = 32;
  private static final int MAX_ACTIVE_CHANNELS = 256;
  private static final int REQUEST_DEADLINE_SECONDS = 5;
  private static final int MAX_TLS_RECORD_OVERHEAD_BYTES = 256;
  private static final int MAX_TLS_FRAME_BYTES =
      TlsRecordObserver.TLS_HEADER_BYTES + TlsRecordObserver.MAX_TLS_RECORD_PAYLOAD_BYTES;
  private static final long SHUTDOWN_TIMEOUT_SECONDS = 5;
  private static final Pattern MARKER_PATTERN = Pattern.compile("[a-zA-Z0-9._:-]{1,128}");
  private static final AttributeKey<Long> CONNECTION_ID =
      AttributeKey.valueOf(TlsBoundaryHttpsServer.class, "connectionID");
  private static final AtomicLong NEXT_CONNECTION_ID = new AtomicLong(1);

  enum Mode {
    SPLIT("split", SPLIT_API_PATH),
    COALESCED("coalesced", COALESCED_API_PATH);

    private final String value;
    private final String path;

    Mode(String value, String path) {
      this.value = value;
      this.path = path;
    }

    String value() {
      return value;
    }

    String path() {
      return path;
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
              childChannels);
      coalesced =
          bind(
              coalescedPort,
              Mode.COALESCED,
              contexts,
              tlsProtocol,
              acceptor,
              eventLoop,
              parserExecutor,
              childChannels);
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
      ChannelGroup childChannels)
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
                BoundaryState state = new BoundaryState(mode);
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
                    .addLast("decrypted-boundary", new DecryptedBoundaryHandler(state));
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
    private ByteBuf aggregate;
    private MessageDigest inputDigest;
    private int expectedRequestBytes = -1;
    private boolean emitted;

    private DecryptedBoundaryHandler(BoundaryState state) {
      this.state = state;
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
        if (emitted) {
          state.fail("plaintext_after_request");
          context.close();
          return;
        }
        int readable = plaintext.readableBytes();
        int aggregateBytes = aggregate == null ? 0 : aggregate.readableBytes();
        if (readable <= 0 || aggregateBytes > MAX_REQUEST_BYTES - readable) {
          state.fail("request_too_large");
          context.close();
          return;
        }
        updateDigest(inputDigest, plaintext);
        if (aggregate == null) {
          aggregate = context.alloc().buffer(Math.min(MAX_REQUEST_BYTES, Math.max(4096, readable)));
        }
        aggregate.writeBytes(plaintext, plaintext.readerIndex(), readable);

        if (expectedRequestBytes < 0) {
          int headerBytes = findHeaderBytes(aggregate);
          if (headerBytes < 0) {
            if (aggregate.readableBytes() > MAX_HEADER_BYTES) {
              state.fail("headers_too_large");
              context.close();
            }
            return;
          }
          int contentLength = parseContentLength(aggregate, headerBytes);
          if (contentLength < 0 || contentLength > MAX_BODY_BYTES) {
            state.fail("invalid_content_length");
            context.close();
            return;
          }
          expectedRequestBytes = headerBytes + contentLength;
        }

        int buffered = aggregate.readableBytes();
        if (buffered > expectedRequestBytes) {
          state.fail("multiple_requests_on_connection");
          context.close();
          return;
        }
        if (buffered == expectedRequestBytes) {
          ByteBuf complete = aggregate;
          aggregate = null;
          emitted = true;
          byte[] before = inputDigest.digest();
          byte[] after = digest(complete);
          state.recordCoalescedPreservation(MessageDigest.isEqual(before, after));
          context.fireChannelRead(complete);
        }
      } finally {
        ReferenceCountUtil.release(plaintext);
      }
    }

    @Override
    public void channelInactive(ChannelHandlerContext context) {
      releaseAggregate();
      state.connectionTerminated();
      context.fireChannelInactive();
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext context) {
      releaseAggregate();
      state.connectionTerminated();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      state.fail("decrypted_boundary_error");
      releaseAggregate();
      context.close();
    }

    private void releaseAggregate() {
      if (aggregate != null) {
        aggregate.release();
        aggregate = null;
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
      if (!(message instanceof ByteBuf) || !state.recordParser((ByteBuf) message)) {
        state.fail("invalid_parser_buffer");
        ReferenceCountUtil.release(message);
        context.close();
        return;
      }
      context.fireChannelRead(message);
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
      if (message instanceof HttpRequest && !state.recordHttpRequestEmission()) {
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
    private boolean handled;

    private RequestHandler(BoundaryState state, Mode mode, String configuredProtocol) {
      this.state = state;
      this.mode = mode;
      this.configuredProtocol = configuredProtocol;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext context, FullHttpRequest request) {
      if (handled) {
        state.fail("multiple_parsed_requests");
        respond(context, HttpResponseStatus.BAD_REQUEST, "multiple requests are not supported\n");
        return;
      }
      handled = true;
      state.requestFinished();
      if (!request.decoderResult().isSuccess()
          || request.method() != HttpMethod.POST
          || !mode.path().equals(request.uri())) {
        state.fail("invalid_http_request");
        respond(context, HttpResponseStatus.NOT_FOUND, "not found\n");
        return;
      }

      String marker = request.headers().get("x-obi-demo-id");
      if (marker == null || !MARKER_PATTERN.matcher(marker).matches()) {
        state.fail("invalid_marker");
        respond(context, HttpResponseStatus.BAD_REQUEST, "invalid x-obi-demo-id header\n");
        return;
      }
      if (HttpUtil.isTransferEncodingChunked(request)
          || request.headers().getAll(HttpHeaderNames.CONTENT_LENGTH).size() != 1
          || HttpUtil.getContentLength(request, -1) != MIN_BODY_BYTES
          || !validPaddingHeaders(request)) {
        state.fail("invalid_boundary_request_shape");
        respond(context, HttpResponseStatus.BAD_REQUEST, "invalid boundary request shape\n");
        return;
      }
      int bodyBytes = request.content().readableBytes();
      BoundaryEvidence evidence = state.evidence(bodyBytes);

      SslHandler tls = context.pipeline().get(SslHandler.class);
      SSLSession session = tls == null ? null : tls.engine().getSession();
      String protocol = session == null ? configuredProtocol : session.getProtocol();
      String cipher = session == null ? "" : session.getCipherSuite();
      long connectionID = connectionID(context.channel());
      int remotePort = remotePort(context.channel().remoteAddress());
      String body =
          String.format(
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
              ApacheJavaHttpsBackend.bridgeCounter("tlsReadEvents"),
              ApacheJavaHttpsBackend.bridgeCounter("tlsReadBytes"),
              evidence.toJson());
      respond(
          context,
          evidence.passed ? HttpResponseStatus.OK : HttpResponseStatus.CONFLICT,
          body);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      state.fail("request_handler_error");
      context.close();
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

    private static void respond(
        ChannelHandlerContext context, HttpResponseStatus status, String body) {
      ByteBuf content = Unpooled.copiedBuffer(body, CharsetUtil.UTF_8);
      FullHttpResponse response =
          new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, content);
      response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
      response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json; charset=utf-8");
      response.headers().set(HttpHeaderNames.CACHE_CONTROL, HttpHeaderValues.NO_STORE);
      response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
      context.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }
  }

  private static final class BoundaryState {
    private final Mode mode;
    private final List<BufferObservation> decrypted = new ArrayList<>();
    private final List<ParserObservation> parsers = new ArrayList<>();
    private int eventSequence;
    private int observedPlaintextBytes;
    private int headerBytes;
    private int headerWindow;
    private int headerWindowBytes;
    private boolean handshakeComplete;
    private WireToken activeWire;
    private boolean splitBuffersUnchanged = true;
    private boolean coalescedBytesPreserved;
    private boolean requestEmitted;
    private int decryptedCallbacksAtRequestEmission;
    private int parserCallbacksAtRequestEmission;
    private ScheduledFuture<?> requestDeadline;
    private boolean terminal;
    private String failure = "none";

    private BoundaryState(Mode mode) {
      this.mode = mode;
      coalescedBytesPreserved = mode == Mode.SPLIT;
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
          || observedPlaintextBytes > MAX_REQUEST_BYTES - length) {
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
      observeHeader(buffer);
      return "none".equals(failure);
    }

    private synchronized boolean recordParser(ByteBuf buffer) {
      if (parsers.size() >= MAX_TLS_RECORDS) {
        fail("too_many_parser_callbacks");
        return false;
      }
      ParserObservation parser = new ParserObservation(buffer, ++eventSequence);
      parsers.add(parser);
      if (mode == Mode.SPLIT) {
        int index = parsers.size() - 1;
        if (index >= decrypted.size() || !decrypted.get(index).sameBuffer(buffer)) {
          splitBuffersUnchanged = false;
          fail("split_buffer_changed");
        }
      }
      return "none".equals(failure);
    }

    private synchronized void recordCoalescedPreservation(boolean preserved) {
      coalescedBytesPreserved = preserved;
      if (!preserved) {
        fail("coalesced_bytes_changed");
      }
    }

    private synchronized boolean recordHttpRequestEmission() {
      if (requestEmitted) {
        fail("multiple_http_requests_emitted");
        return false;
      }
      requestEmitted = true;
      decryptedCallbacksAtRequestEmission = decrypted.size();
      parserCallbacksAtRequestEmission = parsers.size();
      if (headerBytes == 0 || decryptedCallbacksAtRequestEmission < 2) {
        fail("request_emitted_before_header_boundaries");
      }
      return true;
    }

    private synchronized void requestFinished() {
      if (terminal) {
        return;
      }
      terminal = true;
      cancelRequestDeadline();
    }

    private synchronized void connectionTerminated() {
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

    private synchronized BoundaryEvidence evidence(int bodyBytes) {
      List<Integer> versions = new ArrayList<>(decrypted.size());
      List<Integer> payloadLengths = new ArrayList<>(decrypted.size());
      List<Integer> decryptedLengths = new ArrayList<>(decrypted.size());
      for (BufferObservation observation : decrypted) {
        versions.add(observation.legacyVersion);
        payloadLengths.add(observation.payloadLength);
        decryptedLengths.add(observation.readableBytes);
      }
      List<Integer> parserLengths = new ArrayList<>(parsers.size());
      for (ParserObservation parser : parsers) {
        parserLengths.add(parser.readableBytes);
      }

      int requestBytes = sum(decryptedLengths);
      int headerCallbackCount = callbacksCovering(decryptedLengths, headerBytes);
      boolean wirePairsExact =
          decryptedLengths.size() >= 2
              && decryptedLengths.size() == versions.size()
              && decryptedLengths.size() == payloadLengths.size();
      boolean headerSpannedRecords =
          headerBytes >= MIN_HEADER_BYTES
              && headerCallbackCount >= 2
              && decryptedCallbacksAtRequestEmission >= headerCallbackCount;
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
      } else {
        parserShapeExact =
            coalescedBytesPreserved
                && parserLengths.size() == 1
                && parserLengths.get(0) == requestBytes;
        handoffBeforeParse = !decrypted.isEmpty() && parsers.size() == 1;
        for (BufferObservation observation : decrypted) {
          handoffBeforeParse =
              handoffBeforeParse
                  && observation.eventSequence < parsers.get(0).eventSequence
                  && observation.threadID != parsers.get(0).threadID;
        }
      }
      boolean requestComplete =
          headerBytes > 0
              && bodyBytes == MIN_BODY_BYTES
              && requestBytes == headerBytes + bodyBytes;
      boolean passed =
          "none".equals(failure)
              && handshakeComplete
              && requestEmitted
              && wirePairsExact
              && headerSpannedRecords
              && parserShapeExact
              && coalescedBytesPreserved
              && handoffBeforeParse
              && requestComplete;
      return new BoundaryEvidence(
          mode,
          passed,
          failure,
          requestComplete,
          headerBytes,
          bodyBytes,
          requestBytes,
          headerCallbackCount,
          decryptedCallbacksAtRequestEmission,
          parserCallbacksAtRequestEmission,
          versions,
          payloadLengths,
          decryptedLengths,
          parserLengths,
          wirePairsExact,
          headerSpannedRecords,
          parserShapeExact,
          mode == Mode.COALESCED,
          coalescedBytesPreserved,
          splitBuffersUnchanged,
          handoffBeforeParse,
          true);
    }

    private void observeHeader(ByteBuf buffer) {
      if (headerBytes != 0) {
        observedPlaintextBytes += buffer.readableBytes();
        return;
      }
      int start = buffer.readerIndex();
      int end = buffer.writerIndex();
      for (int index = start; index < end; index++) {
        observedPlaintextBytes++;
        headerWindow = (headerWindow << 8) | buffer.getUnsignedByte(index);
        if (headerWindowBytes < 4) {
          headerWindowBytes++;
        }
        if (headerWindowBytes == 4 && headerWindow == 0x0d0a0d0a) {
          headerBytes = observedPlaintextBytes;
        }
        if (headerBytes == 0 && observedPlaintextBytes > MAX_HEADER_BYTES) {
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
    private final boolean passed;
    private final String failure;
    private final boolean requestComplete;
    private final int headerBytes;
    private final int bodyBytes;
    private final int requestBytes;
    private final int headerCallbackCount;
    private final int decryptedCallbacksAtRequestEmission;
    private final int parserCallbacksAtRequestEmission;
    private final List<Integer> legacyVersions;
    private final List<Integer> payloadLengths;
    private final List<Integer> decryptedLengths;
    private final List<Integer> parserLengths;
    private final boolean wirePairsExact;
    private final boolean headerSpannedRecords;
    private final boolean parserShapeExact;
    private final boolean parserFacingCoalesced;
    private final boolean requestBytesPreserved;
    private final boolean splitBuffersUnchanged;
    private final boolean handoffBeforeParse;
    private final boolean closeRequested;

    private BoundaryEvidence(
        Mode mode,
        boolean passed,
        String failure,
        boolean requestComplete,
        int headerBytes,
        int bodyBytes,
        int requestBytes,
        int headerCallbackCount,
        int decryptedCallbacksAtRequestEmission,
        int parserCallbacksAtRequestEmission,
        List<Integer> legacyVersions,
        List<Integer> payloadLengths,
        List<Integer> decryptedLengths,
        List<Integer> parserLengths,
        boolean wirePairsExact,
        boolean headerSpannedRecords,
        boolean parserShapeExact,
        boolean parserFacingCoalesced,
        boolean requestBytesPreserved,
        boolean splitBuffersUnchanged,
        boolean handoffBeforeParse,
        boolean closeRequested) {
      this.mode = mode;
      this.passed = passed;
      this.failure = failure;
      this.requestComplete = requestComplete;
      this.headerBytes = headerBytes;
      this.bodyBytes = bodyBytes;
      this.requestBytes = requestBytes;
      this.headerCallbackCount = headerCallbackCount;
      this.decryptedCallbacksAtRequestEmission = decryptedCallbacksAtRequestEmission;
      this.parserCallbacksAtRequestEmission = parserCallbacksAtRequestEmission;
      this.legacyVersions = List.copyOf(legacyVersions);
      this.payloadLengths = List.copyOf(payloadLengths);
      this.decryptedLengths = List.copyOf(decryptedLengths);
      this.parserLengths = List.copyOf(parserLengths);
      this.wirePairsExact = wirePairsExact;
      this.headerSpannedRecords = headerSpannedRecords;
      this.parserShapeExact = parserShapeExact;
      this.parserFacingCoalesced = parserFacingCoalesced;
      this.requestBytesPreserved = requestBytesPreserved;
      this.splitBuffersUnchanged = splitBuffersUnchanged;
      this.handoffBeforeParse = handoffBeforeParse;
      this.closeRequested = closeRequested;
    }

    private String toJson() {
      return String.format(
          Locale.ROOT,
          "{\"mode\":\"%s\",\"passed\":%s,\"failure_reason\":\"%s\","
              + "\"request_complete\":%s,\"header_bytes\":%d,\"body_bytes\":%d,"
              + "\"request_bytes\":%d,\"header_decrypted_callback_count\":%d,"
              + "\"decrypted_callbacks_before_request\":%d,"
              + "\"parser_callbacks_before_request\":%d,"
              + "\"tls_application_record_legacy_versions\":%s,"
              + "\"tls_application_record_payload_lengths\":%s,"
              + "\"decrypted_callback_lengths\":%s,\"parser_callback_lengths\":%s,"
              + "\"wire_decrypted_pairs_exact\":%s,\"header_spanned_records\":%s,"
              + "\"parser_shape_exact\":%s,\"parser_facing_coalesced\":%s,"
              + "\"request_bytes_preserved\":%s,\"split_buffers_forwarded_unchanged\":%s,"
              + "\"handoff_before_parse\":%s,\"response_forces_connection_close\":%s}",
          mode.value(),
          passed,
          failure,
          requestComplete,
          headerBytes,
          bodyBytes,
          requestBytes,
          headerCallbackCount,
          decryptedCallbacksAtRequestEmission,
          parserCallbacksAtRequestEmission,
          integerListJson(legacyVersions),
          integerListJson(payloadLengths),
          integerListJson(decryptedLengths),
          integerListJson(parserLengths),
          wirePairsExact,
          headerSpannedRecords,
          parserShapeExact,
          parserFacingCoalesced,
          requestBytesPreserved,
          splitBuffersUnchanged,
          handoffBeforeParse,
          closeRequested);
    }
  }

  private static int findHeaderBytes(ByteBuf buffer) {
    int window = 0;
    int windowBytes = 0;
    int start = buffer.readerIndex();
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

  private static int parseContentLength(ByteBuf buffer, int headerBytes) {
    int start = buffer.readerIndex();
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

  private static int callbacksCovering(List<Integer> lengths, int bytes) {
    if (bytes <= 0) {
      return 0;
    }
    int total = 0;
    for (int index = 0; index < lengths.size(); index++) {
      total += lengths.get(index);
      if (total >= bytes) {
        return index + 1;
      }
    }
    return 0;
  }

  private static String integerListJson(List<Integer> values) {
    return values.toString().replace(" ", "");
  }

  private static String paddingHeaderName(int index) {
    return "Z-OBI-Boundary-Pad-" + index;
  }
}
