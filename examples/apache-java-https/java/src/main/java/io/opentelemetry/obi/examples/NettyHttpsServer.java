// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
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
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.Attribute;
import io.netty.util.AttributeKey;
import io.netty.util.CharsetUtil;
import io.netty.util.concurrent.ScheduledFuture;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSession;

final class NettyHttpsServer implements AutoCloseable {
  static final String API_PATH = "/api/netty-server";
  static final String COALESCED_BRIDGE_PATH = "/api/coalesced-bridge";
  static final String COALESCED_SEQUENCE_HEADER = "x-obi-coalesced-sequence";
  private static final int MAX_REQUEST_BYTES = 64 * 1024;
  private static final int MAX_COALESCED_PLAINTEXT_BYTES = 8 * 1024;
  private static final long COALESCED_PAIR_DEADLINE_MILLIS = 5_000;
  private static final long MAX_COALESCED_PAIR_DEADLINE_MILLIS = 10_000;
  private static final Pattern MARKER_PATTERN = Pattern.compile("[a-zA-Z0-9._:-]{1,128}");
  private static final AttributeKey<Long> CONNECTION_ID =
      AttributeKey.valueOf(NettyHttpsServer.class, "connectionID");
  private static final AtomicLong NEXT_CONNECTION_ID = new AtomicLong(1);

  private final EventLoopGroup acceptor;
  private final EventLoopGroup eventLoop;
  private final Channel serverChannel;
  private final AtomicBoolean closed = new AtomicBoolean();

  static NettyHttpsServer start(
      int port, Path keyStorePath, String keyStorePassword, String tlsProtocol) throws Exception {
    return start(
        port,
        keyStorePath,
        keyStorePassword,
        tlsProtocol,
        COALESCED_PAIR_DEADLINE_MILLIS);
  }

  static NettyHttpsServer start(
      int port,
      Path keyStorePath,
      String keyStorePassword,
      String tlsProtocol,
      long coalescedPairDeadlineMillis)
      throws Exception {
    if (coalescedPairDeadlineMillis <= 0
        || coalescedPairDeadlineMillis > MAX_COALESCED_PAIR_DEADLINE_MILLIS) {
      throw new IllegalArgumentException("coalesced pair deadline is outside the supported bound");
    }
    TlsContextFactory.Contexts contexts =
        TlsContextFactory.load(keyStorePath, keyStorePassword, tlsProtocol);
    EventLoopGroup acceptor = new NioEventLoopGroup(1);
    EventLoopGroup eventLoop = new NioEventLoopGroup(1);
    try {
      ServerBootstrap bootstrap = new ServerBootstrap();
      bootstrap
          .group(acceptor, eventLoop)
          .channel(NioServerSocketChannel.class)
          .childOption(ChannelOption.AUTO_READ, true)
          .childHandler(
              new ChannelInitializer<SocketChannel>() {
                @Override
                protected void initChannel(SocketChannel channel) {
                  PlaintextState plaintextState = new PlaintextState();
                  channel
                      .pipeline()
                      .addLast("tls", contexts.serverContext().newHandler(channel.alloc()));
                  channel
                      .pipeline()
                      .addLast("plaintext-boundary", new PlaintextBoundaryHandler(plaintextState));
                  channel.pipeline().addLast("http-codec", new HttpServerCodec());
                  channel
                      .pipeline()
                      .addLast("http-aggregate", new HttpObjectAggregator(MAX_REQUEST_BYTES));
                  channel
                      .pipeline()
                      .addLast(
                          "request",
                          new RequestHandler(
                              tlsProtocol, plaintextState, coalescedPairDeadlineMillis));
                }
              });
      Channel serverChannel =
          bootstrap.bind(new InetSocketAddress("127.0.0.1", port)).sync().channel();
      return new NettyHttpsServer(acceptor, eventLoop, serverChannel);
    } catch (Exception failure) {
      if (failure instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      shutdown(acceptor);
      shutdown(eventLoop);
      throw failure;
    }
  }

  private NettyHttpsServer(
      EventLoopGroup acceptor, EventLoopGroup eventLoop, Channel serverChannel) {
    this.acceptor = acceptor;
    this.eventLoop = eventLoop;
    this.serverChannel = serverChannel;
  }

  int port() {
    return ((InetSocketAddress) serverChannel.localAddress()).getPort();
  }

  boolean isTerminated() {
    return acceptor.isTerminated() && eventLoop.isTerminated();
  }

  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    serverChannel.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
    shutdown(acceptor);
    shutdown(eventLoop);
  }

  private static void shutdown(EventLoopGroup group) {
    group.shutdownGracefully(0, 5, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS);
  }

  private static final class RequestHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
    private final String configuredProtocol;
    private final PlaintextState plaintextState;
    private final long coalescedPairDeadlineMillis;
    private final List<String> coalescedMarkers = new ArrayList<>(2);
    private ScheduledFuture<?> coalescedPairDeadline;

    private RequestHandler(
        String configuredProtocol,
        PlaintextState plaintextState,
        long coalescedPairDeadlineMillis) {
      this.configuredProtocol = configuredProtocol;
      this.plaintextState = plaintextState;
      this.coalescedPairDeadlineMillis = coalescedPairDeadlineMillis;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext context, FullHttpRequest request) {
      QueryStringDecoder target = new QueryStringDecoder(request.uri());
      if (COALESCED_BRIDGE_PATH.equals(target.path())) {
        handleCoalesced(context, request, target);
        return;
      }
      if (!request.decoderResult().isSuccess()
          || request.method() != HttpMethod.GET
          || !API_PATH.equals(target.path())) {
        respond(context, request, HttpResponseStatus.NOT_FOUND, "not found\n");
        return;
      }

      String marker = request.headers().get("x-obi-demo-id");
      if (marker == null || !MARKER_PATTERN.matcher(marker).matches()) {
        respond(context, request, HttpResponseStatus.BAD_REQUEST, "invalid x-obi-demo-id header\n");
        return;
      }

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
                  + "\"tls_read_bytes\":%d,\"backend_kind\":\"netty\"}%n",
              ApacheJavaHttpsBackend.jsonEscape(marker),
              ApacheJavaHttpsBackend.jsonEscape(protocol),
              ApacheJavaHttpsBackend.jsonEscape(cipher),
              connectionID,
              remotePort,
              ApacheJavaHttpsBackend.bridgeCounter("tlsReadEvents"),
              ApacheJavaHttpsBackend.bridgeCounter("tlsReadBytes"));
      respond(context, request, HttpResponseStatus.OK, body);
    }

    private void handleCoalesced(
        ChannelHandlerContext context, FullHttpRequest request, QueryStringDecoder target) {
      int expectedSequence = coalescedMarkers.size() + 1;
      int sequence = parseSequence(request.headers().get(COALESCED_SEQUENCE_HEADER));
      String marker = request.headers().get("x-obi-demo-id");
      boolean diagnostics = exactQueryFlag(target, ApacheJavaHttpsBackend.BRIDGE_DIAGNOSTICS_PARAMETER);
      boolean expectedKeepAlive = expectedSequence == 1;
      if (!request.decoderResult().isSuccess()
          || request.method() != HttpMethod.GET
          || request.content().isReadable()
          || marker == null
          || !MARKER_PATTERN.matcher(marker).matches()
          || coalescedMarkers.contains(marker)
          || sequence != expectedSequence
          || sequence < 1
          || sequence > 2
          || request.headers().contains(HttpHeaderNames.TRANSFER_ENCODING)
          || HttpUtil.getContentLength(request, 0) != 0
          || request.headers().contains("traceparent")
          || HttpUtil.isKeepAlive(request) != expectedKeepAlive
          || diagnostics != (sequence == 2)) {
        context.close();
        return;
      }
      if (!plaintextState.recordParserRequest(sequence, marker)) {
        context.close();
        return;
      }
      coalescedMarkers.add(marker);
      if (coalescedMarkers.size() < 2) {
        scheduleCoalescedPairDeadline(context);
        return;
      }
      cancelCoalescedPairDeadline();

      CoalescedEvidence evidence = plaintextState.evidence(coalescedMarkers);
      HttpResponseStatus status =
          evidence.passed ? HttpResponseStatus.OK : HttpResponseStatus.CONFLICT;
      writeCoalescedResponse(context, coalescedMarkers.get(0), status, evidence, false, false);
      writeCoalescedResponse(context, coalescedMarkers.get(1), status, evidence, true, true);
    }

    private void writeCoalescedResponse(
        ChannelHandlerContext context,
        String marker,
        HttpResponseStatus status,
        CoalescedEvidence evidence,
        boolean diagnostics,
        boolean close) {
      SslHandler tls = context.pipeline().get(SslHandler.class);
      SSLSession session = tls == null ? null : tls.engine().getSession();
      String protocol = session == null ? configuredProtocol : session.getProtocol();
      String cipher = session == null ? "" : session.getCipherSuite();
      String body =
          String.format(
              Locale.ROOT,
              "{\"marker\":\"%s\",\"secure\":true,\"protocol\":\"HTTP/1.1\","
                  + "\"tls_protocol\":\"%s\",\"tls_cipher\":\"%s\","
                  + "\"backend_connection_id\":%d,\"backend_remote_port\":%d,"
                  + "\"backend_socket_fd\":0,\"tls_read_events\":%d,"
                  + "\"tls_read_bytes\":%d,\"backend_kind\":\"netty-coalesced-bridge\","
                  + "\"coalesced_bridge\":%s}%n",
              ApacheJavaHttpsBackend.jsonEscape(marker),
              ApacheJavaHttpsBackend.jsonEscape(protocol),
              ApacheJavaHttpsBackend.jsonEscape(cipher),
              connectionID(context.channel()),
              remotePort(context.channel().remoteAddress()),
              ApacheJavaHttpsBackend.bridgeCounter("tlsReadEvents"),
              ApacheJavaHttpsBackend.bridgeCounter("tlsReadBytes"),
              evidence.toJson());
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
      if (diagnostics) {
        String snapshot =
            ApacheJavaHttpsBackend.bridgeDiagnosticsHeaderValue(new String[] {"1"});
        if (snapshot != null) {
          response.headers().set(ApacheJavaHttpsBackend.BRIDGE_DIAGNOSTICS_HEADER, snapshot);
        }
      }
      if (close) {
        context.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
      } else {
        context.write(response);
      }
    }

    private void scheduleCoalescedPairDeadline(ChannelHandlerContext context) {
      if (coalescedPairDeadline != null) {
        plaintextState.fail("coalesced_pair_deadline_state");
        context.close();
        return;
      }
      coalescedPairDeadline =
          context
              .executor()
              .schedule(
                  () -> {
                    coalescedPairDeadline = null;
                    if (coalescedMarkers.size() == 1) {
                      plaintextState.fail("coalesced_pair_deadline_exceeded");
                      context.close();
                    }
                  },
                  coalescedPairDeadlineMillis,
                  TimeUnit.MILLISECONDS);
    }

    private void cancelCoalescedPairDeadline() {
      if (coalescedPairDeadline != null) {
        coalescedPairDeadline.cancel(false);
        coalescedPairDeadline = null;
      }
    }

    @Override
    public void channelInactive(ChannelHandlerContext context) {
      cancelCoalescedPairDeadline();
      context.fireChannelInactive();
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext context) {
      cancelCoalescedPairDeadline();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
      cancelCoalescedPairDeadline();
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
        throw new IllegalStateException("Netty connection identifier exhausted");
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

    private static void respond(
        ChannelHandlerContext context,
        FullHttpRequest request,
        HttpResponseStatus status,
        String body) {
      ByteBuf content = Unpooled.copiedBuffer(body, CharsetUtil.UTF_8);
      FullHttpResponse response =
          new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, content);
      response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
      response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json; charset=utf-8");
      response.headers().set(HttpHeaderNames.CACHE_CONTROL, HttpHeaderValues.NO_STORE);
      if (HttpUtil.isKeepAlive(request)) {
        response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        context.writeAndFlush(response);
      } else {
        response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
        context.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
      }
    }
  }

  private static int parseSequence(String raw) {
    if (raw == null || raw.length() != 1 || raw.charAt(0) < '1' || raw.charAt(0) > '2') {
      return -1;
    }
    return raw.charAt(0) - '0';
  }

  private static boolean exactQueryFlag(QueryStringDecoder target, String name) {
    List<String> values = target.parameters().get(name);
    return values != null && values.size() == 1 && "1".equals(values.get(0));
  }

  private static final class PlaintextBoundaryHandler extends ChannelInboundHandlerAdapter {
    private final PlaintextState state;

    private PlaintextBoundaryHandler(PlaintextState state) {
      this.state = state;
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) {
      if (!(message instanceof ByteBuf)) {
        context.fireChannelRead(message);
        return;
      }
      state.beginCallback((ByteBuf) message);
      try {
        context.fireChannelRead(message);
      } finally {
        state.endCallback();
      }
    }
  }

  static final class PlaintextState {
    private byte[] plaintext = new byte[0];
    private final List<Integer> parserCallbackGenerations = new ArrayList<>(2);
    private final List<String> parserMarkers = new ArrayList<>(2);
    private int callbackCount;
    private int activeCallbackGeneration;
    private String failureReason = "none";

    void beginCallback(ByteBuf buffer) {
      callbackCount++;
      activeCallbackGeneration = callbackCount;
      int readable = buffer.readableBytes();
      if (readable <= 0 || readable > MAX_COALESCED_PLAINTEXT_BYTES || callbackCount != 1) {
        fail("plaintext_callback_shape");
        return;
      }
      plaintext = ByteBufUtil.getBytes(buffer, buffer.readerIndex(), readable, true);
    }

    void endCallback() {
      activeCallbackGeneration = 0;
    }

    boolean recordParserRequest(int sequence, String marker) {
      if (sequence != parserMarkers.size() + 1
          || activeCallbackGeneration <= 0
          || parserMarkers.size() >= 2) {
        fail("parser_request_shape");
        return false;
      }
      parserCallbackGenerations.add(activeCallbackGeneration);
      parserMarkers.add(marker);
      return true;
    }

    CoalescedEvidence evidence(List<String> expectedMarkers) {
      String text = new String(plaintext, StandardCharsets.US_ASCII);
      int traceparentHeaders = headerCount(text, "traceparent");
      boolean markersExact = expectedMarkers.equals(parserMarkers);
      for (String marker : expectedMarkers) {
        markersExact &=
            occurrenceCount(text, "X-OBI-Demo-ID: " + marker + "\r\n") == 1;
      }
      boolean passed =
          "none".equals(failureReason)
              && callbackCount == 1
              && plaintext.length > 0
              && plaintext.length <= MAX_COALESCED_PLAINTEXT_BYTES
              && parserCallbackGenerations.equals(List.of(1, 1))
              && markersExact
              && traceparentHeaders == 0
              && occurrenceCount(text, "GET " + COALESCED_BRIDGE_PATH) == 2;
      String reason = passed ? "none" : failureReason;
      if (!passed && "none".equals(reason)) {
        reason = "coalesced_evidence_mismatch";
      }
      return new CoalescedEvidence(
          callbackCount,
          plaintext.length,
          sha256(plaintext),
          parserCallbackGenerations,
          parserMarkers,
          traceparentHeaders,
          markersExact,
          passed,
          reason);
    }

    private void fail(String reason) {
      if ("none".equals(failureReason)) {
        failureReason = reason;
      }
    }
  }

  static final class CoalescedEvidence {
    private final int plaintextCallbackCount;
    private final int plaintextCallbackBytes;
    private final String plaintextSHA256;
    private final List<Integer> parserCallbackGenerations;
    private final List<String> parserMarkers;
    private final int traceparentHeaderCount;
    private final boolean requestMarkersExact;
    private final boolean passed;
    private final String failureReason;

    private CoalescedEvidence(
        int plaintextCallbackCount,
        int plaintextCallbackBytes,
        String plaintextSHA256,
        List<Integer> parserCallbackGenerations,
        List<String> parserMarkers,
        int traceparentHeaderCount,
        boolean requestMarkersExact,
        boolean passed,
        String failureReason) {
      this.plaintextCallbackCount = plaintextCallbackCount;
      this.plaintextCallbackBytes = plaintextCallbackBytes;
      this.plaintextSHA256 = plaintextSHA256;
      this.parserCallbackGenerations = List.copyOf(parserCallbackGenerations);
      this.parserMarkers = List.copyOf(parserMarkers);
      this.traceparentHeaderCount = traceparentHeaderCount;
      this.requestMarkersExact = requestMarkersExact;
      this.passed = passed;
      this.failureReason = failureReason;
    }

    String toJson() {
      return String.format(
          Locale.ROOT,
          "{\"plaintext_callback_count\":%d,\"plaintext_callback_bytes\":%d,"
              + "\"plaintext_sha256\":\"%s\",\"parser_request_count\":%d,"
              + "\"parser_callback_generations\":%s,\"parser_markers\":%s,"
              + "\"traceparent_header_count\":%d,\"request_markers_exact\":%s,"
              + "\"one_plaintext_receive\":%s,\"passed\":%s,\"failure_reason\":\"%s\"}",
          plaintextCallbackCount,
          plaintextCallbackBytes,
          plaintextSHA256,
          parserMarkers.size(),
          parserCallbackGenerations,
          quotedStrings(parserMarkers),
          traceparentHeaderCount,
          requestMarkersExact,
          plaintextCallbackCount == 1 && parserCallbackGenerations.equals(List.of(1, 1)),
          passed,
          ApacheJavaHttpsBackend.jsonEscape(failureReason));
    }
  }

  private static int headerCount(String plaintext, String name) {
    int count = 0;
    String prefix = name.toLowerCase(Locale.ROOT) + ":";
    for (String line : plaintext.toLowerCase(Locale.ROOT).split("\\r\\n")) {
      if (line.startsWith(prefix)) {
        count++;
      }
    }
    return count;
  }

  private static int occurrenceCount(String value, String wanted) {
    int count = 0;
    int offset = 0;
    while ((offset = value.indexOf(wanted, offset)) >= 0) {
      count++;
      offset += wanted.length();
    }
    return count;
  }

  private static String sha256(byte[] value) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException(impossible);
    }
  }

  private static String quotedStrings(List<String> values) {
    StringBuilder json = new StringBuilder("[");
    for (int index = 0; index < values.size(); index++) {
      if (index > 0) {
        json.append(',');
      }
      json.append('"').append(ApacheJavaHttpsBackend.jsonEscape(values.get(index))).append('"');
    }
    return json.append(']').toString();
  }
}
