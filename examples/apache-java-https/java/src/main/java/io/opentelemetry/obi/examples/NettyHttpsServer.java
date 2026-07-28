// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
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
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSession;

final class NettyHttpsServer implements AutoCloseable {
  static final String API_PATH = "/api/netty-server";
  private static final int MAX_REQUEST_BYTES = 64 * 1024;
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
                  channel
                      .pipeline()
                      .addLast("tls", contexts.serverContext().newHandler(channel.alloc()));
                  channel.pipeline().addLast("http-codec", new HttpServerCodec());
                  channel
                      .pipeline()
                      .addLast("http-aggregate", new HttpObjectAggregator(MAX_REQUEST_BYTES));
                  channel.pipeline().addLast("request", new RequestHandler(tlsProtocol));
                }
              });
      Channel serverChannel =
          bootstrap.bind(new InetSocketAddress("127.0.0.1", port)).sync().channel();
      return new NettyHttpsServer(acceptor, eventLoop, serverChannel);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      shutdown(acceptor);
      shutdown(eventLoop);
      throw interrupted;
    } catch (RuntimeException failure) {
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

    private RequestHandler(String configuredProtocol) {
      this.configuredProtocol = configuredProtocol;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext context, FullHttpRequest request) {
      QueryStringDecoder target = new QueryStringDecoder(request.uri());
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

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
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
}
