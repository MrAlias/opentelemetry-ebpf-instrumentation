/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package fixture;

import com.sun.net.httpserver.HttpServer;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientInterceptors;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.MetadataUtils;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class Source {
  private static final MethodDescriptor.Marshaller<byte[]> BYTES =
      new MethodDescriptor.Marshaller<byte[]>() {
        public InputStream stream(byte[] value) {
          return new ByteArrayInputStream(value);
        }

        public byte[] parse(InputStream input) {
          try {
            return input.readAllBytes();
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
        }
      };
  private static final MethodDescriptor<byte[], byte[]> METHOD =
      MethodDescriptor.<byte[], byte[]>newBuilder()
          .setType(MethodDescriptor.MethodType.UNARY)
          .setFullMethodName("fixture.Receiver/Call")
          .setRequestMarshaller(BYTES)
          .setResponseMarshaller(BYTES)
          .build();

  public static void main(String[] args) throws Exception {
    SslContext sslContext =
        GrpcSslContexts.forClient()
            .trustManager(
                new java.io.File(System.getenv().getOrDefault("GRPC_CERT", "/certs/cert.pem")))
            .build();
    ManagedChannel channel =
        NettyChannelBuilder.forAddress(
                System.getenv().getOrDefault("GRPC_HOST", "proxy"),
                Integer.parseInt(System.getenv().getOrDefault("GRPC_PORT", "8443")))
            .sslContext(sslContext)
            .build();
    HttpServer server =
        HttpServer.create(
            new InetSocketAddress(
                Integer.parseInt(System.getenv().getOrDefault("HTTP_PORT", "8080"))),
            0);
    server.setExecutor(Executors.newFixedThreadPool(16));
    server.createContext(
        "/health",
        exchange -> {
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    server.createContext(
        "/call",
        exchange -> {
          try {
            Channel callChannel = channel;
            String query = exchange.getRequestURI().getRawQuery();
            if (query != null && query.startsWith("app=")) {
              Metadata metadata = new Metadata();
              metadata.put(
                  Metadata.Key.of("traceparent", Metadata.ASCII_STRING_MARSHALLER),
                  URLDecoder.decode(query.substring(4), "UTF-8"));
              callChannel =
                  ClientInterceptors.intercept(
                      channel, MetadataUtils.newAttachHeadersInterceptor(metadata));
            }
            byte[] response =
                ClientCalls.blockingUnaryCall(
                    callChannel,
                    METHOD,
                    CallOptions.DEFAULT.withDeadlineAfter(60, TimeUnit.SECONDS),
                    exchange
                        .getRequestHeaders()
                        .getFirst("x-case-id")
                        .getBytes(StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
          } catch (Throwable error) {
            error.printStackTrace();
            exchange.sendResponseHeaders(500, -1);
          } finally {
            exchange.close();
          }
        });
    server.start();
    System.out.println(
        "grpc-java="
            + ManagedChannel.class.getPackage().getImplementationVersion()
            + " TLS="
            + sslContext.getClass().getSimpleName()
            + " JDK="
            + System.getProperty("java.version"));
  }
}
