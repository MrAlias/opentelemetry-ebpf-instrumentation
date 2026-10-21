/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.ssl.SSLContexts;

public class HttpClient5Service {
  public static void main(String[] args) throws Exception {
    SSLContext tls = SSLContexts.custom().loadTrustMaterial((chain, auth) -> true).build();
    CloseableHttpClient client = HttpClients.custom()
        .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
            .setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create().setSslContext(tls)
                .setHostnameVerifier(NoopHostnameVerifier.INSTANCE).build())
            .setMaxConnPerRoute(8).setMaxConnTotal(8).build())
        .disableAutomaticRetries().disableRedirectHandling().build();
    java.util.concurrent.ExecutorService workers = Executors.newFixedThreadPool(8);
    ServerSocket listener = new ServerSocket(8080);
    while (true) {
      Socket socket = listener.accept();
      workers.execute(() -> {
        try (Socket incoming = socket) {
          BufferedReader reader = new BufferedReader(new InputStreamReader(incoming.getInputStream(), StandardCharsets.US_ASCII));
          String path = reader.readLine().split(" ")[1];
          String supplied = null;
          String line;
          while (!(line = reader.readLine()).isEmpty()) {
            if (line.startsWith("X-Supplied-Traceparent: ")) supplied = line.substring(24);
          }
          String body = "ready";
          if (!path.equals("/health")) {
            HttpPost request = new HttpPost("https://proxy:8443" + path);
            request.setVersion(HttpVersion.HTTP_1_1);
            request.setHeader("X-Request-Token", path.substring(1));
            if (supplied != null) request.setHeader("TraceParent", supplied);
            request.setEntity(new StringEntity("payload:" + path));
            body = client.execute(request, response -> {
              if (response.getCode() != 200) throw new IOException("downstream status " + response.getCode());
              return EntityUtils.toString(response.getEntity());
            });
            if (supplied == null && request.containsHeader("traceparent")) throw new IOException("request mutated");
          }
          byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
          OutputStream out = incoming.getOutputStream();
          out.write(("HTTP/1.1 200 OK\r\nContent-Length: " + bytes.length + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
          out.write(bytes);
        } catch (Exception e) { e.printStackTrace(); }
      });
    }
  }
}
