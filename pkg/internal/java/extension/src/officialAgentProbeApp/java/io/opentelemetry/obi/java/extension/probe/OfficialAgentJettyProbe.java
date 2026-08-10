/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension.probe;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

/** Isolated Jetty process used with an official Java agent and the production OBI extension. */
public final class OfficialAgentJettyProbe {
  private static final String OUTPUT_PROPERTY = "obi.test.official.agent.probe.output";
  private static final String MODE_PROPERTY = "obi.test.official.agent.probe.mode";
  private static final String MODE_BLOCKING = "blocking";
  private static final String MODE_AUTO_UNAVAILABLE = "auto-unavailable";
  private static final String MODE_DEFAULT = "default";
  private static final String MODE_FRAMEWORK_MISS = "framework-miss";
  private static final String MODE_HELPER_ABSENT = "helper-absent";
  private static final String MODE_NESTED = "nested";
  private static final String MODE_STANDARD_FIRST = "standard-first";

  private static final String TRACE_W3C = "55555555555555555555555555555555";
  private static final String PARENT_W3C = "6666666666666666";
  private static final String TRACE_W3C_ONLY = "12121212121212121212121212121212";
  private static final String PARENT_W3C_ONLY = "1313131313131313";
  private static final String TRACE_MATCHING = "34343434343434343434343434343434";
  private static final String PARENT_MATCHING = "5656565656565656";
  private static final String TRACE_STALE_W3C = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
  private static final String PARENT_STALE_W3C = "b2b2b2b2b2b2b2b2";
  private static final String TRACE_MALFORMED_OBI_W3C = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
  private static final String PARENT_MALFORMED_OBI_W3C = "d4d4d4d4d4d4d4d4";
  private static final String TRACE_D_W3C = "dddddddddddddddddddddddddddddddd";
  private static final String PARENT_D_W3C = "eeeeeeeeeeeeeeee";

  private OfficialAgentJettyProbe() {}

  public static void main(String[] args) throws Exception {
    Path output = Paths.get(requiredProperty(OUTPUT_PROPERTY)).toAbsolutePath().normalize();
    String mode = requiredProperty(MODE_PROPERTY);
    require(
        MODE_BLOCKING.equals(mode)
            || MODE_AUTO_UNAVAILABLE.equals(mode)
            || MODE_DEFAULT.equals(mode)
            || MODE_FRAMEWORK_MISS.equals(mode)
            || MODE_HELPER_ABSENT.equals(mode)
            || MODE_NESTED.equals(mode)
            || MODE_STANDARD_FIRST.equals(mode),
        "unsupported probe mode " + mode);
    boolean blockingMode = MODE_BLOCKING.equals(mode);

    AtomicInteger dispatchThreadId = new AtomicInteger();
    ExecutorService dispatchExecutor =
        Executors.newFixedThreadPool(
            2,
            runnable -> {
              Thread thread =
                  new Thread(
                      runnable,
                      "obi-official-agent-dispatch-" + dispatchThreadId.incrementAndGet());
              thread.setDaemon(true);
              return thread;
            });
    Server server = new Server();
    ServerConnector connector = new ServerConnector(server);
    connector.setHost("127.0.0.1");
    connector.setPort(0);
    server.addConnector(connector);

    ServletContextHandler context = new ServletContextHandler();
    context.setContextPath("/");
    ServletHolder servlet = new ServletHolder(new ProbeServlet(dispatchExecutor, blockingMode));
    servlet.setAsyncSupported(!blockingMode);
    context.addServlet(servlet, "/probe/*");
    server.setHandler(context);

    try {
      server.start();
      int port = connector.getLocalPort();
      require(port > 0, "Jetty did not bind an ephemeral port");
      int expectedSpans;
      if (MODE_BLOCKING.equals(mode)) {
        runBlockingMode(port);
        expectedSpans = 1;
      } else if (MODE_DEFAULT.equals(mode)) {
        runDefaultMode(port);
        expectedSpans = 11;
      } else if (MODE_HELPER_ABSENT.equals(mode) || MODE_AUTO_UNAVAILABLE.equals(mode)) {
        if (MODE_HELPER_ABSENT.equals(mode)) {
          requireBootstrapHelperAbsent();
        }
        runW3cFallbackMode(port, mode);
        expectedSpans = 1;
      } else if (MODE_FRAMEWORK_MISS.equals(mode)) {
        runFrameworkMissMode(port);
        expectedSpans = 4;
      } else if (MODE_NESTED.equals(mode)) {
        runNestedMode(port);
        expectedSpans = 1;
      } else {
        runStandardFirstMode(port);
        expectedSpans = 1;
      }

      awaitServerSpans(output, expectedSpans, 10, TimeUnit.SECONDS);
      if (!MODE_HELPER_ABSENT.equals(mode)) {
        Class<?> bridge =
            Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", true, null);
        String diagnostics = (String) bridge.getMethod("diagnosticsSnapshot").invoke(null);
        System.out.println("OBI_STOCK_PROBE mode=" + mode + " diagnostics=" + diagnostics);
      }
      System.out.println("OBI_STOCK_PROBE mode=" + mode + " passed");
    } finally {
      try {
        server.stop();
        server.join();
      } finally {
        dispatchExecutor.shutdown();
        if (!dispatchExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
          dispatchExecutor.shutdownNow();
          require(
              dispatchExecutor.awaitTermination(5, TimeUnit.SECONDS),
              "dispatch executor did not terminate");
        }
      }
    }
  }

  private static void runDefaultMode(int port) throws Exception {
    try (Socket socket = connect(port)) {
      BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
      OutputStream request = socket.getOutputStream();
      require("A:ok".equals(send(request, input, "A", null, false)), "request A failed");
      require("B:ok".equals(send(request, input, "B", null, false)), "request B failed");
      require("C:ok".equals(send(request, input, "C", null, false)), "request C failed");
      require(
          "H:ok"
              .equals(
                  send(
                      request,
                      input,
                      "H",
                      traceparent(TRACE_W3C_ONLY, PARENT_W3C_ONLY, "01"),
                      false)),
          "request H failed W3C-only extraction");
      require(
          "M:ok"
              .equals(
                  send(
                      request,
                      input,
                      "M",
                      traceparent(TRACE_MATCHING, PARENT_MATCHING, "01"),
                      false)),
          "request M failed matching-parent extraction");
      require(
          "W:ok".equals(send(request, input, "W", traceparent(TRACE_W3C, PARENT_W3C, "01"), false)),
          "request W failed standard-parent precedence");
      require(
          "F:ok".equals(send(request, input, "F", "malformed-traceparent", false)),
          "request F failed malformed-W3C fallback");
      require(
          "R:ok"
              .equals(
                  send(
                      request,
                      input,
                      "R",
                      traceparent(TRACE_MALFORMED_OBI_W3C, PARENT_MALFORMED_OBI_W3C, "01"),
                      false)),
          "request R failed malformed-OBI precedence");
      require(
          "S:ok"
              .equals(
                  send(
                      request,
                      input,
                      "S",
                      traceparent(TRACE_STALE_W3C, PARENT_STALE_W3C, "00"),
                      true)),
          "request S failed stale-OBI precedence");
    }
    sendParallel(port);
  }

  private static void runBlockingMode(int port) throws Exception {
    try (Socket socket = connect(port)) {
      require(
          "T:ok"
              .equals(
                  send(
                      socket.getOutputStream(),
                      new BufferedInputStream(socket.getInputStream()),
                      "T",
                      null,
                      true)),
          "blocking request T failed");
    }
  }

  private static void runFrameworkMissMode(int port) throws Exception {
    try (Socket socket = connect(port)) {
      BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
      OutputStream request = socket.getOutputStream();
      for (String id : new String[] {"X", "Y", "L", "K"}) {
        require(
            (id + ":ok").equals(send(request, input, id, null, false)),
            "framework miss request " + id + " failed");
      }
    }
  }

  private static void runStandardFirstMode(int port) throws Exception {
    try (Socket socket = connect(port)) {
      require(
          "D:ok"
              .equals(
                  send(
                      socket.getOutputStream(),
                      new BufferedInputStream(socket.getInputStream()),
                      "D",
                      traceparent(TRACE_D_W3C, PARENT_D_W3C, "00"),
                      true)),
          "request D failed standard-first discard");
    }
  }

  private static void runW3cFallbackMode(int port, String mode) throws Exception {
    try (Socket socket = connect(port)) {
      require(
          "H:ok"
              .equals(
                  send(
                      socket.getOutputStream(),
                      new BufferedInputStream(socket.getInputStream()),
                      "H",
                      traceparent(TRACE_W3C_ONLY, PARENT_W3C_ONLY, "01"),
                      true)),
          mode + " request H failed W3C extraction");
    }
  }

  private static void requireBootstrapHelperAbsent() {
    try {
      Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", false, null);
      throw new IllegalStateException("OBI bootstrap helper unexpectedly present");
    } catch (ClassNotFoundException expected) {
      // The missing helper is the condition under test for this entire process.
    }
  }

  private static void runNestedMode(int port) throws Exception {
    try (Socket socket = connect(port)) {
      require(
          "A:ok"
              .equals(
                  send(
                      socket.getOutputStream(),
                      new BufferedInputStream(socket.getInputStream()),
                      "A",
                      null,
                      true)),
          "nested-instrumentation request A failed");
    }
  }

  private static Socket connect(int port) throws IOException {
    Socket socket = new Socket();
    socket.connect(new InetSocketAddress("127.0.0.1", port), 5_000);
    socket.setSoTimeout(10_000);
    return socket;
  }

  private static String traceparent(String traceId, String parentSpanId, String flags) {
    return "00-" + traceId + "-" + parentSpanId + "-" + flags;
  }

  private static String send(
      OutputStream output, BufferedInputStream input, String id, String traceparent, boolean close)
      throws IOException {
    // Raw framing prevents an instrumented client from adding a parent or creating client spans.
    StringBuilder request =
        new StringBuilder()
            .append("GET /probe/")
            .append(id)
            .append(" HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Obi-Probe-Id: ")
            .append(id)
            .append("\r\n");
    if (traceparent != null) {
      request.append("traceparent: ").append(traceparent).append("\r\n");
    }
    request.append("Connection: ").append(close ? "close" : "keep-alive").append("\r\n\r\n");
    output.write(request.toString().getBytes(StandardCharsets.US_ASCII));
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
            try (Socket socket = connect(port)) {
              String response =
                  send(
                      socket.getOutputStream(),
                      new BufferedInputStream(socket.getInputStream()),
                      id,
                      null,
                      true);
              require((id + ":ok").equals(response), "request " + id + " failed");
            }
          } catch (Throwable problem) {
            failure.compareAndSet(null, problem);
          }
        },
        "obi-official-agent-parallel-" + id);
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
        long count = lines.stream().filter(line -> line.startsWith("SPAN\t")).count();
        if (count >= expected) {
          return;
        }
      }
      Thread.sleep(25L);
    }
    throw new IllegalStateException("timed out waiting for server spans");
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

  private static final class ProbeServlet extends HttpServlet {
    private final ExecutorService dispatchExecutor;
    private final boolean blockingMode;

    private ProbeServlet(ExecutorService dispatchExecutor, boolean blockingMode) {
      this.dispatchExecutor = dispatchExecutor;
      this.blockingMode = blockingMode;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException, ServletException {
      String id = request.getHeader("x-obi-probe-id");
      require(
          "A".equals(id)
              || "B".equals(id)
              || "C".equals(id)
              || "H".equals(id)
              || "M".equals(id)
              || "W".equals(id)
              || "F".equals(id)
              || "R".equals(id)
              || "S".equals(id)
              || "P".equals(id)
              || "Q".equals(id)
              || "D".equals(id)
              || "K".equals(id)
              || "L".equals(id)
              || "X".equals(id)
              || "Y".equals(id)
              || "T".equals(id),
          "invalid probe id");

      if (request.getDispatcherType() == DispatcherType.REQUEST) {
        recordDispatch("REQUEST", id);
        if (blockingMode) {
          require("T".equals(id), "unexpected blocking probe id");
          require(!request.isAsyncSupported(), "blocking request unexpectedly supports async");
          require(!request.isAsyncStarted(), "blocking request unexpectedly started async");
          writeResponse(id, response);
          require(!request.isAsyncStarted(), "blocking response unexpectedly started async");
          recordDispatch("BLOCKING", id);
          return;
        }
        AsyncContext async = request.startAsync();
        async.setTimeout(5_000L);
        dispatchExecutor.execute(
            () -> {
              recordDispatch("EXECUTOR", id);
              async.dispatch();
            });
        return;
      }

      require(!blockingMode, "blocking request was asynchronously dispatched");
      require(request.getDispatcherType() == DispatcherType.ASYNC, "unexpected dispatch type");
      recordDispatch("ASYNC", id);
      writeResponse(id, response);
    }

    private static void recordDispatch(String phase, String id) {
      long threadId = Thread.currentThread().getId();
      long observedNanos = System.nanoTime();
      System.out.println("OBI_DISPATCH\t" + phase + "\t" + id + "\t" + threadId);
      if ("B".equals(id)) {
        System.out.println(
            "OBI_TIMING\t" + phase + "\t" + id + "\t" + threadId + "\t" + observedNanos);
      }
    }

    private static void writeResponse(String id, HttpServletResponse response) throws IOException {
      byte[] body = (id + ":ok").getBytes(StandardCharsets.UTF_8);
      response.setStatus(HttpServletResponse.SC_OK);
      response.setContentType("text/plain");
      response.setContentLength(body.length);
      response.getOutputStream().write(body);
    }
  }
}
