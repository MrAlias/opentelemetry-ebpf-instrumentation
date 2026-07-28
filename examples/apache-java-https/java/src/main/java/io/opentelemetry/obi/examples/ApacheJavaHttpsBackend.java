// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import io.netty.util.concurrent.DefaultEventExecutor;
import io.netty.util.concurrent.ScheduledFuture;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.LockSupport;
import java.util.regex.Pattern;
import javax.net.ssl.SSLSession;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;

public final class ApacheJavaHttpsBackend {
  static final String BRIDGE_DIAGNOSTICS_HEADER = "X-OBI-Java-Diagnostics";
  static final String BRIDGE_DIAGNOSTICS_PARAMETER = "bridge_diagnostics";
  private static final int DEFAULT_PORT = 18443;
  private static final int DEFAULT_NETTY_PORT = 18444;
  private static final int MAX_DELAY_MILLIS = 1000;
  private static final int MAX_BODY_BYTES = 64 * 1024;
  private static final int MAX_HANDOFFS = 8;
  private static final int MAX_DISPATCH_ROUNDS = 8;
  private static final int PROC_LOCAL_ENDPOINT_INDEX = 1;
  private static final int PROC_REMOTE_ENDPOINT_INDEX = 2;
  private static final int PROC_STATE_INDEX = 3;
  private static final int PROC_INODE_INDEX = 9;
  private static final String TCP_ESTABLISHED_STATE = "01";
  private static final Path[] PROC_TCP_TABLES = {
    Path.of("/proc/self/net/tcp"), Path.of("/proc/self/net/tcp6")
  };
  private static final String DISPATCH_COUNT_ATTRIBUTE =
      ApacheJavaHttpsBackend.class.getName() + ".dispatchCount";
  private static final Pattern MARKER_PATTERN = Pattern.compile("[a-zA-Z0-9._:-]{1,128}");
  private static final Set<String> HANDOFF_FAULTS = Set.of("none", "cancel", "reject", "timeout");
  private static final AtomicLong NEXT_BACKEND_CONNECTION_ID = new AtomicLong(1);
  private static final ReferenceQueue<Object> CLOSED_BACKEND_CONNECTIONS = new ReferenceQueue<>();
  private static final Map<IdentityWeakReference, Long> BACKEND_CONNECTION_IDS = new HashMap<>();
  private static final ExecutorService HANDOFF_FIRST =
      Executors.newFixedThreadPool(4, namedThreadFactory("obi-handoff-a-"));
  private static final ExecutorService HANDOFF_SECOND =
      Executors.newFixedThreadPool(4, namedThreadFactory("obi-handoff-b-"));
  private static final ScheduledExecutorService FAULT_EXECUTOR =
      Executors.newSingleThreadScheduledExecutor(namedThreadFactory("obi-fault-"));
  private static final ExecutorService REJECTING_EXECUTOR = rejectingExecutor();
  private static final DefaultEventExecutor NETTY_EVENT_LOOP =
      new DefaultEventExecutor(namedThreadFactory("obi-netty-eventloop-"));
  private static final ExecutorService VIRTUAL_EXECUTOR = virtualThreadExecutor();
  private static final AtomicBoolean STOPPED = new AtomicBoolean();

  private ApacheJavaHttpsBackend() {}

  public static void main(String[] args) throws Exception {
    int port =
        parsePort("HTTPS_PORT", environment("HTTPS_PORT", Integer.toString(DEFAULT_PORT)));
    int nettyPort =
        parsePort(
            "NETTY_HTTPS_PORT",
            environment("NETTY_HTTPS_PORT", Integer.toString(DEFAULT_NETTY_PORT)));
    String keyStorePath = environment("TLS_KEYSTORE_PATH", "/run/obi-demo/certs/server.p12");
    String keyStorePassword = environment("TLS_KEYSTORE_PASSWORD", "changeit");
    String tlsProtocol = environment("TLS_PROTOCOL", "TLSv1.3");
    if (!tlsProtocol.equals("TLSv1.2") && !tlsProtocol.equals("TLSv1.3")) {
      throw new IllegalArgumentException("TLS_PROTOCOL must be TLSv1.2 or TLSv1.3");
    }
    boolean tlsBoundaryEnabled =
        parseFlag(
            environment("TLS_RECEIVE_BOUNDARY_FIXTURE_ENABLED", "0"),
            false,
            "TLS_RECEIVE_BOUNDARY_FIXTURE_ENABLED");
    TlsReceiveBoundaryFixture tlsBoundaryFixture =
        tlsBoundaryEnabled
            ? TlsReceiveBoundaryFixture.start(
                Path.of(keyStorePath), keyStorePassword, tlsProtocol)
            : null;

    Server server = new Server();
    SslContextFactory.Server sslContext = new SslContextFactory.Server();
    sslContext.setKeyStorePath(keyStorePath);
    sslContext.setKeyStorePassword(keyStorePassword);
    sslContext.setIncludeProtocols(tlsProtocol);

    HttpConfiguration https = new HttpConfiguration();
    https.addCustomizer(new SecureRequestCustomizer());
    ServerConnector connector =
        new ServerConnector(
            server,
            new SslConnectionFactory(sslContext, HttpVersion.HTTP_1_1.asString()),
            new HttpConnectionFactory(https));
    connector.setHost("127.0.0.1");
    connector.setPort(port);
    connector.setIdleTimeout(30_000);
    server.addConnector(connector);

    ServletContextHandler context = new ServletContextHandler();
    context.setContextPath("/");
    configureServlets(context, tlsProtocol, tlsBoundaryFixture);
    server.setHandler(context);

    NettyHttpsServer nettyServer = null;
    try {
      nettyServer =
          NettyHttpsServer.start(nettyPort, Path.of(keyStorePath), keyStorePassword, tlsProtocol);
      NettyHttpsServer runningNettyServer = nettyServer;
      Runtime.getRuntime()
          .addShutdownHook(
              new Thread(() -> stop(server, runningNettyServer, tlsBoundaryFixture), "jetty-shutdown"));
      server.start();
      System.out.printf(
          Locale.ROOT,
          "Jetty HTTPS backend ready on 127.0.0.1:%d with %s and HTTP/1.1%n",
          port,
          tlsProtocol);
      System.out.printf(
          Locale.ROOT,
          "Netty HTTPS backend ready on 127.0.0.1:%d with %s and HTTP/1.1%n",
          runningNettyServer.port(),
          tlsProtocol);
      server.join();
    } finally {
      stop(server, nettyServer, tlsBoundaryFixture);
    }
  }

  static void configureServlets(
      ServletContextHandler context,
      String tlsProtocol,
      TlsReceiveBoundaryFixture tlsBoundaryFixture) {
    context.addServlet(new ServletHolder(new HealthServlet(tlsProtocol)), "/healthz");
    context.addServlet(new ServletHolder(new EchoServlet(tlsProtocol)), "/api/echo");
    context.addServlet(new ServletHolder(new EchoServlet(tlsProtocol)), "/api/obi-flags");
    context.addServlet(new ServletHolder(new DispatchServlet(tlsProtocol)), "/api/dispatch");
    context.addServlet(new ServletHolder(new HandoffServlet(tlsProtocol)), "/api/handoff");
    context.addServlet(new ServletHolder(new NettyHandoffServlet(tlsProtocol)), "/api/netty");
    context.addServlet(new ServletHolder(new VirtualThreadServlet(tlsProtocol)), "/api/virtual");
    context.addServlet(new ServletHolder(new BridgeDiagnosticsServlet()), "/obi-diagnostics");
    context.addServlet(
        new ServletHolder(new TransportConfigurationServlet()),
        "/obi-transport-configuration");
    if (tlsBoundaryFixture != null) {
      context.addServlet(
          new ServletHolder(new TlsReceiveBoundaryServlet(tlsBoundaryFixture, tlsProtocol)),
          "/api/tls-boundary");
    }
  }

  private static final class HealthServlet extends HttpServlet {
    private final String configuredProtocol;

    private HealthServlet(String configuredProtocol) {
      this.configuredProtocol = configuredProtocol;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
      writeResponse(response, request, "health", configuredProtocol);
    }
  }

  private static final class EchoServlet extends HttpServlet {
    private final String configuredProtocol;

    private EchoServlet(String configuredProtocol) {
      this.configuredProtocol = configuredProtocol;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
      handle(request, response, false);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
      handle(request, response, true);
    }

    private void handle(
        HttpServletRequest request, HttpServletResponse response, boolean consumeRequestBody)
        throws IOException {
      String marker = request.getHeader("x-obi-demo-id");
      if (marker == null || !MARKER_PATTERN.matcher(marker).matches()) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid x-obi-demo-id header");
        return;
      }

      if (consumeRequestBody && !consumeBoundedBody(request)) {
        response.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, "request body too large");
        return;
      }

      int delayMillis = parseDelay(request.getParameter("delay_ms"));
      if (delayMillis > 0) {
        try {
          Thread.sleep(delayMillis);
        } catch (InterruptedException exception) {
          Thread.currentThread().interrupt();
          response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "request interrupted");
          return;
        }
      }

      writeResponse(response, request, marker, configuredProtocol);
    }

    private static boolean consumeBoundedBody(HttpServletRequest request) throws IOException {
      byte[] buffer = new byte[1024];
      int total = 0;
      int read;
      while ((read = request.getInputStream().read(buffer)) >= 0) {
        total += read;
        if (total > MAX_BODY_BYTES) {
          return false;
        }
      }
      return true;
    }
  }

  private static final class HandoffServlet extends HttpServlet {
    private final String configuredProtocol;

    private HandoffServlet(String configuredProtocol) {
      this.configuredProtocol = configuredProtocol;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
      String marker = validatedMarker(request, response);
      if (marker == null) {
        return;
      }

      int hops;
      String fault;
      try {
        hops = parseHops(request.getParameter("hops"));
        fault = parseHandoffFault(request.getParameter("fault"));
      } catch (IllegalArgumentException invalid) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, invalid.getMessage());
        return;
      }

      AsyncContext async = request.startAsync();
      async.setTimeout(5_000);
      async.start(
          () ->
              dispatchHandoff(
                  async, request, response, marker, configuredProtocol, hops, fault, 0));
    }
  }

  private static final class DispatchServlet extends HttpServlet {
    private final String configuredProtocol;

    private DispatchServlet(String configuredProtocol) {
      this.configuredProtocol = configuredProtocol;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
      String marker = validatedMarker(request, response);
      if (marker == null) {
        return;
      }

      int rounds;
      try {
        rounds = parseDispatchRounds(request.getParameter("rounds"));
      } catch (IllegalArgumentException invalid) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, invalid.getMessage());
        return;
      }

      Object countAttribute = request.getAttribute(DISPATCH_COUNT_ATTRIBUTE);
      int completed = countAttribute instanceof Integer ? (Integer) countAttribute : 0;
      if (completed < rounds) {
        request.setAttribute(DISPATCH_COUNT_ATTRIBUTE, completed + 1);
        AsyncContext async = request.startAsync();
        async.setTimeout(5_000);
        async.dispatch();
        return;
      }

      response.setHeader("X-OBI-Workload", "servlet-async-redispatch");
      response.setHeader("X-OBI-Dispatch-Rounds", Integer.toString(completed));
      response.setHeader("X-OBI-Dispatch-Invocations", Integer.toString(completed + 1));
      writeResponse(response, request, marker, configuredProtocol);
    }
  }

  private static final class VirtualThreadServlet extends HttpServlet {
    private final String configuredProtocol;

    private VirtualThreadServlet(String configuredProtocol) {
      this.configuredProtocol = configuredProtocol;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
      String marker = validatedMarker(request, response);
      if (marker == null) {
        return;
      }
      if (VIRTUAL_EXECUTOR == null) {
        response.sendError(
            HttpServletResponse.SC_NOT_IMPLEMENTED, "virtual threads require Java 21 or newer");
        return;
      }

      boolean mixed;
      boolean cancel;
      try {
        mixed = parseFlag(request.getParameter("mixed"), true, "mixed");
        cancel = parseFlag(request.getParameter("cancel"), false, "cancel");
      } catch (IllegalArgumentException invalid) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, invalid.getMessage());
        return;
      }

      AsyncContext async = request.startAsync();
      async.setTimeout(5_000);
      if (cancel) {
        Future<?> cancelled = VIRTUAL_EXECUTOR.submit((Runnable) LockSupport::park);
        if (!cancelTask(cancelled, true)) {
          failAsync(async, response, "unable to cancel virtual-thread task");
          return;
        }
      }
      VIRTUAL_EXECUTOR.execute(
          () -> {
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(2));
            Runnable complete =
                () -> {
                  response.setHeader("X-OBI-Workload", "virtual-thread");
                  response.setHeader("X-OBI-Virtual-Mixed", mixed ? "1" : "0");
                  response.setHeader("X-OBI-Virtual-Cancel", cancel ? "1" : "0");
                  completeAsync(
                      async, request, response, marker, configuredProtocol, "virtual-thread");
                };
            if (mixed) {
              HANDOFF_FIRST.execute(complete);
            } else {
              complete.run();
            }
          });
    }
  }

  private static final class NettyHandoffServlet extends HttpServlet {
    private final String configuredProtocol;

    private NettyHandoffServlet(String configuredProtocol) {
      this.configuredProtocol = configuredProtocol;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
      String marker = validatedMarker(request, response);
      if (marker == null) {
        return;
      }

      boolean cancel;
      try {
        cancel = parseFlag(request.getParameter("cancel"), false, "cancel");
      } catch (IllegalArgumentException invalid) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, invalid.getMessage());
        return;
      }

      AsyncContext async = request.startAsync();
      async.setTimeout(5_000);
      if (cancel) {
        ScheduledFuture<?> cancelled = NETTY_EVENT_LOOP.schedule(() -> {}, 1, TimeUnit.HOURS);
        if (!cancelled.cancel(false)) {
          failAsync(async, response, "unable to cancel Netty task");
          return;
        }
      }

      try {
        NETTY_EVENT_LOOP.execute(
            () -> {
              if (!NETTY_EVENT_LOOP.inEventLoop()) {
                failAsync(async, response, "Netty task did not run on the event loop");
                return;
              }
              try {
                HANDOFF_FIRST.execute(
                    () -> {
                      response.setHeader("X-OBI-Workload", "netty-eventloop-worker");
                      response.setHeader("X-OBI-Netty-Cancel", cancel ? "1" : "0");
                      completeAsync(
                          async,
                          request,
                          response,
                          marker,
                          configuredProtocol,
                          "netty-eventloop-worker");
                    });
              } catch (RejectedExecutionException rejected) {
                failAsync(async, response, "Netty worker executor is unavailable");
              }
            });
      } catch (RejectedExecutionException rejected) {
        failAsync(async, response, "Netty event loop is unavailable");
      }
    }
  }

  private static final class BridgeDiagnosticsServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
      response.setStatus(HttpServletResponse.SC_OK);
      response.setContentType("text/plain");
      response.setCharacterEncoding("US-ASCII");
      response.setHeader("Cache-Control", "no-store");
      try (PrintWriter writer = response.getWriter()) {
        writer.println(bridgeDiagnostics());
      }
    }
  }

  static final class TransportConfigurationServlet extends HttpServlet {
    private final ClassLoader bridgeClassLoader;

    TransportConfigurationServlet() {
      this(null);
    }

    TransportConfigurationServlet(ClassLoader bridgeClassLoader) {
      this.bridgeClassLoader = bridgeClassLoader;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
      response.setStatus(HttpServletResponse.SC_OK);
      response.setContentType("text/plain");
      response.setCharacterEncoding("US-ASCII");
      response.setHeader("Cache-Control", "no-store");
      try (PrintWriter writer = response.getWriter()) {
        writer.println(bridgeTransportConfiguration(bridgeClassLoader));
      }
    }
  }

  private static final class TlsReceiveBoundaryServlet extends HttpServlet {
    private final TlsReceiveBoundaryFixture fixture;
    private final String configuredProtocol;

    private TlsReceiveBoundaryServlet(
        TlsReceiveBoundaryFixture fixture, String configuredProtocol) {
      this.fixture = fixture;
      this.configuredProtocol = configuredProtocol;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
      String marker = validatedMarker(request, response);
      if (marker == null) {
        return;
      }

      TlsReceiveBoundaryFixture.Mode mode;
      try {
        mode = TlsReceiveBoundaryFixture.Mode.parse(request.getParameter("mode"));
      } catch (IllegalArgumentException invalid) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, invalid.getMessage());
        return;
      }

      TlsReceiveBoundaryFixture.Evidence evidence;
      String fixtureMarker = "fixture-" + marker;
      if (fixtureMarker.length() > 128) {
        fixtureMarker = "fixture-" + Integer.toUnsignedString(marker.hashCode(), 36);
      }
      try {
        evidence = fixture.exercise(mode, fixtureMarker);
      } catch (IOException | IllegalStateException failure) {
        response.sendError(
            HttpServletResponse.SC_SERVICE_UNAVAILABLE,
            "TLS receive-boundary fixture did not complete");
        return;
      }

      response.setStatus(
          evidence.passed() ? HttpServletResponse.SC_OK : HttpServletResponse.SC_CONFLICT);
      response.setContentType("application/json");
      response.setCharacterEncoding("US-ASCII");
      response.setHeader("Cache-Control", "no-store");
      Object cipherAttribute = request.getAttribute("jakarta.servlet.request.cipher_suite");
      String cipher = cipherAttribute == null ? "" : cipherAttribute.toString();
      try (PrintWriter writer = response.getWriter()) {
        writer.printf(
            Locale.ROOT,
            "{\"marker\":\"%s\",\"secure\":%s,\"protocol\":\"%s\","
                + "\"tls_protocol\":\"%s\",\"tls_cipher\":\"%s\","
                + "\"backend_connection_id\":%d,\"backend_remote_port\":%d,"
                + "\"tls_read_events\":%d,\"tls_read_bytes\":%d,"
                + "\"tls_boundary\":%s}%n",
            jsonEscape(marker),
            request.isSecure(),
            jsonEscape(request.getProtocol()),
            jsonEscape(negotiatedProtocol(request, configuredProtocol)),
            jsonEscape(cipher),
            backendConnectionID(request),
            request.getRemotePort(),
            bridgeCounter("tlsReadEvents"),
            bridgeCounter("tlsReadBytes"),
            evidence.toJson().trim());
      }
    }
  }

  private static void dispatchHandoff(
      AsyncContext async,
      HttpServletRequest request,
      HttpServletResponse response,
      String marker,
      String configuredProtocol,
      int hops,
      String fault,
      int completedHops) {
    if (completedHops < hops) {
      ExecutorService executor = (completedHops & 1) == 0 ? HANDOFF_FIRST : HANDOFF_SECOND;
      try {
        executor.execute(
            () ->
                dispatchHandoff(
                    async,
                    request,
                    response,
                    marker,
                    configuredProtocol,
                    hops,
                    fault,
                    completedHops + 1));
      } catch (RejectedExecutionException rejected) {
        failAsync(async, response, "handoff executor is unavailable");
      }
      return;
    }

    try {
      exerciseFaultPath(fault);
      response.setHeader("X-OBI-Workload", "servlet-async-executor");
      response.setHeader("X-OBI-Handoff-Hops", Integer.toString(hops));
      response.setHeader("X-OBI-Handoff-Fault", fault);
      completeAsync(
          async, request, response, marker, configuredProtocol, "servlet-async-executor");
    } catch (RuntimeException failure) {
      failAsync(async, response, "handoff workload failed");
    }
  }

  private static void exerciseFaultPath(String fault) {
    if ("none".equals(fault)) {
      return;
    }
    if ("cancel".equals(fault)) {
      Future<?> cancelled = FAULT_EXECUTOR.schedule(() -> {}, 1, TimeUnit.HOURS);
      if (!cancelled.cancel(false)) {
        throw new IllegalStateException("unable to cancel handoff task");
      }
      return;
    }
    if ("reject".equals(fault)) {
      try {
        REJECTING_EXECUTOR.execute(() -> {});
        throw new IllegalStateException("rejecting executor accepted a task");
      } catch (RejectedExecutionException expected) {
        return;
      }
    }

    Future<?> timedOut = FAULT_EXECUTOR.schedule(() -> {}, 1, TimeUnit.SECONDS);
    try {
      timedOut.get(1, TimeUnit.MILLISECONDS);
      throw new IllegalStateException("delayed task completed before timeout");
    } catch (TimeoutException expected) {
      timedOut.cancel(false);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      timedOut.cancel(false);
      throw new IllegalStateException("timeout workload was interrupted", interrupted);
    } catch (java.util.concurrent.ExecutionException failure) {
      throw new IllegalStateException("timeout workload failed", failure);
    }
  }

  private static void completeAsync(
      AsyncContext async,
      HttpServletRequest request,
      HttpServletResponse response,
      String marker,
      String configuredProtocol,
      String workload) {
    try {
      writeResponse(response, request, marker, configuredProtocol);
    } catch (IOException failure) {
      System.err.printf(Locale.ROOT, "%s response failed: %s%n", workload, failure.getMessage());
    } finally {
      async.complete();
    }
  }

  private static void failAsync(
      AsyncContext async, HttpServletResponse response, String publicMessage) {
    try {
      response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, publicMessage);
    } catch (IOException failure) {
      System.err.printf(
          Locale.ROOT, "asynchronous error response failed: %s%n", failure.getMessage());
    } finally {
      async.complete();
    }
  }

  private static String validatedMarker(
      HttpServletRequest request, HttpServletResponse response) throws IOException {
    String marker = request.getHeader("x-obi-demo-id");
    if (marker == null || !MARKER_PATTERN.matcher(marker).matches()) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid x-obi-demo-id header");
      return null;
    }
    return marker;
  }

  static int parseHops(String raw) {
    if (raw == null || raw.isEmpty()) {
      return 2;
    }
    try {
      int hops = Integer.parseInt(raw);
      if (hops < 1 || hops > MAX_HANDOFFS) {
        throw new IllegalArgumentException("hops must be between 1 and 8");
      }
      return hops;
    } catch (NumberFormatException failure) {
      throw new IllegalArgumentException("hops must be an integer", failure);
    }
  }

  static int parseDispatchRounds(String raw) {
    if (raw == null || raw.isEmpty()) {
      return 2;
    }
    try {
      int rounds = Integer.parseInt(raw);
      if (rounds < 1 || rounds > MAX_DISPATCH_ROUNDS) {
        throw new IllegalArgumentException("rounds must be between 1 and 8");
      }
      return rounds;
    } catch (NumberFormatException failure) {
      throw new IllegalArgumentException("rounds must be an integer", failure);
    }
  }

  static String parseHandoffFault(String raw) {
    String fault = raw == null || raw.isEmpty() ? "none" : raw;
    if (!HANDOFF_FAULTS.contains(fault)) {
      throw new IllegalArgumentException("fault must be none, cancel, reject, or timeout");
    }
    return fault;
  }

  static boolean parseFlag(String raw, boolean fallback, String name) {
    if (raw == null || raw.isEmpty()) {
      return fallback;
    }
    if ("1".equals(raw)) {
      return true;
    }
    if ("0".equals(raw)) {
      return false;
    }
    throw new IllegalArgumentException(name + " must be 0 or 1");
  }

  static boolean cancelTask(Future<?> task, boolean mayInterruptIfRunning) {
    return task.cancel(mayInterruptIfRunning);
  }

  private static ThreadFactory namedThreadFactory(String prefix) {
    AtomicInteger sequence = new AtomicInteger();
    return task -> {
      Thread thread = new Thread(task, prefix + sequence.incrementAndGet());
      thread.setDaemon(true);
      return thread;
    };
  }

  private static ExecutorService rejectingExecutor() {
    ExecutorService executor = Executors.newSingleThreadExecutor(namedThreadFactory("obi-reject-"));
    executor.shutdown();
    return executor;
  }

  private static ExecutorService virtualThreadExecutor() {
    try {
      Object executor =
          Executors.class.getMethod("newVirtualThreadPerTaskExecutor").invoke(null);
      return (ExecutorService) executor;
    } catch (NoSuchMethodException unsupported) {
      return null;
    } catch (IllegalAccessException | InvocationTargetException failure) {
      throw new ExceptionInInitializerError(failure);
    }
  }

  private static String bridgeDiagnostics() {
    try {
      Class<?> bridge =
          Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBootstrap", true, null);
      Object snapshot = bridge.getMethod("diagnosticsSnapshot").invoke(null);
      return snapshot == null ? "unavailable" : snapshot.toString();
    } catch (ReflectiveOperationException | LinkageError failure) {
      return "unavailable";
    }
  }

  private static String bridgeTransportConfiguration(ClassLoader bridgeClassLoader) {
    try {
      Class<?> diagnostics =
          Class.forName(
              "io.opentelemetry.obi.java.bridge.RemoteParentTransportDiagnosticsV1",
              true,
              bridgeClassLoader);
      Object snapshot = diagnostics.getMethod("snapshot").invoke(null);
      return snapshot == null ? "unavailable" : snapshot.toString();
    } catch (ReflectiveOperationException | LinkageError failure) {
      return "unavailable";
    }
  }

  private static void writeResponse(
      HttpServletResponse response,
      HttpServletRequest request,
      String marker,
      String configuredProtocol)
      throws IOException {
    Object cipherAttribute = request.getAttribute("jakarta.servlet.request.cipher_suite");
    String cipher = cipherAttribute == null ? "" : cipherAttribute.toString();
    String negotiatedProtocol = negotiatedProtocol(request, configuredProtocol);
    long backendConnectionID = backendConnectionID(request);
    int backendSocketFD = 0;
    if ("1".equals(request.getParameter("socket_identity"))) {
      backendSocketFD = backendSocketFileDescriptor(request);
    }
    long tlsReadEvents = bridgeCounter("tlsReadEvents");
    long tlsReadBytes = bridgeCounter("tlsReadBytes");

    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
    response.setHeader("Cache-Control", "no-store");
    String diagnostics =
        bridgeDiagnosticsHeaderValue(request.getParameterValues(BRIDGE_DIAGNOSTICS_PARAMETER));
    if (diagnostics != null) {
      response.setHeader(BRIDGE_DIAGNOSTICS_HEADER, diagnostics);
    }
    if ("1".equals(request.getParameter("close"))) {
      response.setHeader("Connection", "close");
    }
    try (PrintWriter writer = response.getWriter()) {
      writer.printf(
          Locale.ROOT,
          "{\"marker\":\"%s\",\"secure\":%s,\"protocol\":\"%s\","
              + "\"tls_protocol\":\"%s\",\"tls_cipher\":\"%s\","
              + "\"backend_connection_id\":%d,\"backend_remote_port\":%d,"
              + "\"backend_socket_fd\":%d,\"tls_read_events\":%d,"
              + "\"tls_read_bytes\":%d}%n",
          jsonEscape(marker),
          request.isSecure(),
          jsonEscape(request.getProtocol()),
          jsonEscape(negotiatedProtocol),
          jsonEscape(cipher),
          backendConnectionID,
          request.getRemotePort(),
          backendSocketFD,
          tlsReadEvents,
          tlsReadBytes);
    }
  }

  static String bridgeDiagnosticsHeaderValue(String[] optIn) {
    return optIn != null && optIn.length == 1 && "1".equals(optIn[0])
        ? bridgeDiagnostics()
        : null;
  }

  static long bridgeCounter(String method) {
    try {
      Class<?> bridge =
          Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBootstrap", true, null);
      Object value = bridge.getMethod(method).invoke(null);
      return value instanceof Number ? ((Number) value).longValue() : -1L;
    } catch (ReflectiveOperationException | LinkageError failure) {
      return -1L;
    }
  }

  private static long backendConnectionID(HttpServletRequest request) {
    Request baseRequest = Request.getBaseRequest(request);
    if (baseRequest == null || baseRequest.getHttpChannel() == null) {
      throw new IllegalStateException("Jetty base request has no HTTP channel");
    }
    Object connection = baseRequest.getHttpChannel().getConnection();
    if (connection == null) {
      throw new IllegalStateException("Jetty HTTP channel has no connection");
    }
    return connectionID(connection);
  }

  static long connectionID(Object connection) {
    if (connection == null) {
      throw new IllegalArgumentException("connection must not be null");
    }
    synchronized (BACKEND_CONNECTION_IDS) {
      IdentityWeakReference closed;
      while ((closed = (IdentityWeakReference) CLOSED_BACKEND_CONNECTIONS.poll()) != null) {
        BACKEND_CONNECTION_IDS.remove(closed);
      }
      IdentityWeakReference lookup = new IdentityWeakReference(connection, null);
      Long existing = BACKEND_CONNECTION_IDS.get(lookup);
      if (existing != null) {
        return existing;
      }
      long created = NEXT_BACKEND_CONNECTION_ID.getAndIncrement();
      if (created <= 0) {
        throw new IllegalStateException("backend connection identifier exhausted");
      }
      BACKEND_CONNECTION_IDS.put(
          new IdentityWeakReference(connection, CLOSED_BACKEND_CONNECTIONS), created);
      return created;
    }
  }

  private static final class IdentityWeakReference extends WeakReference<Object> {
    private final int identityHashCode;

    private IdentityWeakReference(Object referent, ReferenceQueue<Object> queue) {
      super(referent, queue);
      identityHashCode = System.identityHashCode(referent);
    }

    @Override
    public int hashCode() {
      return identityHashCode;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      if (!(other instanceof IdentityWeakReference)) {
        return false;
      }
      Object referent = get();
      return referent != null && referent == ((IdentityWeakReference) other).get();
    }
  }

  private static int backendSocketFileDescriptor(HttpServletRequest request) {
    long socketInode = findBackendSocketInode(request.getLocalPort(), request.getRemotePort());
    if (socketInode < 0) {
      return -1;
    }

    String expectedTarget = "socket:[" + socketInode + "]";
    try (DirectoryStream<Path> entries = Files.newDirectoryStream(Path.of("/proc/self/fd"))) {
      for (Path entry : entries) {
        int fileDescriptor;
        try {
          fileDescriptor = Integer.parseInt(entry.getFileName().toString());
        } catch (NumberFormatException ignored) {
          continue;
        }
        try {
          if (Files.readSymbolicLink(entry).toString().equals(expectedTarget)) {
            return fileDescriptor;
          }
        } catch (IOException ignored) {
          continue;
        }
      }
    } catch (IOException ignored) {
      return -1;
    }
    return -1;
  }

  private static long findBackendSocketInode(int localPort, int remotePort) {
    for (Path tcpTable : PROC_TCP_TABLES) {
      try (BufferedReader reader = Files.newBufferedReader(tcpTable)) {
        String line;
        while ((line = reader.readLine()) != null) {
          long socketInode = socketInodeFromProcLine(line, localPort, remotePort);
          if (socketInode >= 0) {
            return socketInode;
          }
        }
      } catch (IOException ignored) {
        continue;
      }
    }
    return -1;
  }

  static long socketInodeFromProcLine(String line, int localPort, int remotePort) {
    String[] fields = line.trim().split("\\s+");
    if (fields.length <= PROC_INODE_INDEX
        || !fields[PROC_STATE_INDEX].equals(TCP_ESTABLISHED_STATE)) {
      return -1;
    }
    try {
      if (hexadecimalPort(fields[PROC_LOCAL_ENDPOINT_INDEX]) != localPort
          || hexadecimalPort(fields[PROC_REMOTE_ENDPOINT_INDEX]) != remotePort) {
        return -1;
      }
      return Long.parseLong(fields[PROC_INODE_INDEX]);
    } catch (NumberFormatException ignored) {
      return -1;
    }
  }

  private static int hexadecimalPort(String endpoint) {
    int separator = endpoint.lastIndexOf(':');
    if (separator < 0 || separator == endpoint.length() - 1) {
      throw new NumberFormatException("missing hexadecimal port");
    }
    return Integer.parseInt(endpoint.substring(separator + 1), 16);
  }

  private static String negotiatedProtocol(HttpServletRequest request, String fallback) {
    Object sessionAttribute = request.getAttribute("org.eclipse.jetty.servlet.request.ssl_session");
    if (sessionAttribute instanceof SSLSession) {
      return ((SSLSession) sessionAttribute).getProtocol();
    }
    return fallback;
  }

  private static int parseDelay(String raw) {
    if (raw == null || raw.isEmpty()) {
      return 0;
    }
    try {
      int delay = Integer.parseInt(raw);
      if (delay < 0 || delay > MAX_DELAY_MILLIS) {
        throw new IllegalArgumentException("delay_ms must be between 0 and 1000");
      }
      return delay;
    } catch (NumberFormatException exception) {
      throw new IllegalArgumentException("delay_ms must be an integer", exception);
    }
  }

  private static int parsePort(String name, String raw) {
    int port = Integer.parseInt(raw);
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException(name + " must be between 1 and 65535");
    }
    return port;
  }

  private static String environment(String name, String fallback) {
    String value = System.getenv(name);
    return value == null || value.isEmpty() ? fallback : value;
  }

  static String jsonEscape(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  private static void stop(
      Server server, NettyHttpsServer nettyServer, TlsReceiveBoundaryFixture tlsBoundaryFixture) {
    if (!STOPPED.compareAndSet(false, true)) {
      return;
    }
    try {
      server.stop();
    } catch (Exception exception) {
      System.err.println("Jetty shutdown failed: " + exception.getMessage());
    }
    try {
      if (nettyServer != null) {
        nettyServer.close();
      }
    } catch (Exception exception) {
      System.err.println("Netty shutdown failed: " + exception.getMessage());
    } finally {
      HANDOFF_FIRST.shutdownNow();
      HANDOFF_SECOND.shutdownNow();
      FAULT_EXECUTOR.shutdownNow();
      NETTY_EVENT_LOOP.shutdownGracefully(0, 5, TimeUnit.SECONDS).syncUninterruptibly();
      if (VIRTUAL_EXECUTOR != null) {
        VIRTUAL_EXECUTOR.shutdownNow();
      }
      if (tlsBoundaryFixture != null) {
        tlsBoundaryFixture.close();
      }
    }
  }
}
