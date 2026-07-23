/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static net.bytebuddy.dynamic.loading.ClassInjector.UsingInstrumentation.Target.BOOTSTRAP;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;

import io.opentelemetry.obi.java.instrumentations.*;
import java.io.File;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.loading.ClassInjector;
import net.bytebuddy.utility.JavaModule;

public class Agent {
  private static final String REMOTE_PARENT_BOOTSTRAP_CLASS =
      "io.opentelemetry.obi.java.bridge.RemoteParentBootstrap";
  public static volatile boolean debugOn = false;
  private static final Logger logger = Logger.getLogger("Agent");
  private static volatile boolean agentLoaded = false;
  private static boolean agentInstallationInProgress = false;
  private static final Set<String> BOOTSTRAP_HELPER_CLASS_NAMES =
      Collections.unmodifiableSet(
          new LinkedHashSet<>(
              Arrays.asList(
                  "io.opentelemetry.obi.java.BootstrapNative",
                  "io.opentelemetry.obi.java.ebpf.ProxyOutputStream",
                  "io.opentelemetry.obi.java.ebpf.ProxyInputStream",
                  "io.opentelemetry.obi.java.ebpf.ConnectionInfo",
                  "io.opentelemetry.obi.java.ebpf.ThreadInfo",
                  "io.opentelemetry.obi.java.ebpf.ThreadInfo$TaskRelayState",
                  "io.opentelemetry.obi.java.ebpf.ThreadInfo$TaskContextEmitter",
                  "io.opentelemetry.obi.java.ebpf.IOCTLPacket",
                  "io.opentelemetry.obi.java.ebpf.OperationType",
                  "io.opentelemetry.obi.java.ebpf.NativeMemory",
                  "io.opentelemetry.obi.java.instrumentations.data.BytesWithLen",
                  "io.opentelemetry.obi.java.instrumentations.data.Connection",
                  "io.opentelemetry.obi.java.instrumentations.data.SSLStorage",
                  "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$BufferHandoff",
                  "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$ConnectionOwner",
                  "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$ExactConnection",
                  "io.opentelemetry.obi.java.instrumentations.data.SSLStorage$TlsConnectionMarkerAttempt",
                  "io.opentelemetry.obi.java.instrumentations.data.RemoteParentSocketContext",
                  "io.opentelemetry.obi.java.instrumentations.data.TaskContext",
                  "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityConcurrentMap",
                  "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityConcurrentMap$IdentityWeakReference",
                  "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityTaskMap",
                  "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityTaskMap$Bucket",
                  "io.opentelemetry.obi.java.instrumentations.data.WeakIdentityTaskMap$Entry",
                  "io.opentelemetry.obi.java.instrumentations.util.ByteBufferExtractor",
                  "io.opentelemetry.obi.java.instrumentations.util.CappedConcurrentHashMap",
                  "io.opentelemetry.obi.java.instrumentations.util.NettyChannelExtractor",
                  "io.opentelemetry.obi.java.bridge.RemoteParentStatus",
                  "io.opentelemetry.obi.java.bridge.RemoteParentDiagnostics",
                  "io.opentelemetry.obi.java.bridge.RemoteParentTransport",
                  "io.opentelemetry.obi.java.bridge.RemoteParentRecord",
                  "io.opentelemetry.obi.java.bridge.RemoteParentProvider",
                  "io.opentelemetry.obi.java.bridge.RemoteParentBridge",
                  "io.opentelemetry.obi.java.bridge.RemoteParentBridge$NoopProvider",
                  "io.opentelemetry.obi.java.bridge.NativeRemoteParentProvider",
                  "io.opentelemetry.obi.java.bridge.NativeRemoteParentProvider$ProcessRegistrar",
                  "io.opentelemetry.obi.java.bridge.NativeRemoteParentProvider$TransportConfigurer",
                  "io.opentelemetry.obi.java.bridge.RemoteParentBootstrap")));

  static AgentBuilder builder(Map<String, String> opts, Instrumentation inst) {
    AgentBuilder builder =
        new AgentBuilder.Default()
            .with(
                new AgentBuilder.LocationStrategy() {
                  @Override
                  public ClassFileLocator classFileLocator(
                      ClassLoader classLoader, JavaModule module) {
                    return ClassFileLocator.ForClassLoader.of(classLoader);
                  }
                })
            .disableClassFormatChanges()
            .ignore(nameStartsWith("io.opentelemetry.obi"))
            .with(
                AgentBuilder.RedefinitionStrategy
                    .RETRANSFORMATION) // required for dynamic injection
            .with(
                AgentBuilder.InitializationStrategy.NoOp.INSTANCE) // required for dynamic injection
            .with(AgentBuilder.TypeStrategy.Default.REDEFINE) // required for dynamic injection
        ;
    if (optEnabled(opts, "debugBB")) {
      builder = builder.with(AgentBuilder.Listener.StreamWriting.toSystemOut());
    }

    return builder;
  }

  static Map<String, String> parseArgs(String agentArgs) {
    Map<String, String> opts = new HashMap<>();
    if (agentArgs != null && !agentArgs.isEmpty()) {
      String[] options = agentArgs.split(",");
      for (String option : options) {
        String[] keyValue = option.split("=", 2);
        if (keyValue.length == 2) {
          opts.put(keyValue[0], keyValue[1]);
        }
      }
    }

    return opts;
  }

  private static boolean optEnabled(Map<String, String> opts, String opt) {
    String optVal = opts.getOrDefault(opt, "");
    return optVal.toLowerCase(Locale.getDefault()).equals("true");
  }

  // Main agent load and instrumentation code, this gets invoked directly with -javaagent on the
  // command line
  public static void premain(String agentArgs, Instrumentation inst) {
    if (install(agentArgs, inst)) {
      logger.info("OBI Java instrumentation ready");
    }
  }

  private static boolean install(String agentArgs, Instrumentation inst) {
    String osName = System.getProperty("os.name").toLowerCase(Locale.getDefault());
    if (!osName.contains("linux")) {
      logger.info("OpenTelemetry eBPF Java Agent only supports Linux, ignoring load request");
      return false;
    }

    Map<String, String> opts = parseArgs(agentArgs);
    if (reconfigureExistingInstallation(opts)) {
      return false;
    }

    if (!claimLocalInstallation()) {
      synchronized (Agent.class) {
        if (agentLoaded) {
          initializeRemoteParentBridge(opts);
          logger.info("OpenTelemetry eBPF Java Agent already loaded; transport reconfigured");
        } else {
          logger.info("OpenTelemetry eBPF Java Agent installation already in progress");
        }
        return false;
      }
    }

    if (optEnabled(opts, "debug")) {
      Agent.debugOn = true;
    }

    boolean installationClaimed = false;
    try {
      initClassesThatNeedToBeBootstrapped();
      injectBootstrapClasses(inst);
      installationClaimed = beginBootstrapInstallation();
      if (!installationClaimed) {
        clearLocalInstallationClaim(false);
        initializeRemoteParentBridge(opts);
        logger.info("OpenTelemetry eBPF Java Agent already installed; transport reconfigured");
        return false;
      }
      initializeRemoteParentBridge(opts);
      if (Agent.debugOn) {
        setupInstrumentationsDebugging();
      }

      builder(opts, inst)
          .type(SSLSocketInst.type())
          .transform(SSLSocketInst.transformer())
          .type(SSLSocketStreamInst.inputStreamType())
          .transform(SSLSocketStreamInst.inputStreamTransformer())
          .type(SSLSocketStreamInst.outputStreamType())
          .transform(SSLSocketStreamInst.outputStreamTransformer())
          .type(SSLEngineInst.type())
          .transform(SSLEngineInst.transformer())
          .type(SocketChannelInst.type())
          .transform(SocketChannelInst.transformer())
          .type(NettySSLHandlerInst.type())
          .transform(NettySSLHandlerInst.transformer())
          .type(JavaExecutorInst.type())
          .transform(JavaExecutorInst.transformer())
          .type(NettyExecutorInst.type())
          .transform(NettyExecutorInst.transformer())
          .type(CallableInst.type())
          .transform(CallableInst.transformer())
          .type(RunnableInst.type())
          .transform(RunnableInst.transformer())
          .type(JavaForkJoinTaskInst.type())
          .transform(JavaForkJoinTaskInst.transformer())
          .type(FutureInst.type())
          .transform(FutureInst.transformer())
          .type(RejectedExecutionHandlerInst.type())
          .transform(RejectedExecutionHandlerInst.transformer())
          .type(BlockingQueueInst.type())
          .transform(BlockingQueueInst.transformer())
          .type(VirtualThreadInst.type())
          .transform(VirtualThreadInst.transformer())
          .installOn(inst);
      completeBootstrapInstallation();
      clearLocalInstallationClaim(true);
      return true;
    } catch (Throwable failure) {
      if (installationClaimed) {
        cancelBootstrapInstallation();
      }
      clearLocalInstallationClaim(false);
      logger.log(Level.SEVERE, "Failed to load agent", failure);
      return false;
    }
  }

  // Needed for Dynamic Agent Injection
  public static void agentmain(String args, Instrumentation inst) {
    if (install(args, inst)) {
      retransformLoadedClasses(inst);
      logger.info("OBI Java instrumentation ready");
    }
  }

  // Package-private for testing. Retransforms already-loaded classes that match the agent's
  // instrumentation targets. This is required for dynamic injection because some classes are
  // loaded before ByteBuddy's transformer is installed.
  static void retransformLoadedClasses(Instrumentation inst) {
    for (Class<?> clazz : inst.getAllLoadedClasses()) {
      // Skip lambda classes — on Java 8 retransforming them corrupts their constant pool
      // linkage due to JDK-8145964, causing NoClassDefFoundError.
      if (clazz.getName().contains("$$Lambda$")) {
        continue;
      }
      if (SSLSocketInst.matches(clazz)
          || SSLSocketStreamInst.matchesInputStream(clazz)
          || SSLSocketStreamInst.matchesOutputStream(clazz)
          || SSLEngineInst.matches(clazz)
          || SocketChannelInst.matches(clazz)
          || JavaExecutorInst.matches(clazz)
          || NettyExecutorInst.matches(clazz)
          || CallableInst.matches(clazz)
          || RunnableInst.matches(clazz)
          || JavaForkJoinTaskInst.matches(clazz)
          || FutureInst.matches(clazz)
          || RejectedExecutionHandlerInst.matches(clazz)
          || BlockingQueueInst.matches(clazz)
          || NettySSLHandlerInst.matches(clazz)
          || VirtualThreadInst.matches(clazz)) {
        if (Agent.debugOn) {
          logger.info("Retransforming " + clazz);
        }
        try {
          inst.retransformClasses(clazz);
        } catch (Throwable t) { // Failure can be normal if we've retransformed this class before
          if (Agent.debugOn) {
            logger.severe("Error " + t.getMessage());
          }
        }
      }
    }
  }

  // Just a test method functionality, not used in the Agent
  public static void main(String[] args) {
    premain(null, ByteBuddyAgent.install());
  }

  private static void initClassesThatNeedToBeBootstrapped() throws Exception {
    for (String className : BOOTSTRAP_HELPER_CLASS_NAMES) {
      Class.forName(className);
    }
  }

  private static void initializeRemoteParentBridge(Map<String, String> opts) {
    String transport = opts.getOrDefault("remoteParentTransport", "disabled");
    String socketPath =
        opts.getOrDefault("remoteParentSocket", "/var/run/obi/java-remote-parent.sock");
    int timeoutMillis =
        boundedIntOption(opts, "remoteParentTimeoutMillis", 50, 1, Integer.MAX_VALUE);
    long serverUid = boundedLongOption(opts, "remoteParentServerUid", 0L, 0L, 0xffff_ffffL);
    long processCapability = boundedLongOption(opts, "processCapability", 0L, 1L, Long.MAX_VALUE);

    try {
      Class<?> bootstrap = Class.forName(REMOTE_PARENT_BOOTSTRAP_CLASS, true, null);
      java.lang.reflect.Method initialize =
          bootstrap.getMethod(
              "initialize", String.class, String.class, int.class, long.class, long.class);
      Object installed =
          initialize.invoke(
              null, transport, socketPath, timeoutMillis, serverUid, processCapability);
      if (Boolean.TRUE.equals(installed)) {
        logger.info("OBI remote-parent provider ready");
      } else if (!"disabled".equalsIgnoreCase(transport)) {
        logger.warning("OBI remote-parent bridge provider is not ready");
      }
      logger.info(
          "OBI remote-parent diagnostics "
              + bootstrap.getMethod("diagnosticsSnapshot").invoke(null));
    } catch (Throwable t) {
      logger.log(Level.WARNING, "OBI remote-parent bridge is unavailable", t);
    }
  }

  private static boolean reconfigureExistingInstallation(Map<String, String> opts) {
    try {
      Class<?> bootstrap = Class.forName(REMOTE_PARENT_BOOTSTRAP_CLASS, true, null);
      java.lang.reflect.Method claimed = bootstrap.getMethod("instrumentationInstallationClaimed");
      if (!Boolean.TRUE.equals(claimed.invoke(null))) {
        return false;
      }
      initializeRemoteParentBridge(opts);
      logger.info("OpenTelemetry eBPF Java Agent already installed; transport reconfigured");
      return true;
    } catch (ClassNotFoundException ignored) {
      return false;
    } catch (Throwable failure) {
      logger.log(
          Level.WARNING,
          "Unable to inspect the existing OpenTelemetry eBPF Java Agent installation; "
              + "skipping duplicate installation",
          failure);
      return true;
    }
  }

  private static boolean beginBootstrapInstallation() throws Exception {
    Class<?> bootstrap = Class.forName(REMOTE_PARENT_BOOTSTRAP_CLASS, true, null);
    return Boolean.TRUE.equals(
        bootstrap.getMethod("beginInstrumentationInstallation").invoke(null));
  }

  private static void completeBootstrapInstallation() throws Exception {
    Class<?> bootstrap = Class.forName(REMOTE_PARENT_BOOTSTRAP_CLASS, true, null);
    bootstrap.getMethod("completeInstrumentationInstallation").invoke(null);
  }

  private static void cancelBootstrapInstallation() {
    try {
      Class<?> bootstrap = Class.forName(REMOTE_PARENT_BOOTSTRAP_CLASS, true, null);
      bootstrap.getMethod("cancelInstrumentationInstallation").invoke(null);
    } catch (Throwable failure) {
      logger.log(Level.WARNING, "Unable to cancel the failed agent installation", failure);
    }
  }

  static synchronized boolean claimLocalInstallation() {
    if (agentLoaded || agentInstallationInProgress) {
      return false;
    }
    agentInstallationInProgress = true;
    return true;
  }

  static synchronized void clearLocalInstallationClaim(boolean installed) {
    agentLoaded = installed;
    agentInstallationInProgress = false;
  }

  static int boundedIntOption(
      Map<String, String> opts, String name, int defaultValue, int minimum, int maximum) {
    String value = opts.get(name);
    if (value == null) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(value);
      return Math.max(minimum, Math.min(maximum, parsed));
    } catch (NumberFormatException ignored) {
      return defaultValue;
    }
  }

  static long boundedLongOption(
      Map<String, String> opts, String name, long defaultValue, long minimum, long maximum) {
    String value = opts.get(name);
    if (value == null) {
      return defaultValue;
    }
    try {
      long parsed = Long.parseLong(value);
      if (parsed < minimum || parsed > maximum) {
        return defaultValue;
      }
      return parsed;
    } catch (NumberFormatException ignored) {
      return defaultValue;
    }
  }

  private static void injectBootstrapClasses(Instrumentation instrumentation) throws Exception {
    File tempDir = Files.createTempDirectory("obi-agent").toFile();
    // Delete on exit in case we throw some sort of exception
    tempDir.deleteOnExit();
    Map<TypeDescription, byte[]> typeMap = new java.util.HashMap<>();
    ClassLoader agentClassLoader = Agent.class.getClassLoader();

    ClassFileLocator locator =
        new ClassFileLocator.Compound(
            ClassFileLocator.ForClassLoader.ofSystemLoader(),
            ClassFileLocator.ForClassLoader.of(agentClassLoader),
            ClassFileLocator.ForClassLoader.ofPlatformLoader(),
            ClassFileLocator.ForClassLoader.ofBootLoader());

    Set<String> missingHelpers = new HashSet<>();
    for (String className : BOOTSTRAP_HELPER_CLASS_NAMES) {
      try {
        Class.forName(className, false, null);
      } catch (ClassNotFoundException ignored) {
        missingHelpers.add(className);
      }
    }

    for (Class<?> clazz : instrumentation.getAllLoadedClasses()) {
      TypeDescription desc = new TypeDescription.ForLoadedType(clazz);
      if (missingHelpers.contains(desc.getName())) {
        try {
          byte[] bytes = locator.locate(desc.getName()).resolve();
          typeMap.put(desc, bytes);
        } catch (Throwable ignored) {
        }
      }
    }
    if (typeMap.size() != missingHelpers.size()) {
      throw new IllegalStateException("Unable to resolve every missing bootstrap helper class");
    }

    if (!typeMap.isEmpty()) {
      ClassInjector injector =
          ClassInjector.UsingInstrumentation.of(tempDir, BOOTSTRAP, instrumentation);
      injector.inject(typeMap);
    }
    tempDir.delete();

    // After injecting into bootstrap, we need to ensure the native library is loaded
    // in the bootstrap classloader context
    try {
      Class<?> bootstrapNativeClass =
          Class.forName("io.opentelemetry.obi.java.BootstrapNative", true, null);
      java.lang.reflect.Method loadMethod =
          bootstrapNativeClass.getDeclaredMethod("loadNativeLibrary", String.class);
      java.lang.reflect.Method loadedMethod =
          bootstrapNativeClass.getDeclaredMethod("isNativeLibraryLoaded");
      loadMethod.setAccessible(true);
      loadedMethod.setAccessible(true);
      if (!Boolean.TRUE.equals(loadedMethod.invoke(null))) {
        String nativeLibrary = extractNativeLibraryFromJar();
        try {
          loadMethod.invoke(null, nativeLibrary);
        } finally {
          File extracted = new File(nativeLibrary);
          if (!extracted.delete()) {
            extracted.deleteOnExit();
          }
        }
      }

      if (Agent.debugOn) {
        logger.info("Successfully loaded native library in bootstrap classloader");
      }

      // Force-initialize the BOOTSTRAP copies of every class on the
      // VirtualThread mount-advice emit path NOW: lazy classloading on the
      // mount path (JarFile synchronized I/O) can pin carriers and deadlock.
      for (String name :
          new String[] {
            io.opentelemetry.obi.java.ebpf.ThreadInfo.class.getName(),
            io.opentelemetry.obi.java.ebpf.IOCTLPacket.class.getName(),
            io.opentelemetry.obi.java.ebpf.OperationType.class.getName(),
            io.opentelemetry.obi.java.ebpf.NativeMemory.class.getName(),
          }) {
        Class.forName(name, true, null);
      }

    } catch (Exception e) {
      if (Agent.debugOn) {
        logger.severe("Error initializing the JNI library" + e.getMessage());
      }
      throw e;
    }
  }

  static boolean isBootstrapHelperClassName(String className) {
    return BOOTSTRAP_HELPER_CLASS_NAMES.contains(className);
  }

  // Picks the correct native library based on the
  private static String nativeLibraryResourcePath() {
    String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);

    if (arch.equals("amd64") || arch.equals("x86_64")) {
      return "/native/linux-amd64/libobijni.so";
    }

    if (arch.equals("aarch64") || arch.equals("arm64")) {
      return "/native/linux-aarch64/libobijni.so";
    }

    throw new IllegalStateException("Unsupported architecture: " + arch);
  }

  private static String extractNativeLibraryFromJar() throws Exception {
    InputStream libStream = Agent.class.getResourceAsStream(nativeLibraryResourcePath());
    if (libStream != null) {
      if (Agent.debugOn) {
        logger.info("[Agent] Found library in JAR, extracting to temp file...");
      }

      // Extract to temp file
      File tempLib = File.createTempFile("libobijni", ".so");

      try (java.io.FileOutputStream out = new java.io.FileOutputStream(tempLib)) {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = libStream.read(buffer)) != -1) {
          out.write(buffer, 0, bytesRead);
        }
      } finally {
        libStream.close();
      }

      if (Agent.debugOn) {
        logger.info("Extracted to: " + tempLib.getAbsolutePath());
        logger.info("File size: " + tempLib.length() + " bytes");
        logger.info("File exists: " + tempLib.exists());
        logger.info("File readable: " + tempLib.canRead());
      }

      if (Agent.debugOn) {
        logger.info("Extracted native library from JAR: " + tempLib.getAbsolutePath());
      }
      return tempLib.getAbsolutePath();
    } else {
      throw new Exception("agent not found in jar file");
    }
  }

  // Must be called after we've called injectBootstrapClasses
  public static void setupInstrumentationsDebugging() {
    try {
      Class<?> sslStorageClass =
          Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
      Field debugOn = sslStorageClass.getDeclaredField("debugOn");
      debugOn.set(null, true);
      logger.info("Setting up instrumentations debugging");
    } catch (Exception x) {
      logger.log(Level.SEVERE, "Failed to setup instrumentation debugging", x);
    }
  }
}
