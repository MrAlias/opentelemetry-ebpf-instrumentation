/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.extension;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigurablePropagatorProvider;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class AgentCompatibility {
  private static final String UPSTREAM_AGENT_CLASS =
      "io.opentelemetry.javaagent.OpenTelemetryAgent";
  private static final String API_VERSION_RESOURCE = "io/opentelemetry/api/version.properties";
  private static final String SPI_VERSION_RESOURCE =
      "io/opentelemetry/sdk/autoconfigure/spi/version.properties";
  private static final String EXTENSION_VERSION_RESOURCE =
      "io/opentelemetry/obi/java/extension/version.properties";
  private static final Pattern SPLUNK_VERSION =
      Pattern.compile("splunk-([0-9]+\\.[0-9]+\\.[0-9]+)-otel-([0-9]+\\.[0-9]+\\.[0-9]+)");

  private final String distribution;
  private final String agentVersion;
  private final String apiVersion;
  private final String apiVersionSource;
  private final String spiVersion;
  private final String extensionVersion;
  private final int javaFeature;
  private final String agentLoader;
  private final String apiLoader;
  private final String spiLoader;
  private final String extensionLoader;
  private final boolean supported;
  private final String reason;

  private AgentCompatibility(
      String distribution,
      String agentVersion,
      String apiVersion,
      String apiVersionSource,
      String spiVersion,
      String extensionVersion,
      int javaFeature,
      String agentLoader,
      String apiLoader,
      String spiLoader,
      String extensionLoader,
      boolean supported,
      String reason) {
    this.distribution = distribution;
    this.agentVersion = normalized(agentVersion);
    this.apiVersion = normalized(apiVersion);
    this.apiVersionSource = normalized(apiVersionSource);
    this.spiVersion = normalized(spiVersion);
    this.extensionVersion = normalized(extensionVersion);
    this.javaFeature = javaFeature;
    this.agentLoader = normalized(agentLoader);
    this.apiLoader = normalized(apiLoader);
    this.spiLoader = normalized(spiLoader);
    this.extensionLoader = normalized(extensionLoader);
    this.supported = supported;
    this.reason = reason;
  }

  static AgentCompatibility inspect() {
    Class<?> agentClass = loadUpstreamAgentClass();
    String agentVersion = implementationVersion(agentClass);
    String spiVersion = libraryVersion(ConfigurablePropagatorProvider.class, SPI_VERSION_RESOURCE);
    String observedApiVersion = libraryVersion(Span.class, API_VERSION_RESOURCE);
    String apiVersion = alignedApiVersion(agentVersion, observedApiVersion, spiVersion);
    String apiVersionSource =
        apiVersion.equals(observedApiVersion) ? "api_package" : "agent_spi_alignment";
    String extensionVersion = extensionVersion();

    AgentCompatibility evaluated =
        evaluate(agentVersion, apiVersion, spiVersion, javaFeatureVersion());
    return new AgentCompatibility(
        evaluated.distribution,
        agentVersion,
        apiVersion,
        apiVersionSource,
        spiVersion,
        extensionVersion,
        evaluated.javaFeature,
        loaderName(agentClass),
        loaderName(Span.class),
        loaderName(ConfigurablePropagatorProvider.class),
        loaderName(AgentCompatibility.class),
        evaluated.supported,
        evaluated.reason);
  }

  static AgentCompatibility evaluate(
      String agentVersion, String apiVersion, String spiVersion, int javaFeature) {
    String distribution = distribution(agentVersion);
    String reason =
        incompatibility(distribution, agentVersion, apiVersion, spiVersion, javaFeature);
    return new AgentCompatibility(
        distribution,
        agentVersion,
        apiVersion,
        "explicit",
        spiVersion,
        "unknown",
        javaFeature,
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        reason == null,
        reason == null ? "compatible" : reason);
  }

  boolean isSupported() {
    return supported;
  }

  String snapshot() {
    return "distribution="
        + distribution
        + ",agent_version="
        + agentVersion
        + ",api_version="
        + apiVersion
        + ",api_version_source="
        + apiVersionSource
        + ",spi_version="
        + spiVersion
        + ",extension_version="
        + extensionVersion
        + ",java_feature="
        + javaFeature
        + ",provider=obi,supported="
        + supported
        + ",reason="
        + reason
        + ",agent_loader="
        + agentLoader
        + ",api_loader="
        + apiLoader
        + ",spi_loader="
        + spiLoader
        + ",extension_loader="
        + extensionLoader;
  }

  private static String incompatibility(
      String distribution,
      String agentVersion,
      String apiVersion,
      String spiVersion,
      int javaFeature) {
    if (!supportedJavaFeature(javaFeature)) {
      return "unsupported_java";
    }
    if (!"1.62.0".equals(normalized(apiVersion))) {
      return "unsupported_api";
    }
    if (!"1.62.0".equals(normalized(spiVersion))) {
      return "unsupported_spi";
    }
    if ("opentelemetry".equals(distribution)) {
      return "2.28.1".equals(normalized(agentVersion)) ? null : "unsupported_agent";
    }
    if ("splunk".equals(distribution)) {
      Matcher matcher = SPLUNK_VERSION.matcher(normalized(agentVersion));
      if (!matcher.matches()
          || !"2.28.0".equals(matcher.group(1))
          || !"2.28.1".equals(matcher.group(2))) {
        return "unsupported_agent";
      }
      return null;
    }
    return "unknown_agent";
  }

  private static boolean supportedJavaFeature(int javaFeature) {
    return javaFeature == 8 || javaFeature == 11 || javaFeature == 17 || javaFeature == 21;
  }

  private static String distribution(String agentVersion) {
    String version = normalized(agentVersion);
    if (SPLUNK_VERSION.matcher(version).matches()) {
      return "splunk";
    }
    if (parseVersion(version) != null) {
      return "opentelemetry";
    }
    return "unknown";
  }

  private static String alignedApiVersion(
      String agentVersion, String apiVersion, String spiVersion) {
    String agent = normalized(agentVersion);
    String api = normalized(apiVersion);
    String spi = normalized(spiVersion);
    if (!api.equals(agent) || !"1.62.0".equals(spi)) {
      return api;
    }
    if ("2.28.1".equals(agent) || "splunk-2.28.0-otel-2.28.1".equals(agent)) {
      return spi;
    }
    return api;
  }

  private static int[] parseVersion(String value) {
    String[] components = value.split("\\.", -1);
    if (components.length != 3) {
      return null;
    }
    int[] parsed = new int[3];
    try {
      for (int i = 0; i < parsed.length; i++) {
        if (components[i].isEmpty()) {
          return null;
        }
        parsed[i] = Integer.parseInt(components[i]);
        if (parsed[i] < 0) {
          return null;
        }
      }
    } catch (NumberFormatException ignored) {
      return null;
    }
    return parsed;
  }

  private static Class<?> loadUpstreamAgentClass() {
    try {
      return Class.forName(UPSTREAM_AGENT_CLASS, false, ClassLoader.getSystemClassLoader());
    } catch (Throwable ignored) {
      return null;
    }
  }

  private static String libraryVersion(Class<?> owner, String resource) {
    ClassLoader loader = owner.getClassLoader();
    if (loader == null) {
      loader = ConfigurablePropagatorProvider.class.getClassLoader();
    }
    String resourceVersion = property(loader, resource, "sdk.version");
    if (parseVersion(normalized(resourceVersion)) != null) {
      return resourceVersion;
    }
    return implementationVersion(owner);
  }

  private static String extensionVersion() {
    String resourceVersion =
        property(
            AgentCompatibility.class.getClassLoader(),
            EXTENSION_VERSION_RESOURCE,
            "extension.version");
    return "unknown".equals(resourceVersion)
        ? implementationVersion(AgentCompatibility.class)
        : resourceVersion;
  }

  private static String property(ClassLoader loader, String resource, String name) {
    if (loader == null) {
      return "unknown";
    }
    try (InputStream input = loader.getResourceAsStream(resource)) {
      if (input == null) {
        return "unknown";
      }
      Properties properties = new Properties();
      properties.load(input);
      return properties.getProperty(name, "unknown");
    } catch (IOException | RuntimeException ignored) {
      return "unknown";
    }
  }

  private static String implementationVersion(Class<?> type) {
    if (type == null) {
      return "unknown";
    }
    try {
      Package typePackage = type.getPackage();
      String version = typePackage == null ? null : typePackage.getImplementationVersion();
      return normalized(version);
    } catch (Throwable ignored) {
      return "unknown";
    }
  }

  private static String loaderName(Class<?> type) {
    if (type == null) {
      return "missing";
    }
    try {
      ClassLoader loader = type.getClassLoader();
      return loader == null ? "bootstrap" : loader.getClass().getName();
    } catch (Throwable ignored) {
      return "unknown";
    }
  }

  private static int javaFeatureVersion() {
    String version = System.getProperty("java.specification.version", "0");
    int start = version.startsWith("1.") ? 2 : 0;
    int end = version.indexOf('.', start);
    try {
      return Integer.parseInt(end < 0 ? version.substring(start) : version.substring(start, end));
    } catch (NumberFormatException ignored) {
      return 0;
    }
  }

  private static String normalized(String value) {
    if (value == null || value.isEmpty()) {
      return "unknown";
    }
    return value.replace(',', '_').replace(' ', '_');
  }
}
