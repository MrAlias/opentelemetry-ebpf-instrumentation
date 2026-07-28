// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

final class TlsContextFactory {
  private TlsContextFactory() {}

  static Contexts load(Path keyStorePath, String keyStorePassword, String tlsProtocol)
      throws Exception {
    char[] password = keyStorePassword.toCharArray();
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream input = Files.newInputStream(keyStorePath)) {
      keyStore.load(input, password);
    }

    KeyManagerFactory keyManagers =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagers.init(keyStore, password);
    TrustManagerFactory trustManagers =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagers.init(keyStore);

    SslContext serverContext =
        SslContextBuilder.forServer(keyManagers)
            .sslProvider(SslProvider.JDK)
            .protocols(tlsProtocol)
            .build();
    SSLContext clientContext = SSLContext.getInstance(tlsProtocol);
    clientContext.init(null, trustManagers.getTrustManagers(), new SecureRandom());
    return new Contexts(serverContext, clientContext.getSocketFactory());
  }

  static final class Contexts {
    private final SslContext serverContext;
    private final SSLSocketFactory clientSocketFactory;

    private Contexts(SslContext serverContext, SSLSocketFactory clientSocketFactory) {
      this.serverContext = serverContext;
      this.clientSocketFactory = clientSocketFactory;
    }

    SslContext serverContext() {
      return serverContext;
    }

    SSLSocketFactory clientSocketFactory() {
      return clientSocketFactory;
    }
  }
}
