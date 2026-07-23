/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.probe;

import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/** Loaded without an application or agent class-loader parent by the late-attach probe. */
public final class IsolatedBridgeConsumer {
  private IsolatedBridgeConsumer() {}

  public static SSLEngine newEngine() {
    return new IsolatedEngine();
  }

  public static int remoteParentStatus() throws Exception {
    try {
      Class<?> bridge =
          Class.forName("io.opentelemetry.obi.java.bridge.RemoteParentBridge", true, null);
      Object record = bridge.getMethod("takeRemoteParent").invoke(null);
      return (Integer) record.getClass().getMethod("getStatus").invoke(record);
    } catch (ClassNotFoundException unavailable) {
      return -1;
    }
  }

  private static final class IsolatedEngine extends SSLEngine {
    @Override
    public String getPeerHost() {
      return null;
    }

    @Override
    public int getPeerPort() {
      return 0;
    }

    @Override
    public void beginHandshake() {}

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
      return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
    }

    @Override
    public void closeInbound() {}

    @Override
    public boolean isInboundDone() {
      return false;
    }

    @Override
    public void closeOutbound() {}

    @Override
    public boolean isOutboundDone() {
      return false;
    }

    @Override
    public String[] getSupportedCipherSuites() {
      return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
      return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {}

    @Override
    public String[] getSupportedProtocols() {
      return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
      return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {}

    @Override
    public Runnable getDelegatedTask() {
      return null;
    }

    @Override
    public boolean getEnableSessionCreation() {
      return false;
    }

    @Override
    public boolean getNeedClientAuth() {
      return false;
    }

    @Override
    public boolean getUseClientMode() {
      return false;
    }

    @Override
    public boolean getWantClientAuth() {
      return false;
    }

    @Override
    public void setEnableSessionCreation(boolean enabled) {}

    @Override
    public void setNeedClientAuth(boolean needed) {}

    @Override
    public void setUseClientMode(boolean clientMode) {}

    @Override
    public void setWantClientAuth(boolean wanted) {}

    @Override
    public SSLSession getSession() {
      return null;
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer source, ByteBuffer destination) throws SSLException {
      return null;
    }

    @Override
    public SSLEngineResult unwrap(
        ByteBuffer source, ByteBuffer[] destinations, int offset, int length) throws SSLException {
      return null;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer source, ByteBuffer destination) throws SSLException {
      return null;
    }

    @Override
    public SSLEngineResult wrap(
        ByteBuffer[] sources, int offset, int length, ByteBuffer destination) throws SSLException {
      return null;
    }
  }
}
