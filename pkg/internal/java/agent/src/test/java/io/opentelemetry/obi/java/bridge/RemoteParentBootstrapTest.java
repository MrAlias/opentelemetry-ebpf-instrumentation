/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.bridge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class RemoteParentBootstrapTest {
  @AfterEach
  void reset() throws Exception {
    RemoteParentBootstrap.cancelInstrumentationInstallation();
    setInstalledProvider(null);
    RemoteParentBridge.resetForTest();
  }

  @Test
  void failedInstallationClosesItsProviderAndCanBeRetried() throws Exception {
    FakeProvider provider = new FakeProvider();
    assertTrue(RemoteParentBootstrap.beginInstrumentationInstallation());
    assertTrue(RemoteParentBridge.installProviderForTest(provider));
    setInstalledProvider(provider);

    RemoteParentBootstrap.cancelInstrumentationInstallation();

    assertTrue(provider.closed.get());
    assertFalse(RemoteParentBootstrap.instrumentationInstallationClaimed());
    assertTrue(RemoteParentBootstrap.beginInstrumentationInstallation());
  }

  @Test
  void providerTeardownAdvancesTheCapabilityEpochBeforeRemoval() throws Exception {
    FakeProvider provider = new FakeProvider();
    assertTrue(RemoteParentBootstrap.beginInstrumentationInstallation());
    assertTrue(RemoteParentBridge.installProviderForTest(provider));
    setInstalledProvider(provider);
    long installedEpoch = ThreadInfo.remoteParentBridgeEpoch();

    RemoteParentBootstrap.cancelInstrumentationInstallation();

    assertNotEquals(installedEpoch, ThreadInfo.remoteParentBridgeEpoch());
    assertTrue(provider.closed.get());
  }

  private static void setInstalledProvider(RemoteParentProvider provider) throws Exception {
    Field installed = RemoteParentBootstrap.class.getDeclaredField("installed");
    installed.setAccessible(true);
    installed.set(null, provider);
  }

  private static final class FakeProvider implements RemoteParentProvider {
    private final AtomicBoolean closed = new AtomicBoolean();

    @Override
    public int abiVersion() {
      return RemoteParentRecord.ABI_VERSION;
    }

    @Override
    public RemoteParentRecord takeRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public RemoteParentRecord discardRemoteParent() {
      return RemoteParentRecord.statusOnly(RemoteParentStatus.MISSING);
    }

    @Override
    public void close() {
      closed.set(true);
    }
  }
}
