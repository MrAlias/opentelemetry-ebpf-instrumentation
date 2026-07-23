/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

class WeakIdentityConcurrentMapTest {
  @Test
  void equalBuffersRemainDistinctIdentityKeys() {
    WeakIdentityConcurrentMap<String> map = new WeakIdentityConcurrentMap<>(2);
    ByteBuffer first = ByteBuffer.wrap(new byte[] {1, 2, 3});
    ByteBuffer second = ByteBuffer.wrap(new byte[] {1, 2, 3});
    assertEquals(first, second);

    assertTrue(map.putIfAbsent(first, "first"));
    assertTrue(map.putIfAbsent(second, "second"));

    assertEquals("first", map.get(first));
    assertEquals("second", map.get(second));
    assertNull(map.get(first.duplicate()));
  }

  @Test
  void capacityRefusalIsAConservativeMissUntilAWeakKeyClears() {
    WeakIdentityConcurrentMap<String> map = new WeakIdentityConcurrentMap<>(1);
    Object first = new Object();
    Object second = new Object();

    assertTrue(map.putIfAbsent(first, "first"));
    assertEquals("first", map.get(first));
    assertFalse(map.putIfAbsent(second, "second"));
    assertNull(map.get(second));
    assertEquals(1, map.size());

    map.clearReferenceForTest(first);

    assertEquals(0, map.size());
    assertTrue(map.putIfAbsent(second, "second"));
    assertEquals("second", map.get(second));
  }

  @Test
  void putReplacesAnIdentityKeyWithoutOpeningCapacityForAnotherKey() {
    WeakIdentityConcurrentMap<String> map = new WeakIdentityConcurrentMap<>(1);
    Object first = new Object();
    Object second = new Object();

    assertNull(map.put(first, "first"));
    assertEquals("first", map.put(first, "replacement"));
    assertEquals("replacement", map.get(first));

    assertNull(map.put(second, "second"));
    assertNull(map.get(second));
    assertEquals("replacement", map.get(first));
  }

  @Test
  void conditionalOperationsUseTheCapturedValueGeneration() {
    WeakIdentityConcurrentMap<Object> map = new WeakIdentityConcurrentMap<>(1);
    Object key = new Object();
    Object first = new Object();
    Object second = new Object();

    assertTrue(map.putIfAbsent(key, first));
    assertFalse(map.replace(key, second, new Object()));
    assertTrue(map.replace(key, first, second));
    assertFalse(map.remove(key, first));
    assertTrue(map.remove(key, second));
    assertNull(map.get(key));
  }
}
