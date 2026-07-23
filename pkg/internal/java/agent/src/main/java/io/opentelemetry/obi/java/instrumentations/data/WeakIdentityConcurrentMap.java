/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.concurrent.ConcurrentHashMap;

final class WeakIdentityConcurrentMap<V> {
  private final ConcurrentHashMap<IdentityWeakReference, V> map = new ConcurrentHashMap<>();
  private final ReferenceQueue<Object> staleKeys = new ReferenceQueue<>();
  private final Object insertionLock = new Object();
  private final int capacity;

  WeakIdentityConcurrentMap(int capacity) {
    if (capacity <= 0) {
      throw new IllegalArgumentException("capacity must be > 0");
    }
    this.capacity = capacity;
  }

  V get(Object key) {
    if (key == null) {
      return null;
    }
    drainStaleKeys();
    return map.get(new IdentityWeakReference(key));
  }

  boolean putIfAbsent(Object key, V value) {
    if (key == null || value == null) {
      return false;
    }

    synchronized (insertionLock) {
      drainStaleKeys();
      IdentityWeakReference lookup = new IdentityWeakReference(key);
      if (map.containsKey(lookup) || map.size() >= capacity) {
        return false;
      }
      return map.putIfAbsent(new IdentityWeakReference(key, staleKeys), value) == null;
    }
  }

  V put(Object key, V value) {
    if (key == null || value == null) {
      return null;
    }

    synchronized (insertionLock) {
      drainStaleKeys();
      IdentityWeakReference lookup = new IdentityWeakReference(key);
      if (!map.containsKey(lookup) && map.size() >= capacity) {
        return null;
      }
      return map.put(new IdentityWeakReference(key, staleKeys), value);
    }
  }

  boolean replace(Object key, V expected, V replacement) {
    if (key == null || expected == null || replacement == null) {
      return false;
    }
    drainStaleKeys();
    return map.replace(new IdentityWeakReference(key), expected, replacement);
  }

  boolean remove(Object key, V expected) {
    if (key == null || expected == null) {
      return false;
    }
    drainStaleKeys();
    return map.remove(new IdentityWeakReference(key), expected);
  }

  V remove(Object key) {
    if (key == null) {
      return null;
    }
    drainStaleKeys();
    return map.remove(new IdentityWeakReference(key));
  }

  int size() {
    drainStaleKeys();
    return map.size();
  }

  void clearReferenceForTest(Object key) {
    for (IdentityWeakReference reference : map.keySet()) {
      if (reference.get() == key) {
        reference.clear();
        reference.enqueue();
        break;
      }
    }
    drainStaleKeys();
  }

  private void drainStaleKeys() {
    IdentityWeakReference stale;
    while ((stale = (IdentityWeakReference) staleKeys.poll()) != null) {
      map.remove(stale);
    }
  }

  static final class IdentityWeakReference extends WeakReference<Object> {
    private final int identityHash;

    IdentityWeakReference(Object referent) {
      super(referent);
      identityHash = System.identityHashCode(referent);
    }

    IdentityWeakReference(Object referent, ReferenceQueue<Object> queue) {
      super(referent, queue);
      identityHash = System.identityHashCode(referent);
    }

    @Override
    public int hashCode() {
      return identityHash;
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
}
