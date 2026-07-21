/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReferenceArray;

final class WeakIdentityTaskMap {
  private static final TaskContext AMBIGUOUS_CONTEXT = new TaskContext(-1L, 0L);
  private static final int MAX_STRIPES = 64;

  private final Bucket[] buckets;
  private final AtomicReferenceArray<Entry> ring;
  private final AtomicLong index = new AtomicLong();
  private final ReferenceQueue<Object> staleTasks = new ReferenceQueue<>();
  private final int maxCancellationTraversal;

  WeakIdentityTaskMap(int capacity) {
    if (capacity <= 0) {
      throw new IllegalArgumentException("capacity must be > 0");
    }

    ring = new AtomicReferenceArray<>(capacity);
    maxCancellationTraversal = capacity;
    int stripeCount = 1;
    int requestedStripes = Math.min(capacity, MAX_STRIPES);
    while (stripeCount < requestedStripes) {
      stripeCount <<= 1;
    }
    buckets = new Bucket[stripeCount];
    for (int i = 0; i < stripeCount; i++) {
      buckets[i] = new Bucket();
    }
  }

  void track(Object task, TaskContext context) {
    track(task, context, System.identityHashCode(task));
  }

  void untrack(Object task) {
    remove(task, System.identityHashCode(task));
  }

  void trackCancellationOwner(Object task, Object owner) {
    if (task == owner) {
      return;
    }

    drainStaleTasks();
    int identityHash = System.identityHashCode(task);
    Bucket bucket = bucket(identityHash);
    boolean found = false;
    boolean ambiguous = false;
    Entry added = null;
    synchronized (bucket) {
      for (Entry entry : bucket.entries) {
        if (entry.get() == task) {
          found = true;
          Object previous = entry.cancellationOwner == null ? null : entry.cancellationOwner.get();
          if (previous != null && previous != owner) {
            ambiguous = true;
          } else {
            entry.cancellationOwner = new WeakReference<>(owner);
          }
          break;
        }
      }
      if (!found) {
        added = new Entry(task, identityHash, null, staleTasks);
        added.cancellationOwner = new WeakReference<>(owner);
        bucket.entries.add(added);
      }
    }

    if (ambiguous) {
      remove(task, identityHash);
      remove(owner, System.identityHashCode(owner));
      return;
    }
    if (added != null) {
      publish(added);
    }
  }

  TaskContext get(Object task) {
    return get(task, System.identityHashCode(task), false);
  }

  TaskContext take(Object task) {
    return get(task, System.identityHashCode(task), true);
  }

  boolean transfer(Object source, Object target) {
    if (source == target) {
      return get(source) != null;
    }

    TaskContext context = take(source);
    if (context == null) {
      return false;
    }
    track(target, context);
    return true;
  }

  void track(Object task, TaskContext context, int identityHash) {
    drainStaleTasks();
    Bucket bucket = bucket(identityHash);
    Entry added = null;
    boolean duplicate = false;
    ArrayList<Object> staleOwners = new ArrayList<>();
    synchronized (bucket) {
      for (Iterator<Entry> iterator = bucket.entries.iterator(); iterator.hasNext(); ) {
        Entry entry = iterator.next();
        Object existing = entry.get();
        if (existing == null) {
          iterator.remove();
          ThreadInfo.cancelTaskContext(entry.context);
          addCancellationOwner(staleOwners, entry);
          entry.context = null;
          entry.clear();
        } else if (existing == task) {
          TaskContext previous = entry.context;
          if (previous == null && entry.cancellationOwner != null) {
            entry.context = context;
            duplicate = true;
            break;
          }
          if (previous != AMBIGUOUS_CONTEXT && previous != context) {
            ThreadInfo.cancelTaskContext(previous);
            entry.context = AMBIGUOUS_CONTEXT;
          }
          ThreadInfo.cancelTaskContext(context);
          duplicate = true;
          break;
        }
      }

      if (!duplicate) {
        added = new Entry(task, identityHash, context, staleTasks);
        bucket.entries.add(added);
      }
    }
    removeCancellationOwners(staleOwners);
    if (duplicate) {
      return;
    }

    publish(added);
  }

  TaskContext get(Object task, int identityHash, boolean remove) {
    drainStaleTasks();
    Bucket bucket = bucket(identityHash);
    TaskContext found = null;
    Object cancellationOwner = null;
    ArrayList<Object> staleOwners = new ArrayList<>();
    synchronized (bucket) {
      for (Iterator<Entry> iterator = bucket.entries.iterator(); iterator.hasNext(); ) {
        Entry entry = iterator.next();
        Object existing = entry.get();
        if (existing == null) {
          iterator.remove();
          ThreadInfo.cancelTaskContext(entry.context);
          addCancellationOwner(staleOwners, entry);
          entry.context = null;
          entry.clear();
          continue;
        }
        if (entry.identityHash != identityHash || existing != task) {
          continue;
        }

        TaskContext context = entry.context;
        if (remove) {
          iterator.remove();
          cancellationOwner = cancellationOwner(entry);
          entry.context = null;
          entry.clear();
        }
        found = context == AMBIGUOUS_CONTEXT ? null : context;
        break;
      }
    }
    removeCancellationOwners(staleOwners);
    removeCancellationOwner(task, cancellationOwner);
    return found;
  }

  void remove(Object task, int identityHash) {
    drainStaleTasks();
    ArrayList<Object> cancellationOwners = new ArrayList<>();
    removeDirect(task, identityHash, cancellationOwners);
    removeCancellationOwners(cancellationOwners);
  }

  private void removeDirect(Object task, int identityHash, ArrayList<Object> cancellationOwners) {
    Bucket bucket = bucket(identityHash);
    synchronized (bucket) {
      for (Iterator<Entry> iterator = bucket.entries.iterator(); iterator.hasNext(); ) {
        Entry entry = iterator.next();
        Object existing = entry.get();
        if (existing == null || (entry.identityHash == identityHash && existing == task)) {
          iterator.remove();
          ThreadInfo.cancelTaskContext(entry.context);
          addCancellationOwner(cancellationOwners, entry);
          entry.context = null;
          entry.clear();
        }
      }
    }
  }

  void clearTaskReferenceForTest(Object task, int identityHash) {
    Bucket bucket = bucket(identityHash);
    synchronized (bucket) {
      for (Entry entry : bucket.entries) {
        if (entry.identityHash == identityHash && entry.get() == task) {
          entry.clear();
          return;
        }
      }
    }
  }

  private Bucket bucket(int identityHash) {
    return buckets[identityHash & (buckets.length - 1)];
  }

  private void drainStaleTasks() {
    Entry stale;
    while ((stale = (Entry) staleTasks.poll()) != null) {
      remove(stale);
    }
  }

  private void remove(Entry entry) {
    Bucket bucket = bucket(entry.identityHash);
    Object task = entry.get();
    Object cancellationOwner = null;
    synchronized (bucket) {
      if (bucket.entries.remove(entry)) {
        ThreadInfo.cancelTaskContext(entry.context);
        cancellationOwner = cancellationOwner(entry);
        entry.context = null;
        entry.clear();
      }
    }
    removeCancellationOwner(task, cancellationOwner);
  }

  private static void addCancellationOwner(ArrayList<Object> owners, Entry entry) {
    Object owner = cancellationOwner(entry);
    if (owner != null) {
      owners.add(owner);
    }
  }

  private static Object cancellationOwner(Entry entry) {
    WeakReference<Object> owner = entry.cancellationOwner;
    entry.cancellationOwner = null;
    return owner == null ? null : owner.get();
  }

  private void removeCancellationOwners(ArrayList<Object> owners) {
    if (owners.isEmpty()) {
      return;
    }

    ArrayDeque<Object> pending = new ArrayDeque<>(owners);
    IdentityHashMap<Object, Boolean> visited = new IdentityHashMap<>();
    int traversed = 0;
    while (!pending.isEmpty() && traversed < maxCancellationTraversal) {
      Object owner = pending.removeFirst();
      if (visited.put(owner, Boolean.TRUE) != null) {
        continue;
      }
      traversed++;

      ArrayList<Object> discovered = new ArrayList<>();
      removeDirect(owner, System.identityHashCode(owner), discovered);
      for (Object next : discovered) {
        if (!visited.containsKey(next)) {
          pending.addLast(next);
        }
      }
    }
  }

  private void removeCancellationOwner(Object task, Object owner) {
    if (owner != null && owner != task) {
      ArrayList<Object> owners = new ArrayList<>(1);
      owners.add(owner);
      removeCancellationOwners(owners);
    }
  }

  private void publish(Entry added) {
    long current = index.getAndIncrement();
    int slot = (int) floorMod(current, ring.length());
    Entry evicted = ring.getAndSet(slot, added);
    if (evicted != null) {
      remove(evicted);
    }
  }

  private static long floorMod(long value, int divisor) {
    long remainder = value % divisor;
    return remainder < 0 ? remainder + divisor : remainder;
  }

  private static final class Bucket {
    private final ArrayList<Entry> entries = new ArrayList<>();

    Bucket() {}
  }

  private static final class Entry extends WeakReference<Object> {
    private final int identityHash;
    private TaskContext context;
    private WeakReference<Object> cancellationOwner;

    Entry(Object task, int identityHash, TaskContext context, ReferenceQueue<Object> staleTasks) {
      super(task, staleTasks);
      this.identityHash = identityHash;
      this.context = context;
    }
  }
}
