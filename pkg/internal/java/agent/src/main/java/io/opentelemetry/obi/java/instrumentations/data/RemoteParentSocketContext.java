/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import java.lang.ref.WeakReference;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** One-shot accepted-socket ownership shared by an exact task handoff. */
public final class RemoteParentSocketContext {
  private final AtomicInteger socketFileDescriptor;
  private final Lifecycle lifecycle;

  public RemoteParentSocketContext(int socketFileDescriptor) {
    this(socketFileDescriptor, null);
  }

  public RemoteParentSocketContext(int socketFileDescriptor, Lifecycle lifecycle) {
    if (socketFileDescriptor < 0) {
      throw new IllegalArgumentException("socket file descriptor must be non-negative");
    }
    this.socketFileDescriptor = new AtomicInteger(socketFileDescriptor);
    this.lifecycle = lifecycle;
  }

  public int peek() {
    return active() ? socketFileDescriptor.get() : -1;
  }

  public int take() {
    Lookup lookup = takeForRemoteParentLookup();
    if (lookup == null) {
      return -1;
    }
    try {
      return lookup.socketFileDescriptor();
    } finally {
      lookup.close();
    }
  }

  /**
   * Atomically consumes this context and retains its live owner until the native lookup finishes.
   *
   * <p>A lifecycle lease closes the interval between the final liveness check and the native
   * descriptor use. The lease also holds a temporary strong reference to the physical transport
   * owner, preventing a weak-map cleanup from closing and reusing its descriptor during the lookup.
   */
  public Lookup takeForRemoteParentLookup() {
    Lifecycle.Lease lease = lifecycle == null ? null : lifecycle.acquireLookupLease();
    if (lifecycle != null && lease == null) {
      socketFileDescriptor.getAndSet(-1);
      return null;
    }

    int socketFileDescriptor = this.socketFileDescriptor.getAndSet(-1);
    if (socketFileDescriptor < 0) {
      if (lease != null) {
        lease.close();
      }
      return null;
    }
    return new Lookup(socketFileDescriptor, lease);
  }

  /** Consumes this one-shot descriptor without performing a native lookup. */
  public void discard() {
    socketFileDescriptor.getAndSet(-1);
  }

  public boolean hasLifecycle(Object candidate) {
    return lifecycle != null && lifecycle == candidate;
  }

  /** Returns the physical lifecycle fence independently of the one-shot descriptor. */
  public Lifecycle lifecycle() {
    return lifecycle;
  }

  private boolean active() {
    return lifecycle == null || lifecycle.active();
  }

  /** A consumed descriptor together with its close fence. */
  public static final class Lookup implements AutoCloseable {
    private final int socketFileDescriptor;
    private Lifecycle.Lease lease;

    Lookup(int socketFileDescriptor, Lifecycle.Lease lease) {
      this.socketFileDescriptor = socketFileDescriptor;
      this.lease = lease;
    }

    public int socketFileDescriptor() {
      return socketFileDescriptor;
    }

    @Override
    public synchronized void close() {
      Lifecycle.Lease current = lease;
      lease = null;
      if (current != null) {
        current.close();
      }
    }
  }

  /** Shared, invalidatable ownership generation for one live socket or connection. */
  public static final class Lifecycle {
    private static final AtomicLong nextLifecycleId = new AtomicLong(initialLifecycleId());

    private final Object lifecycleLock = new Object();
    private final AtomicInteger closeReferences;
    private final long id;
    private final WeakReference<?> owner;
    private final boolean ownerRequired;
    private final ActiveCheck activity;
    private boolean terminal;
    private boolean closePending;
    private int closeFences;
    private int lookupLeases;

    public Lifecycle() {
      this(null, false, false, null);
    }

    Lifecycle(Socket socket) {
      this(socket == null ? null : new WeakReference<Socket>(socket), socket != null, false, null);
    }

    Lifecycle(WeakReference<Socket> socketOwner) {
      this(socketOwner, true, false, null);
    }

    Lifecycle(ActiveCheck activity) {
      this(null, false, false, activity);
    }

    Lifecycle(Object owner, ActiveCheck activity) {
      this(owner == null ? null : new WeakReference<Object>(owner), owner != null, false, activity);
    }

    Lifecycle(WeakReference<?> owner, ActiveCheck activity) {
      this(owner, owner != null, false, activity);
    }

    private Lifecycle(
        WeakReference<?> owner,
        boolean ownerRequired,
        boolean closeTombstone,
        ActiveCheck activity) {
      this.owner = owner;
      this.ownerRequired = ownerRequired;
      this.activity = activity;
      this.id = newLifecycleId();
      closeReferences = new AtomicInteger(closeTombstone ? 1 : 0);
      terminal = closeTombstone;
    }

    /** Process-local nonzero identity used to fence native request cursors. */
    public long id() {
      return id;
    }

    public static Lifecycle newCloseTombstone() {
      return new Lifecycle(null, false, true, null);
    }

    public boolean active() {
      synchronized (lifecycleLock) {
        return activeLocked();
      }
    }

    /**
     * Prevents future leases, then waits for every already-acquired lookup before returning.
     *
     * <p>The wait is deliberately uninterruptible: returning before an in-flight native call
     * completes would permit numeric descriptor reuse to select a different connection.
     */
    public void invalidate() {
      boolean interrupted = false;
      synchronized (lifecycleLock) {
        terminal = true;
        while (lookupLeases > 0) {
          try {
            lifecycleLock.wait();
          } catch (InterruptedException ignored) {
            interrupted = true;
          }
        }
        lifecycleLock.notifyAll();
      }
      if (interrupted) {
        Thread.currentThread().interrupt();
      }
    }

    /**
     * Temporarily blocks new native operations while a close whose terminal result is not yet known
     * runs. Callers may release a {@code false} result only when they have independently proven
     * that the physical transport remains usable; JDK {@code SocketChannelImpl.tryClose()} does not
     * meet that condition because its {@code false} result defers physical closure.
     */
    public CloseFence beginCloseFence() {
      boolean interrupted = false;
      CloseFence fence = null;
      synchronized (lifecycleLock) {
        if (terminal || !ownerActiveLocked()) {
          // Another invalidator may already have made this generation terminal but still be
          // waiting for an in-flight native call. A close that reached the underlying channel
          // before that call completes could reuse the descriptor, so it must wait as well.
          while (lookupLeases > 0) {
            try {
              lifecycleLock.wait();
            } catch (InterruptedException ignored) {
              interrupted = true;
            }
          }
        } else {
          closePending = true;
          closeFences++;
          while (lookupLeases > 0) {
            try {
              lifecycleLock.wait();
            } catch (InterruptedException ignored) {
              interrupted = true;
            }
          }
          fence = new CloseFence(this);
        }
      }
      if (interrupted) {
        Thread.currentThread().interrupt();
      }
      return fence;
    }

    /** Acquires a close fence for one native operation while this generation remains live. */
    public Lease acquireLookupLease() {
      synchronized (lifecycleLock) {
        if (!activeLocked()) {
          return null;
        }
        Object retainedOwner = owner == null ? null : owner.get();
        if (ownerRequired && !ownerActive(retainedOwner)) {
          return null;
        }
        lookupLeases++;
        return new Lease(this, retainedOwner);
      }
    }

    private boolean activeLocked() {
      if (terminal || closePending) {
        return false;
      }
      return ownerActiveLocked();
    }

    private boolean ownerActiveLocked() {
      if (activity != null && !activity.active()) {
        return false;
      }
      if (!ownerRequired) {
        return true;
      }
      return ownerActive(owner == null ? null : owner.get());
    }

    private static boolean ownerActive(Object owner) {
      if (owner == null) {
        return false;
      }
      try {
        if (owner instanceof Socket) {
          return !((Socket) owner).isClosed();
        }
        return true;
      } catch (Throwable ignored) {
        return false;
      }
    }

    void releaseLookupLease() {
      synchronized (lifecycleLock) {
        if (lookupLeases <= 0) {
          return;
        }
        lookupLeases--;
        if (lookupLeases == 0) {
          lifecycleLock.notifyAll();
        }
      }
    }

    void finishCloseFence(CloseFence fence, boolean terminalClose) {
      synchronized (lifecycleLock) {
        if (fence.lifecycle != this || fence.finished) {
          return;
        }
        fence.finished = true;
        if (terminalClose) {
          terminal = true;
        }
        if (closeFences > 0) {
          closeFences--;
        }
        if (closeFences == 0) {
          closePending = false;
        }
        lifecycleLock.notifyAll();
      }
    }

    public boolean isCloseTombstone() {
      return closeReferences.get() > 0;
    }

    public boolean retainCloseTombstoneIfOpen() {
      while (true) {
        int references = closeReferences.get();
        if (references <= 0) {
          return false;
        }
        if (closeReferences.compareAndSet(references, references + 1)) {
          return true;
        }
      }
    }

    public boolean releaseCloseTombstone() {
      while (true) {
        int references = closeReferences.get();
        if (references <= 0) {
          return false;
        }
        if (closeReferences.compareAndSet(references, references - 1)) {
          return references == 1;
        }
      }
    }

    /** A lease which retains the physical transport owner until its native operation completes. */
    public static final class Lease implements AutoCloseable {
      private Lifecycle lifecycle;

      @SuppressWarnings("unused")
      private Object owner;

      Lease(Lifecycle lifecycle, Object owner) {
        this.lifecycle = lifecycle;
        this.owner = owner;
      }

      Object retainedOwnerForTest() {
        return owner;
      }

      @Override
      public synchronized void close() {
        Lifecycle current = lifecycle;
        lifecycle = null;
        Object retainedOwner = owner;
        owner = null;
        if (current != null) {
          current.releaseLookupLease();
        }
        if (retainedOwner != null) {
          // Keep the owner strongly reachable until after the lifecycle release. The local is
          // deliberately retained through this point so a Cleaner cannot close its descriptor
          // before the native operation guarded by this lease has completed.
          retainedOwner.getClass();
        }
      }
    }

    /** A provisional gate used by close paths whose terminal outcome is known only at exit. */
    public static final class CloseFence {
      private final Lifecycle lifecycle;
      private boolean finished;

      CloseFence(Lifecycle lifecycle) {
        this.lifecycle = lifecycle;
      }

      public void finish(boolean terminalClose) {
        lifecycle.finishCloseFence(this, terminalClose);
      }
    }

    /** Allows connection-owned lifecycles to fail closed when their registry entry is evicted. */
    public interface ActiveCheck {
      boolean active();
    }

    private static long newLifecycleId() {
      long id;
      do {
        id = nextLifecycleId.getAndIncrement();
      } while (id == 0L);
      return id;
    }

    private static long initialLifecycleId() {
      long seed = System.nanoTime() ^ System.currentTimeMillis();
      seed ^= (long) System.identityHashCode(Lifecycle.class) << 32;
      return seed == 0L ? 1L : seed;
    }
  }

  /** Exact HTTP receive ownership carried from TLS plaintext to one extraction attempt. */
  public static final class ReceiveContext {
    private final Lifecycle lifecycle;
    private final long requestSequence;
    private final long bridgeEpoch;
    private final ExtractionObserver observer;

    ReceiveContext(
        Lifecycle lifecycle, long requestSequence, long bridgeEpoch, ExtractionObserver observer) {
      if (lifecycle == null || requestSequence <= 0L || bridgeEpoch == 0L || observer == null) {
        throw new IllegalArgumentException("incomplete receive context");
      }
      this.lifecycle = lifecycle;
      this.requestSequence = requestSequence;
      this.bridgeEpoch = bridgeEpoch;
      this.observer = observer;
    }

    public Lifecycle lifecycle() {
      return lifecycle;
    }

    public long requestSequence() {
      return requestSequence;
    }

    /** Process-wide bridge/provider epoch that issued this one-shot capability. */
    public long bridgeEpoch() {
      return bridgeEpoch;
    }

    public boolean extractionObserved() {
      return lifecycle.active() && observer.extractionObserved(this);
    }
  }

  interface ExtractionObserver {
    boolean extractionObserved(ReceiveContext context);
  }
}
