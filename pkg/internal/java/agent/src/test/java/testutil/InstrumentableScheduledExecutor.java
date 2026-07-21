/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package testutil;

import java.util.concurrent.Delayed;
import java.util.concurrent.Future;
import java.util.concurrent.RunnableScheduledFuture;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Test executor outside the agent's instrumentation ignore namespace. */
public final class InstrumentableScheduledExecutor extends ScheduledThreadPoolExecutor {
  private final boolean wrapTasks;

  public InstrumentableScheduledExecutor(boolean wrapTasks) {
    super(1);
    this.wrapTasks = wrapTasks;
  }

  @Override
  public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
    return super.schedule(command, delay, unit);
  }

  @Override
  protected void beforeExecute(Thread thread, Runnable task) {
    super.beforeExecute(thread, task);
  }

  @Override
  protected void afterExecute(Runnable task, Throwable failure) {
    super.afterExecute(task, failure);
  }

  @Override
  protected <V> RunnableScheduledFuture<V> decorateTask(
      Runnable runnable, RunnableScheduledFuture<V> task) {
    RunnableScheduledFuture<V> decorated = super.decorateTask(runnable, task);
    return wrapTasks ? new DelegatingScheduledFuture<>(decorated) : decorated;
  }

  public static Future<?> delegate(Future<?> future) {
    return ((DelegatingScheduledFuture<?>) future).delegate;
  }

  private static final class DelegatingScheduledFuture<V> implements RunnableScheduledFuture<V> {
    private final RunnableScheduledFuture<V> delegate;

    private DelegatingScheduledFuture(RunnableScheduledFuture<V> delegate) {
      this.delegate = delegate;
    }

    @Override
    public boolean isPeriodic() {
      return delegate.isPeriodic();
    }

    @Override
    public long getDelay(TimeUnit unit) {
      return delegate.getDelay(unit);
    }

    @Override
    public int compareTo(Delayed other) {
      return delegate.compareTo(other);
    }

    @Override
    public void run() {
      delegate.run();
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
      return delegate.cancel(mayInterruptIfRunning);
    }

    @Override
    public boolean isCancelled() {
      return delegate.isCancelled();
    }

    @Override
    public boolean isDone() {
      return delegate.isDone();
    }

    @Override
    public V get() throws java.util.concurrent.ExecutionException, InterruptedException {
      return delegate.get();
    }

    @Override
    public V get(long timeout, TimeUnit unit)
        throws java.util.concurrent.ExecutionException,
            InterruptedException,
            java.util.concurrent.TimeoutException {
      return delegate.get(timeout, unit);
    }
  }
}
