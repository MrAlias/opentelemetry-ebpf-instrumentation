/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

public enum OperationType {
  SEND((byte) 1),
  RECEIVE((byte) 2),
  THREAD((byte) 3),
  // virtual thread mounted on the calling carrier; payload = its logical id
  VT_MOUNT((byte) 4),
  // virtual thread unmounted from the calling carrier; payload unused
  VT_UNMOUNT((byte) 5),
  // capture the calling task's exact remote-parent generation under an opaque token
  TASK_CAPTURE((byte) 6),
  // discard an unused submission-time handoff token
  TASK_CANCEL((byte) 7),
  // link a worker through a captured token; token zero is fail-closed
  TASK_LINK((byte) 8),
  // snapshot only the calling worker's existing exact task relay under a new token
  TASK_RELAY_CAPTURE((byte) 9),
  // register a nonzero token that distinguishes this JVM from later PID reuse
  PROCESS_REGISTER((byte) 10),
  // the full-width virtual-thread id has permanently completed
  VT_TERMINATE((byte) 11),
  // fail closed by removing the calling logical task's inherited context
  TASK_UNLINK((byte) 12),
  // identify a correlated live socket as TLS before application data arrives
  TLS_CONNECTION((byte) 13),
  // start one exact HTTP/1 receive sequence with its first nonempty plaintext fragment
  HTTP1_RECEIVE_START((byte) 14),
  // append a nonempty plaintext fragment to an exact HTTP/1 receive sequence
  HTTP1_RECEIVE_CONTINUE((byte) 15),
  // discard an exact HTTP/1 receive sequence without a payload
  HTTP1_RECEIVE_RESET((byte) 16),
  // preserve generic receive telemetry without staging remote-parent authority
  TELEMETRY_RECEIVE((byte) 17);

  public final byte code;

  OperationType(byte code) {
    this.code = code;
  }
}
