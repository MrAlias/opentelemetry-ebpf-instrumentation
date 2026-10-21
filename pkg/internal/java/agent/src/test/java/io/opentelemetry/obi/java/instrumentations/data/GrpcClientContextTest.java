/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.*;

import io.grpc.Metadata;
import io.grpc.netty.shaded.io.netty.util.AsciiString;
import io.opentelemetry.obi.java.ebpf.NativeMemory;
import io.opentelemetry.obi.java.ebpf.OperationType;
import io.opentelemetry.obi.java.instrumentations.util.CappedConcurrentHashMap;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

class GrpcClientContextTest {
  private static final Metadata.Key<String> TP =
      Metadata.Key.of("traceparent", Metadata.ASCII_STRING_MARSHALLER);

  @Test
  void tracksGrpcImmutableOutboundHeadersByIdentity() throws Exception {
    Class<?> type = Class.forName("io.grpc.netty.shaded.io.grpc.netty.GrpcHttp2OutboundHeaders");
    Method factory =
        type.getDeclaredMethod(
            "clientRequestHeaders",
            byte[][].class,
            AsciiString.class,
            AsciiString.class,
            AsciiString.class,
            AsciiString.class,
            AsciiString.class);
    factory.setAccessible(true);
    String value = "00-33333333333333333333333333333333-4444444444444444-01";
    Object[] fields = {
      new byte[][] {
        "traceparent".getBytes(StandardCharsets.US_ASCII), value.getBytes(StandardCharsets.US_ASCII)
      },
      new AsciiString("localhost"),
      new AsciiString("/fixture.Receiver/Call"),
      new AsciiString("POST"),
      new AsciiString("https"),
      new AsciiString("grpc-java/1.84.0")
    };
    Object headers = factory.invoke(null, fields);
    Object sameFields = factory.invoke(null, fields);
    GrpcClientContext previous = GrpcClientContext.enter();
    try {
      Metadata metadata = new Metadata();
      metadata.put(TP, value);
      register(metadata, 3);
      GrpcClientContext call = GrpcClientContext.prepare(metadata);
      assertNotNull(call);
      GrpcClientContext.bind(headers, call);
      assertNull(GrpcClientContext.take(sameFields));
      assertSame(call, GrpcClientContext.take(headers));
      assertNull(GrpcClientContext.take(headers));
      assertEquals(value, metadata.get(TP));
      GrpcClientContext.bind(headers, call);
    } finally {
      GrpcClientContext.exit(previous);
    }
    assertNull(GrpcClientContext.take(headers));
  }

  @Test
  void requiresAnAcknowledgedCompleteContext() {
    NativeMemory reply = new NativeMemory(49, true);
    byte[] context = new byte[48];
    context[15] = 1;
    context[23] = 2;
    reply.write(1, context, 0, context.length);
    reply.setByte(0, OperationType.GRPC_CONTEXT.code);
    assertNull(GrpcClientContext.readContext(reply));
    reply.setByte(0, (byte) 0);
    assertArrayEquals(context, GrpcClientContext.readContext(reply));
    reply.setByte(24, (byte) 0);
    assertNull(GrpcClientContext.readContext(reply));
    reply.setByte(24, (byte) 2);
    reply.setByte(16, (byte) 0);
    assertNull(GrpcClientContext.readContext(reply));
  }

  @Test
  void preservesApplicationOwnershipIncludingInvalidAndEmptyValues() throws Exception {
    for (String supplied :
        new String[] {
          "application-owned-invalid", "", "00-33333333333333333333333333333333-4444444444444444-01"
        }) {
      Metadata headers = new Metadata();
      headers.put(TP, supplied);
      GrpcClientContext previous = GrpcClientContext.enter();
      try {
        register(headers, 1);
        GrpcClientContext.prepare(headers);
        assertEquals(java.util.Collections.singletonList(supplied), values(headers));
      } finally {
        GrpcClientContext.exit(previous);
      }
    }
    assertInjected(new Metadata(), 2);
  }

  @Test
  void carriesOwnershipAcrossGrpcRetryHeaderCopy() throws Exception {
    GrpcClientContext previous = GrpcClientContext.enter();
    try {
      Metadata original = new Metadata();
      register(original, 3);
      Metadata copy = new Metadata();
      copy.merge(original);
      GrpcClientContext.copy(original, copy);
      GrpcClientContext.prepare(copy);
      assertNotNull(copy.get(TP));
      assertNull(original.get(TP));
    } finally {
      GrpcClientContext.exit(previous);
    }
  }

  @Test
  void eachConcurrentCallOwnsItsMetadata() throws Exception {
    ExecutorService pool = Executors.newFixedThreadPool(8);
    try {
      List<Future<String>> results = new ArrayList<>();
      for (int i = 1; i <= 32; i++) {
        final int id = i;
        results.add(pool.submit(() -> assertInjected(new Metadata(), id)));
      }
      java.util.Set<String> unique = new java.util.HashSet<>();
      for (Future<String> result : results) {
        assertTrue(unique.add(result.get(10, TimeUnit.SECONDS)));
      }
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void failedCallReleasesMetadataAndRestoresOuterScope() throws Exception {
    GrpcClientContext previous = GrpcClientContext.enter();
    Metadata outer = new Metadata();
    try {
      register(outer, 1);
      GrpcClientContext nested = GrpcClientContext.enter();
      Metadata cancelled = new Metadata();
      register(cancelled, 2);
      Metadata cancelledCopy = new Metadata();
      GrpcClientContext.copy(cancelled, cancelledCopy);
      GrpcClientContext.exit(nested);
      GrpcClientContext.prepare(cancelledCopy);
      assertNull(cancelledCopy.get(TP));
      GrpcClientContext.prepare(cancelled);
      assertNull(cancelled.get(TP));
      GrpcClientContext.prepare(outer);
      assertEquals(1, values(outer).size());
    } finally {
      GrpcClientContext.exit(previous);
    }
    Metadata unrelated = new Metadata();
    GrpcClientContext.prepare(unrelated);
    assertNull(unrelated.get(TP));
  }

  private static String assertInjected(Metadata headers, int id) throws Exception {
    GrpcClientContext previous = GrpcClientContext.enter();
    try {
      register(headers, id);
      GrpcClientContext.prepare(headers);
      GrpcClientContext.prepare(headers);
      assertEquals(1, values(headers).size());
      String value = headers.get(TP);
      assertEquals(String.format("00-%032x-%016x-01", id, id), value);
      return value;
    } finally {
      GrpcClientContext.exit(previous);
    }
  }

  private static List<String> values(Metadata headers) {
    List<String> result = new ArrayList<>();
    headers.getAll(TP).forEach(result::add);
    return result;
  }

  @SuppressWarnings("unchecked")
  private static void register(Metadata headers, int id) throws Exception {
    Field current = GrpcClientContext.class.getDeclaredField("current");
    current.setAccessible(true);
    GrpcClientContext call = ((ThreadLocal<GrpcClientContext>) current.get(null)).get();
    byte[] context = new byte[48];
    context[15] = (byte) id;
    context[23] = (byte) id;
    context[40] = 1;
    Field bytes = GrpcClientContext.class.getDeclaredField("context");
    bytes.setAccessible(true);
    bytes.set(call, context);
    Field metadata = GrpcClientContext.class.getDeclaredField("metadata");
    metadata.setAccessible(true);
    metadata.set(call, headers);
    Field calls = GrpcClientContext.class.getDeclaredField("calls");
    calls.setAccessible(true);
    ((CappedConcurrentHashMap<Object, GrpcClientContext>) calls.get(null)).put(headers, call);
  }
}
