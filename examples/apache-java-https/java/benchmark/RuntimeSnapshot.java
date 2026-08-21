// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package io.opentelemetry.obi.examples.benchmark;

import com.sun.tools.attach.VirtualMachine;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.management.BufferPoolMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

/** Benchmark-only, low-cardinality JVM and JFR evidence helper. */
public final class RuntimeSnapshot {
  private static final long MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991L;
  private static final long HARD_MAX_JFR_BYTES = 33_554_432L;
  private static final long HARD_MAX_JFR_RECORDS = 600_000L;
  private static final Path PRIVATE_TMP_ROOT = Path.of("/tmp");
  private static final Path BOOTSTRAP_JFR = Path.of("/tmp/obi-benchmark-bootstrap.jfr");
  private static final Path MEASUREMENT_JFR = Path.of("/tmp/obi-benchmark-measurement.jfr");
  private RuntimeSnapshot() {}

  public static void main(String[] args) throws Exception {
    if (args.length == 2 && args[0].equals("runtime-snapshot")) {
      printRuntimeSnapshot(parsePositiveSafeLong(args[1], "target pid"));
      return;
    }
    if (args.length == 4 && args[0].equals("jfr-snapshot")) {
      printJfrSummary(
          Path.of(args[1]),
          parsePositiveCappedLong(args[2], "maximum JFR bytes", HARD_MAX_JFR_BYTES),
          parsePositiveCappedLong(args[3], "maximum JFR records", HARD_MAX_JFR_RECORDS));
      return;
    }
    if (args.length == 2 && args[0].equals("discard-bootstrap-jfr")) {
      discardBootstrapJfr(
          parsePositiveCappedLong(args[1], "maximum JFR bytes", HARD_MAX_JFR_BYTES));
      return;
    }
    throw new IllegalArgumentException(
        "usage: runtime-snapshot PID | jfr-snapshot FILE MAX_BYTES MAX_RECORDS | "
            + "discard-bootstrap-jfr MAX_BYTES");
  }

  private static void printRuntimeSnapshot(long targetPid) throws Exception {
    String connectorAddress;
    VirtualMachine target = VirtualMachine.attach(Long.toString(targetPid));
    try {
      connectorAddress = target.startLocalManagementAgent();
    } finally {
      target.detach();
    }
    if (connectorAddress == null || connectorAddress.isEmpty()) {
      throw new IllegalStateException("target JVM did not expose a local management connector");
    }

    try (JMXConnector connector =
        JMXConnectorFactory.connect(new JMXServiceURL(connectorAddress))) {
      MBeanServerConnection connection = connector.getMBeanServerConnection();
      RuntimeMXBean runtime =
          ManagementFactory.newPlatformMXBeanProxy(
              connection, ManagementFactory.RUNTIME_MXBEAN_NAME, RuntimeMXBean.class);
      long runtimePid = requirePositiveSafe(runtime.getPid(), "runtime pid");
      long startEpochMillis =
          requirePositiveSafe(runtime.getStartTime(), "JVM start epoch millis");
      if (runtimePid != targetPid) {
        throw new IllegalStateException("attached runtime pid does not match requested target");
      }

      List<BufferPoolMXBean> pools =
          ManagementFactory.getPlatformMXBeans(connection, BufferPoolMXBean.class);
      BufferPoolMXBean direct = null;
      for (BufferPoolMXBean pool : pools) {
        if (pool.getName().equals("direct")) {
          if (direct != null) {
            throw new IllegalStateException("duplicate direct buffer pool");
          }
          direct = pool;
        }
      }
      if (direct == null) {
        throw new IllegalStateException("direct buffer pool is unavailable");
      }
      long count = requireNonNegativeSafe(direct.getCount(), "direct buffer count");
      long memoryUsed =
          requireNonNegativeSafe(direct.getMemoryUsed(), "direct buffer memory used");
      long totalCapacity =
          requireNonNegativeSafe(direct.getTotalCapacity(), "direct buffer total capacity");

      System.out.printf(
          "{\"schema_version\":1,\"target_pid\":%d,\"runtime_pid\":%d,"
              + "\"jvm_start_epoch_millis\":%d,\"direct_buffer\":{\"count\":%d,"
              + "\"memory_used_bytes\":%d,\"total_capacity_bytes\":%d}}%n",
          targetPid, runtimePid, startEpochMillis, count, memoryUsed, totalCapacity);
    }
  }

  private static void printJfrSummary(
      Path recording,
      long maximumBytes,
      long maximumRecords)
      throws IOException {
    if (!recording.toAbsolutePath().normalize().equals(MEASUREMENT_JFR)) {
      throw new IllegalArgumentException("recording path is not the fixed measurement JFR path");
    }

    long totalRecords = 0;
    long allocationRecords = 0;
    long allocationWeightBytes = 0;
    long monitorEnterRecords = 0;
    long monitorEnterDurationNanos = 0;
    long threadParkRecords = 0;
    long threadParkDurationNanos = 0;
    long dataLossRecords = 0;
    long dataLossBytes = 0;

    long fileSize;
    String digest;
    try (PrivateSnapshot snapshot = PrivateSnapshot.copyOf(recording, maximumBytes)) {
      fileSize = snapshot.sizeBytes();
      digest = snapshot.sha256();
      try (RecordingFile file = new RecordingFile(snapshot.descriptorPath())) {
        while (file.hasMoreEvents()) {
          RecordedEvent event = file.readEvent();
          totalRecords = safeAdd(totalRecords, 1, "total JFR records");
          if (totalRecords > maximumRecords) {
            throw new IllegalArgumentException("JFR recording exceeds the record cap");
          }
          switch (event.getEventType().getName()) {
            case "jdk.ObjectAllocationSample" -> {
              allocationRecords = safeAdd(allocationRecords, 1, "allocation records");
              allocationWeightBytes =
                  safeAdd(
                      allocationWeightBytes,
                      requireNonNegativeSafe(event.getLong("weight"), "allocation weight"),
                      "allocation weight");
            }
            case "jdk.JavaMonitorEnter" -> {
              monitorEnterRecords = safeAdd(monitorEnterRecords, 1, "monitor enter records");
              monitorEnterDurationNanos =
                  safeAdd(
                      monitorEnterDurationNanos,
                      durationNanos(event.getDuration(), "monitor enter duration"),
                      "monitor enter duration");
            }
            case "jdk.ThreadPark" -> {
              threadParkRecords = safeAdd(threadParkRecords, 1, "thread park records");
              threadParkDurationNanos =
                  safeAdd(
                      threadParkDurationNanos,
                      durationNanos(event.getDuration(), "thread park duration"),
                      "thread park duration");
            }
            case "jdk.DataLoss" -> {
              dataLossRecords = safeAdd(dataLossRecords, 1, "data loss records");
              dataLossBytes =
                  safeAdd(
                      dataLossBytes,
                      requireNonNegativeSafe(event.getLong("amount"), "data loss bytes"),
                      "data loss bytes");
            }
            default ->
                throw new IllegalStateException(
                    "unexpected event in benchmark JFR: " + event.getEventType().getName());
          }
        }
      }
      snapshot.verifyUnchanged();
      snapshot.streamRaw(System.out);
    }
    if (dataLossRecords != 0 || dataLossBytes != 0) {
      throw new IllegalStateException("JFR reported data loss");
    }

    System.err.printf(
        "{\"schema_version\":1,\"file_size_bytes\":%d,\"raw_sha256\":\"%s\","
            + "\"snapshot_semantics\":\"single_source_descriptor_bounded_private_copy\","
            + "\"total_records\":%d,"
            + "\"allocation_sample\":{\"records\":%d,\"weight_bytes\":%d},"
            + "\"java_monitor_enter\":{\"records\":%d,\"duration_nanos\":%d},"
            + "\"thread_park\":{\"records\":%d,\"duration_nanos\":%d},"
            + "\"data_loss\":{\"records\":%d,\"bytes\":%d}}%n",
        fileSize,
        digest,
        totalRecords,
        allocationRecords,
        allocationWeightBytes,
        monitorEnterRecords,
        monitorEnterDurationNanos,
        threadParkRecords,
        threadParkDurationNanos,
        dataLossRecords,
        dataLossBytes);
  }

  private static void discardBootstrapJfr(long maximumBytes) throws IOException {
    Path quarantineDirectory = createPrivateDirectory(".obi-jfr-discard-");
    Object directoryKey = requireFileKey(quarantineDirectory, true, "discard directory");
    Path quarantined = quarantineDirectory.resolve("bootstrap.jfr");
    Object bootstrapKey = null;
    Object quarantinedKey = null;
    try {
      bootstrapKey = requireRegularIdentity(BOOTSTRAP_JFR, "bootstrap JFR").fileKey();
      Files.move(BOOTSTRAP_JFR, quarantined, StandardCopyOption.ATOMIC_MOVE);
      quarantinedKey = requireEntryKey(quarantined, "quarantined bootstrap JFR");
      if (!bootstrapKey.equals(quarantinedKey)) {
        throw new IllegalStateException("bootstrap JFR identity changed during quarantine");
      }
      try (FileChannel descriptor =
          FileChannel.open(
              quarantined, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
        Path descriptorPath = locateOpenDescriptor(quarantined);
        if (!quarantinedKey.equals(
            requireDescriptorKey(descriptorPath, "quarantined bootstrap JFR descriptor"))) {
          throw new IllegalStateException("quarantined bootstrap JFR identity changed");
        }
        BoundedFile inspected =
            readBoundedDescriptor(descriptor, descriptorPath, maximumBytes);
        if (!quarantinedKey.equals(inspected.fileKey())) {
          throw new IllegalStateException("quarantined bootstrap JFR identity changed");
        }
        if (Files.exists(BOOTSTRAP_JFR, LinkOption.NOFOLLOW_LINKS)) {
          throw new IllegalStateException("bootstrap JFR path was recreated during discard");
        }
        deleteExactPrivateEntry(quarantineDirectory, directoryKey, quarantined, quarantinedKey);
        quarantinedKey = null;
        if (Files.exists(BOOTSTRAP_JFR, LinkOption.NOFOLLOW_LINKS)) {
          throw new IllegalStateException("bootstrap JFR remained after discard");
        }
        deleteExactPrivateDirectory(quarantineDirectory, directoryKey);
        System.out.printf(
            "{\"schema_version\":1,\"status\":\"discarded\",\"size_bytes\":%d,"
                + "\"sha256\":\"%s\","
                + "\"discard_semantics\":\"atomic_move_then_descriptor_bounded_delete\"}%n",
            inspected.sizeBytes(), inspected.sha256());
      }
    } finally {
      if (quarantinedKey != null) {
        deleteExactPrivateEntry(quarantineDirectory, directoryKey, quarantined, quarantinedKey);
      }
      if (Files.exists(quarantineDirectory, LinkOption.NOFOLLOW_LINKS)) {
        deleteExactPrivateDirectory(quarantineDirectory, directoryKey);
      }
    }
  }

  private record BoundedFile(long sizeBytes, String sha256, Object fileKey) {}

  private static final class PrivateSnapshot implements AutoCloseable {
    private final Path directory;
    private final Object directoryKey;
    private final Path file;
    private final Object fileKey;
    private final FileChannel descriptor;
    private final Path descriptorPath;
    private final long sizeBytes;
    private final String sha256;
    private boolean closed;

    private PrivateSnapshot(
        Path directory,
        Object directoryKey,
        Path file,
        Object fileKey,
        FileChannel descriptor,
        Path descriptorPath,
        long sizeBytes,
        String sha256) {
      this.directory = directory;
      this.directoryKey = directoryKey;
      this.file = file;
      this.fileKey = fileKey;
      this.descriptor = descriptor;
      this.descriptorPath = descriptorPath;
      this.sizeBytes = sizeBytes;
      this.sha256 = sha256;
    }

    static PrivateSnapshot copyOf(Path source, long maximumBytes) throws IOException {
      BasicFileAttributes sourcePathBefore = requireRegularIdentity(source, "JFR source");
      if (sourcePathBefore.size() <= 0 || sourcePathBefore.size() > maximumBytes) {
        throw new IllegalArgumentException("JFR source size is outside the byte cap");
      }
      Path directory = createPrivateDirectory(".obi-jfr-snapshot-");
      Object directoryKey = requireFileKey(directory, true, "snapshot directory");
      Path snapshot = directory.resolve("recording.jfr");
      FileChannel descriptor = null;
      Object snapshotKey = null;
      try (FileChannel sourceDescriptor =
          FileChannel.open(source, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
        Path sourceDescriptorPath = locateOpenDescriptor(source);
        BasicFileAttributes sourceDescriptorBefore =
            requireDescriptorIdentity(sourceDescriptorPath, "JFR source descriptor");
        if (!sourcePathBefore.fileKey().equals(sourceDescriptorBefore.fileKey())
            || sourcePathBefore.size() != sourceDescriptorBefore.size()) {
          throw new IllegalStateException("JFR source identity changed while it was opened");
        }
        descriptor =
            FileChannel.open(
                snapshot,
                Set.of(
                    StandardOpenOption.READ,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.CREATE_NEW,
                    LinkOption.NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rw-------")));
        snapshotKey = requireEntryKey(snapshot, "snapshot entry");
        Path descriptorPath = locateOpenDescriptor(snapshot);
        if (!snapshotKey.equals(requireDescriptorKey(descriptorPath, "snapshot descriptor"))) {
          throw new IllegalStateException("private JFR snapshot descriptor identity changed");
        }
        BoundedFile copied =
            copyBoundedFile(
                sourceDescriptor,
                sourceDescriptorPath,
                descriptor,
                descriptorPath,
                maximumBytes);
        if (!snapshotKey.equals(copied.fileKey())) {
          throw new IllegalStateException("private JFR snapshot identity changed while copying");
        }
        BoundedFile sourceVerification =
            readBoundedDescriptor(sourceDescriptor, sourceDescriptorPath, maximumBytes);
        BasicFileAttributes sourcePathAfter = requireRegularIdentity(source, "JFR source");
        if (!sourcePathBefore.fileKey().equals(sourceVerification.fileKey())
            || sourceVerification.sizeBytes() != copied.sizeBytes()
            || !sourceVerification.sha256().equals(copied.sha256())
            || !sourcePathBefore.fileKey().equals(sourcePathAfter.fileKey())
            || sourcePathAfter.size() != copied.sizeBytes()) {
          throw new IllegalStateException("JFR source changed while it was snapshotted");
        }
        return new PrivateSnapshot(
            directory,
            directoryKey,
            snapshot,
            snapshotKey,
            descriptor,
            descriptorPath,
            copied.sizeBytes(),
            copied.sha256());
      } catch (IOException | RuntimeException exception) {
        if (descriptor != null) {
          descriptor.close();
        }
        if (snapshotKey != null) {
          deleteExactPrivateEntry(directory, directoryKey, snapshot, snapshotKey);
        }
        if (!Files.exists(snapshot, LinkOption.NOFOLLOW_LINKS)) {
          deleteExactPrivateDirectory(directory, directoryKey);
        }
        throw exception;
      }
    }

    Path descriptorPath() {
      return descriptorPath;
    }

    long sizeBytes() {
      return sizeBytes;
    }

    String sha256() {
      return sha256;
    }

    void verifyUnchanged() throws IOException {
      requireExactDirectory(directory, directoryKey, "snapshot directory");
      BoundedFile current = readBoundedDescriptor(descriptor, descriptorPath, sizeBytes);
      if (!fileKey.equals(current.fileKey())
          || current.sizeBytes() != sizeBytes
          || !current.sha256().equals(sha256)) {
        throw new IllegalStateException("private JFR snapshot changed while it was parsed");
      }
    }

    void streamRaw(OutputStream output) throws IOException {
      BoundedFile streamed = streamBoundedDescriptor(descriptor, descriptorPath, sizeBytes, output);
      if (!fileKey.equals(streamed.fileKey())
          || streamed.sizeBytes() != sizeBytes
          || !streamed.sha256().equals(sha256)) {
        throw new IllegalStateException("private JFR snapshot changed while it was streamed");
      }
    }

    @Override
    public void close() throws IOException {
      if (closed) {
        return;
      }
      Exception failure = null;
      try {
        verifyUnchanged();
      } catch (IOException | RuntimeException exception) {
        failure = exception;
      }
      try {
        descriptor.close();
      } catch (IOException exception) {
        if (failure == null) {
          failure = exception;
        } else {
          failure.addSuppressed(exception);
        }
      }
      try {
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
          deleteExactPrivateEntry(directory, directoryKey, file, fileKey);
        }
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)
            && Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
          deleteExactPrivateDirectory(directory, directoryKey);
        }
      } catch (IOException | RuntimeException exception) {
        if (failure == null) {
          failure = exception;
        } else {
          failure.addSuppressed(exception);
        }
      }
      closed = true;
      if (failure instanceof IOException ioException) {
        throw ioException;
      }
      if (failure instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
    }
  }

  private static Path createPrivateDirectory(String prefix) throws IOException {
    Path directory =
        Files.createTempDirectory(
            PRIVATE_TMP_ROOT,
            prefix,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    requireFileKey(directory, true, "private directory");
    return directory;
  }

  private static BoundedFile copyBoundedFile(
      FileChannel source,
      Path sourceDescriptorPath,
      FileChannel destination,
      Path destinationDescriptorPath,
      long maximumBytes)
      throws IOException {
    BasicFileAttributes sourceBefore =
        requireDescriptorIdentity(sourceDescriptorPath, "JFR source descriptor");
    if (sourceBefore.size() <= 0 || sourceBefore.size() > maximumBytes) {
      throw new IllegalArgumentException("JFR source size is outside the byte cap");
    }
    Object destinationKey =
        requireDescriptorKey(destinationDescriptorPath, "JFR snapshot destination");
    MessageDigest digest = sha256Digest();
    long total = 0;
    ByteBuffer buffer = ByteBuffer.allocate(8192);
    destination.truncate(0);
    destination.position(0);
    source.position(0);
    int count;
    while ((count = source.read(buffer)) != -1) {
      if (count == 0) {
        buffer.clear();
        continue;
      }
      if (total > maximumBytes - count) {
        throw new IllegalArgumentException("JFR source exceeds the byte cap while copying");
      }
      total += count;
      buffer.flip();
      digest.update(buffer.asReadOnlyBuffer());
      while (buffer.hasRemaining()) {
        destination.write(buffer);
      }
      buffer.clear();
    }
    if (total <= 0 || total != sourceBefore.size()) {
      throw new IllegalStateException("JFR source size changed while copying");
    }
    BasicFileAttributes sourceAfter =
        requireDescriptorIdentity(sourceDescriptorPath, "JFR source descriptor");
    if (!sourceBefore.fileKey().equals(sourceAfter.fileKey())
        || sourceAfter.size() != total
        || source.size() != total) {
      throw new IllegalStateException("JFR source identity changed while copying");
    }
    BasicFileAttributes destinationAfter =
        requireDescriptorIdentity(destinationDescriptorPath, "JFR snapshot");
    if (!destinationKey.equals(destinationAfter.fileKey())
        || destinationAfter.size() != total
        || destination.size() != total) {
      throw new IllegalStateException("JFR snapshot identity changed while copying");
    }
    return new BoundedFile(total, HexFormat.of().formatHex(digest.digest()), destinationKey);
  }

  private static Path locateOpenDescriptor(Path expectedPath) throws IOException {
    Path descriptors =
        Path.of("/proc", Long.toString(ProcessHandle.current().pid()), "fd");
    Path match = null;
    int entries = 0;
    try (DirectoryStream<Path> stream = Files.newDirectoryStream(descriptors)) {
      for (Path entry : stream) {
        entries++;
        if (entries > 4096) {
          throw new IllegalStateException("open file descriptor scan exceeds the hard cap");
        }
        String name = entry.getFileName().toString();
        if (!name.matches("[0-9]+") || !Files.isSymbolicLink(entry)) {
          continue;
        }
        Path target;
        try {
          target = Files.readSymbolicLink(entry);
        } catch (IOException exception) {
          continue;
        }
        if (target.toString().equals(expectedPath.toString())) {
          if (match != null) {
            throw new IllegalStateException("private JFR snapshot descriptor is ambiguous");
          }
          match = entry;
        }
      }
    }
    if (match == null) {
      throw new IllegalStateException("private JFR snapshot descriptor is unavailable");
    }
    requireDescriptorKey(match, "private JFR snapshot descriptor");
    return match;
  }

  private static BasicFileAttributes requireDescriptorIdentity(Path descriptorPath, String label)
      throws IOException {
    BasicFileAttributes attributes =
        Files.readAttributes(descriptorPath, BasicFileAttributes.class);
    if (!attributes.isRegularFile() || attributes.fileKey() == null) {
      throw new IllegalStateException(label + " does not expose a stable descriptor identity");
    }
    return attributes;
  }

  private static Object requireDescriptorKey(Path descriptorPath, String label) throws IOException {
    return requireDescriptorIdentity(descriptorPath, label).fileKey();
  }

  private static BoundedFile readBoundedDescriptor(
      FileChannel descriptor, Path descriptorPath, long maximumBytes) throws IOException {
    return streamBoundedDescriptor(descriptor, descriptorPath, maximumBytes, null);
  }

  private static BoundedFile streamBoundedDescriptor(
      FileChannel descriptor, Path descriptorPath, long maximumBytes, OutputStream output)
      throws IOException {
    BasicFileAttributes before =
        requireDescriptorIdentity(descriptorPath, "bounded descriptor");
    if (!descriptor.isOpen() || before.size() <= 0 || before.size() > maximumBytes) {
      throw new IllegalArgumentException("bounded descriptor size is outside the byte cap");
    }
    MessageDigest digest = sha256Digest();
    long total = 0;
    ByteBuffer buffer = ByteBuffer.allocate(8192);
    WritableByteChannel outputChannel = output == null ? null : Channels.newChannel(output);
    descriptor.position(0);
    int count;
    while ((count = descriptor.read(buffer)) != -1) {
      if (count == 0) {
        buffer.clear();
        continue;
      }
      if (total > maximumBytes - count) {
        throw new IllegalArgumentException("bounded descriptor exceeds the byte cap while reading");
      }
      total += count;
      buffer.flip();
      digest.update(buffer.asReadOnlyBuffer());
      if (outputChannel != null) {
        while (buffer.hasRemaining()) {
          outputChannel.write(buffer);
        }
      }
      buffer.clear();
    }
    if (output != null) {
      output.flush();
    }
    BasicFileAttributes after =
        requireDescriptorIdentity(descriptorPath, "bounded descriptor");
    if (total <= 0
        || total != before.size()
        || !before.fileKey().equals(after.fileKey())
        || after.size() != total
        || descriptor.size() != total) {
      throw new IllegalStateException("bounded descriptor identity changed while reading");
    }
    return new BoundedFile(total, HexFormat.of().formatHex(digest.digest()), before.fileKey());
  }

  private static BasicFileAttributes requireRegularIdentity(Path path, String label)
      throws IOException {
    BasicFileAttributes attributes =
        Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (!attributes.isRegularFile() || attributes.isSymbolicLink()) {
      throw new IllegalArgumentException(label + " must be a non-symlink regular file");
    }
    if (attributes.fileKey() == null) {
      throw new IllegalStateException(label + " does not expose a stable file identity");
    }
    return attributes;
  }

  private static Object requireFileKey(Path path, boolean directory, String label)
      throws IOException {
    BasicFileAttributes attributes =
        Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if ((directory && !attributes.isDirectory())
        || (!directory && !attributes.isRegularFile())
        || attributes.isSymbolicLink()
        || attributes.fileKey() == null) {
      throw new IllegalStateException(label + " does not have the required stable identity");
    }
    return attributes.fileKey();
  }

  private static Object requireEntryKey(Path path, String label) throws IOException {
    BasicFileAttributes attributes =
        Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    if (attributes.isDirectory() || attributes.fileKey() == null) {
      throw new IllegalStateException(label + " does not have the required entry identity");
    }
    return attributes.fileKey();
  }

  private static void requireExactDirectory(Path directory, Object expectedKey, String label)
      throws IOException {
    if (!requireFileKey(directory, true, label).equals(expectedKey)) {
      throw new IllegalStateException(label + " identity changed");
    }
  }

  private static void deleteExactPrivateEntry(
      Path directory, Object directoryKey, Path entry, Object entryKey) throws IOException {
    requireExactDirectory(directory, directoryKey, "private directory before entry deletion");
    if (!requireEntryKey(entry, "private entry before deletion").equals(entryKey)) {
      throw new IllegalStateException("private entry identity changed before deletion");
    }
    Files.delete(entry);
    if (Files.exists(entry, LinkOption.NOFOLLOW_LINKS)) {
      throw new IllegalStateException("private entry remained after deletion");
    }
    requireExactDirectory(directory, directoryKey, "private directory after entry deletion");
  }

  private static void deleteExactPrivateDirectory(Path directory, Object directoryKey)
      throws IOException {
    requireExactDirectory(directory, directoryKey, "private directory before deletion");
    Files.delete(directory);
    if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
      throw new IllegalStateException("private directory remained after deletion");
    }
  }

  private static MessageDigest sha256Digest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static long durationNanos(Duration duration, String label) {
    if (duration.isNegative()) {
      throw new IllegalArgumentException(label + " is negative");
    }
    try {
      return requireNonNegativeSafe(duration.toNanos(), label);
    } catch (ArithmeticException exception) {
      throw new IllegalArgumentException(label + " exceeds the safe range", exception);
    }
  }

  private static long parsePositiveSafeLong(String raw, String label) {
    try {
      return requirePositiveSafe(Long.parseLong(raw), label);
    } catch (NumberFormatException exception) {
      throw new IllegalArgumentException(label + " is not an integer", exception);
    }
  }

  private static long parsePositiveCappedLong(String raw, String label, long maximum) {
    long value = parsePositiveSafeLong(raw, label);
    if (value > maximum) {
      throw new IllegalArgumentException(label + " exceeds the hard cap");
    }
    return value;
  }

  private static long requirePositiveSafe(long value, String label) {
    if (value <= 0 || value > MAX_SAFE_JSON_INTEGER) {
      throw new IllegalArgumentException(label + " is outside the safe positive range");
    }
    return value;
  }

  private static long requireNonNegativeSafe(long value, String label) {
    if (value < 0 || value > MAX_SAFE_JSON_INTEGER) {
      throw new IllegalArgumentException(label + " is outside the safe non-negative range");
    }
    return value;
  }

  private static long safeAdd(long left, long right, String label) {
    if (left < 0 || right < 0 || left > MAX_SAFE_JSON_INTEGER - right) {
      throw new IllegalArgumentException(label + " exceeds the safe aggregate range");
    }
    return left + right;
  }
}
