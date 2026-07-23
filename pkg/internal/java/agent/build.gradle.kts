import org.cyclonedx.model.Component
import org.gradle.api.tasks.compile.JavaCompile

plugins {
    java
    id("com.gradleup.shadow") version "9.6.0"
    id("com.github.jk1.dependency-license-report") version "3.1.4"
    id("me.champeau.jmh") version "0.7.3"
    id("org.cyclonedx.bom") version "3.3.0"
    id("com.diffplug.spotless")
}

group = "io.opentelemetry.obi"
version = "0.1.0"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

configure<com.diffplug.gradle.spotless.SpotlessExtension> {
    java {
        // Use Google Java Format
        googleJavaFormat()
        // Or use Eclipse formatter
        // eclipse()

        // Remove unused imports
        removeUnusedImports()

        // Trim trailing whitespace
        trimTrailingWhitespace()

        // End files with newline
        endWithNewline()

        // Target files
        target("src/**/*.java")
    }
}

repositories {
    mavenCentral()
}

val nettyProbe = configurations.create("nettyProbe")

dependencies {
    implementation("net.bytebuddy:byte-buddy:1.18.11")
    implementation("net.bytebuddy:byte-buddy-agent:1.18.11")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.14.4")
    testImplementation("org.junit.platform:junit-platform-launcher:1.14.4")
    testImplementation("org.awaitility:awaitility:4.3.0")
    testImplementation("io.netty:netty-common:4.1.135.Final")
    add(nettyProbe.name, "io.netty:netty-common:4.1.135.Final")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.14.4")
}

tasks.register("prepareKotlinBuildScriptModel"){}

val java21ProbeClasses = layout.buildDirectory.dir("classes/java21Probe")
val lateAttachProbeClasses = layout.buildDirectory.dir("classes/lateAttachProbe")
val nettyProbeClasses = layout.buildDirectory.dir("classes/nettyProbe")
val remoteParentVectors =
    rootProject.file("../../../testdata/java-remote-parent-v1-vectors.txt")

val compileLateAttachProbe by tasks.registering(JavaCompile::class) {
    description = "Compile the isolated late-attach class-loader probe"
    source(fileTree("src/test/javaProbe") { include("**/*.java") })
    destinationDirectory.set(lateAttachProbeClasses)
    classpath = files()
    options.release.set(8)
}

val compileJava21Probe by tasks.registering(Exec::class) {
    description = "Compile the packaged-agent Java 21 virtual-thread probe"
    val testJavaVersion = providers.environmentVariable("OBI_TEST_JAVA_VERSION")
        .orElse(JavaVersion.current().majorVersion)
    val testJavaHome = providers.environmentVariable("OBI_TEST_JAVA_HOME")
        .orElse(System.getProperty("java.home"))
    val sources = fileTree("src/test/java21") { include("**/*.java") }

    onlyIf { testJavaVersion.get() == "21" }
    inputs.files(sources)
    outputs.dir(java21ProbeClasses)
    doFirst {
        java21ProbeClasses.get().asFile.mkdirs()
        commandLine(
            file("${testJavaHome.get()}/bin/javac").absolutePath,
            "--enable-preview",
            "--release",
            "21",
            "-d",
            java21ProbeClasses.get().asFile.absolutePath,
            *sources.files.sorted().map { it.absolutePath }.toTypedArray(),
        )
    }
}

val compileNettyProbe by tasks.registering(JavaCompile::class) {
    description = "Compile the packaged-agent Netty event-loop probe"
    source(fileTree("src/test/javaNettyProbe") { include("**/*.java") })
    destinationDirectory.set(nettyProbeClasses)
    classpath = nettyProbe
    options.release.set(8)
}

tasks.test {
    useJUnitPlatform()
    inputs.file(remoteParentVectors)
    dependsOn(
        rootProject.tasks.named("copyLoaderJar"),
        compileJava21Probe,
        compileLateAttachProbe,
        compileNettyProbe,
    )
    doFirst {
        systemProperty(
            "obi.test.remote.parent.vectors",
            remoteParentVectors.absolutePath,
        )
        systemProperty(
            "obi.test.packaged.agent",
            rootProject.layout.buildDirectory.file("obi-java-agent.jar").get().asFile.absolutePath,
        )
        systemProperty(
            "obi.test.java21.probe.classes",
            java21ProbeClasses.get().asFile.absolutePath,
        )
        systemProperty(
            "obi.test.late.attach.probe.classes",
            lateAttachProbeClasses.get().asFile.absolutePath,
        )
        systemProperty(
            "obi.test.netty.probe.classes",
            nettyProbeClasses.get().asFile.absolutePath,
        )
        systemProperty("obi.test.netty.probe.classpath", nettyProbe.asPath)
    }
}

// Automatic JNI header generation during compilation
// Outputs to the build directory to avoid affecting the source tree
tasks.compileJava {
    options.headerOutputDirectory.set(layout.buildDirectory.dir("generated/jni-headers"))
}

// Ensure spotless runs after compileJava to avoid task ordering issues
tasks.named("spotlessJava") {
    mustRunAfter(tasks.compileJava)
}

val currentArch = if (System.getProperty("os.arch").contains("aarch64")) "aarch64" else "amd64"

// Build the native JNI library
tasks.register<Exec>("buildNativeLib-amd64") {
    group = "build"
    description = "Build the JNI native library (libobijni.so)"

    dependsOn("compileJava")

    workingDir = projectDir
    val cc = if (currentArch == "amd64") "gcc" else "gcc-x86-64-linux-gnu"
    commandLine("make", "-f", "Makefile.jni", "CC=$cc", "BUILD_DIR=build/jni/linux-amd64", "TARGET_DIR=target/classes/native/linux-amd64")

    doLast {
        println("OBI JNI library built successfully")
    }
}

tasks.register<Exec>("buildNativeLib-aarch64") {
    group = "build"
    description = "Build the JNI native library (libobijni.so)"

    dependsOn("compileJava")

    workingDir = projectDir
    val cc = if (currentArch == "aarch64") "gcc" else "aarch64-linux-gnu-gcc"
    commandLine("make", "-f", "Makefile.jni", "CC=$cc", "BUILD_DIR=build/jni/linux-aarch64", "TARGET_DIR=target/classes/native/linux-aarch64")

    doLast {
        println("OBI JNI library built successfully")
    }
}

val nativeTest by tasks.registering(Exec::class) {
    group = "verification"
    description = "Build and run the native remote-parent transport tests"

    dependsOn("compileJava")
    inputs.file(remoteParentVectors)

    workingDir = projectDir
    environment("JAVA_HOME", System.getProperty("java.home"))
    commandLine(
        "make",
        "-f",
        "Makefile.jni",
        "test",
        "BUILD_DIR=build/jni-test",
        "REMOTE_PARENT_VECTORS=${remoteParentVectors.absolutePath}",
    )
}

tasks.check {
    dependsOn(nativeTest)
}

// Clean native library
tasks.register<Delete>("cleanNativeLib") {
    group = "build"
    description = "Clean the JNI native library build artifacts"
    
    delete(file("build"))
    delete(file("target/classes/native/linux-amd64/libobijni.so"))
    delete(file("target/classes/native/linux-aarch64/libobijni.so"))
}

val jmhIncludes: String? by project
val jmhProfilers: String? by project
val jmhWarmupIterations: String? by project
val jmhIterations: String? by project
val jmhForks: String? by project

jmh {
    includes.set(listOf(".*Benchmark.*"))
    jmhIncludes?.let {
        includes.set(listOf(it))
    }
    jmhProfilers?.let { profilersStr ->
        profilers.set(profilersStr.split(",").map { p: String -> p.trim() })
    }
    benchmarkMode.set(listOf("avgt"))
    timeUnit.set("ns")
    warmupIterations.set(jmhWarmupIterations?.toInt() ?: 3)
    iterations.set(jmhIterations?.toInt() ?: 5)
    fork.set(jmhForks?.toInt() ?: 1)
    jvmArgs.set(listOf("-Xmx2G"))
}

val nativeOnly: String? by project
val nativeArches: List<String> = if (nativeOnly != null) {
    val osArch = System.getProperty("os.arch")
    listOf(if (osArch.contains("aarch64")) "aarch64" else "amd64")
} else {
    listOf("amd64", "aarch64")
}

tasks.shadowJar {
    nativeArches.forEach { arch -> dependsOn("buildNativeLib-$arch") }

    archiveBaseName.set("agent")
    archiveVersion.set("0.1.0")
    archiveClassifier.set("shaded")

    // Include the native libraries in the JAR
    from(file("target/classes")) {
        nativeArches.forEach { arch -> include("native/linux-$arch/libobijni.so") }
    }

    manifest {
        attributes(
            "Premain-Class" to "io.opentelemetry.obi.java.Agent",
            "Agent-Class" to "io.opentelemetry.obi.java.Agent",
            "Can-Redefine-Classes" to "true",
            "Can-Retransform-Classes" to "true",
            "Main-Class" to "io.opentelemetry.obi.java.Agent"
        )
    }
    relocate("net.bytebuddy", "io.opentelemetry.obi.net.bytebuddy")
    // Exclude META-INF files as in Maven Shade plugin
    exclude("META-INF/**")
    exclude("META-INF/versions/9/module-info.class")
}

licenseReport {
    outputDir = layout.buildDirectory.dir("reports/dependency-license").get().asFile.absolutePath
    configurations = arrayOf("runtimeClasspath")
    renderers = arrayOf<com.github.jk1.license.render.ReportRenderer>(
        com.github.jk1.license.render.TextReportRenderer("THIRD_PARTY_LICENSES.txt"),
        com.github.jk1.license.render.CsvReportRenderer("THIRD_PARTY_LICENSES.csv"),
    )
}

tasks.cyclonedxDirectBom {
    includeConfigs = listOf("runtimeClasspath")
    skipConfigs = listOf("testCompileClasspath", "testRuntimeClasspath")
    projectType.set(Component.Type.APPLICATION)
    componentName.set("obi-java-agent")
    componentVersion.set(providers.environmentVariable("OBI_JAVA_AGENT_SBOM_VERSION").orElse(version.toString()))
    includeBuildSystem.set(true)
}
