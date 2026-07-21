plugins {
    java
    id("com.diffplug.spotless") version "8.8.0" apply false
}

import java.io.ByteArrayOutputStream
import org.gradle.api.tasks.compile.JavaCompile

group = "io.opentelemetry.obi"
version = "0.1.0"

subprojects {
    apply(plugin = "java")

    configure<JavaPluginExtension> {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    repositories {
        mavenCentral()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.release.set(8)
    }
}

val copyLoaderJar by tasks.registering(Copy::class) {
    dependsOn(":loader:shadowJar")
    from("$projectDir/loader/build/libs/loader-$version-shaded.jar")
    into("$projectDir/build")
    rename { "obi-java-agent.jar" }
}

val copyExtensionJar by tasks.registering(Copy::class) {
    dependsOn(":extension:jar")
    from("$projectDir/extension/build/libs/obi-otel-extension.jar")
    into("$projectDir/build")
    rename { "obi-otel-extension.jar" }
}

tasks.named("jar") {
    dependsOn(copyLoaderJar, copyExtensionJar)
}

// Ensure root test task depends on copyLoaderJar
tasks.named("test") {
    dependsOn(copyLoaderJar, copyExtensionJar)
}

val verifyDoubleAgentLoad by tasks.registering(Exec::class) {
    group = "verification"
    description = "Verify duplicate agent loads reuse the bootstrap installation"
    dependsOn(copyLoaderJar)

    val output = ByteArrayOutputStream()
    standardOutput = output
    errorOutput = output
    doFirst {
        val agentJar = layout.buildDirectory.file("obi-java-agent.jar").get().asFile
        val java = file("${System.getProperty("java.home")}/bin/java")
        commandLine(
            java.absolutePath,
            "-javaagent:${agentJar.absolutePath}=remoteParentTransport=disabled",
            "-javaagent:${agentJar.absolutePath}=remoteParentTransport=disabled",
            "-version",
        )
    }
    doLast {
        val text = output.toString(Charsets.UTF_8.name())
        val marker = "already installed; transport reconfigured"
        val first = text.indexOf(marker)
        check(first >= 0 && text.indexOf(marker, first + marker.length) < 0) {
            "Expected one duplicate-install reconfiguration, output was:\n$text"
        }
    }
}

tasks.named("check") {
    dependsOn(verifyDoubleAgentLoad)
}
