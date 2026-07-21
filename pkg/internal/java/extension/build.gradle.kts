import java.util.jar.Manifest
import java.util.zip.ZipFile

plugins {
    java
    id("com.diffplug.spotless")
}

version = rootProject.version

val otelVersion = "1.62.0"

dependencies {
    compileOnly("io.opentelemetry:opentelemetry-api:$otelVersion")
    compileOnly("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure-spi:$otelVersion")

    testImplementation("io.opentelemetry:opentelemetry-api:$otelVersion")
    testImplementation("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure-spi:$otelVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.14.4")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.14.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.14.4")
}

configure<com.diffplug.gradle.spotless.SpotlessExtension> {
    java {
        googleJavaFormat()
        removeUnusedImports()
        trimTrailingWhitespace()
        endWithNewline()
        target("src/**/*.java")
    }
}

tasks.test {
    useJUnitPlatform()
    dependsOn(tasks.jar)
    doFirst {
        systemProperty(
            "obi.test.extension.jar",
            tasks.jar.get().archiveFile.get().asFile.absolutePath,
        )
    }
}

tasks.jar {
    archiveFileName.set("obi-otel-extension.jar")
    from(rootProject.file("../../../LICENSE")) {
        into("META-INF")
        rename { "LICENSE" }
    }
    from(rootProject.file("../../../NOTICE")) {
        into("META-INF")
        rename { "NOTICE" }
    }
    manifest {
        attributes(
            "Implementation-Title" to "OBI OpenTelemetry Java agent extension",
            "Implementation-Version" to project.version,
        )
    }
}

tasks.processResources {
    inputs.property("extensionVersion", project.version)
    filesMatching("io/opentelemetry/obi/java/extension/version.properties") {
        expand("extensionVersion" to project.version.toString())
    }
}

val verifyExtensionJar by tasks.registering {
    dependsOn(tasks.jar)
    inputs.file(tasks.jar.flatMap { it.archiveFile })

    doLast {
        val jarFile = tasks.jar.get().archiveFile.get().asFile
        ZipFile(jarFile).use { zip ->
            val service =
                "META-INF/services/io.opentelemetry.sdk.autoconfigure.spi.ConfigurablePropagatorProvider"
            check(zip.getEntry(service) != null) { "Missing ConfigurablePropagatorProvider SPI metadata" }
            val customizerService =
                "META-INF/services/io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider"
            check(zip.getEntry(customizerService) != null) {
                "Missing AutoConfigurationCustomizerProvider SPI metadata"
            }
            check(
                zip.getEntry("io/opentelemetry/obi/java/extension/version.properties") != null,
            ) { "Missing extension compatibility version metadata" }
            check(zip.getEntry("META-INF/LICENSE") != null) { "Missing extension license" }
            check(zip.getEntry("META-INF/NOTICE") != null) { "Missing extension notice" }
            val manifestEntry = zip.getEntry("META-INF/MANIFEST.MF")
            check(manifestEntry != null) { "Missing extension manifest" }
            val jarManifest = zip.getInputStream(manifestEntry).use { Manifest(it) }
            check(
                jarManifest.mainAttributes.getValue("Implementation-Version") == project.version.toString(),
            ) { "Missing extension manifest version" }

            val forbidden =
                zip.entries().asSequence().firstOrNull {
                    it.name.startsWith("io/opentelemetry/api/") ||
                        it.name.startsWith("io/opentelemetry/context/") ||
                        it.name.startsWith("io/opentelemetry/javaagent/") ||
                        it.name.startsWith("io/opentelemetry/sdk/")
                }
            check(forbidden == null) { "Extension contains agent-provided class: ${forbidden?.name}" }
        }
    }
}

tasks.check {
    dependsOn(verifyExtensionJar)
}
