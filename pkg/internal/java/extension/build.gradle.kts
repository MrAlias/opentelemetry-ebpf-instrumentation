import java.util.jar.Manifest
import java.util.zip.ZipFile
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.testing.Test
import org.gradle.jvm.tasks.Jar

plugins {
    java
    id("com.diffplug.spotless")
}

version = rootProject.version

val otelVersion = "1.62.0"
val otelJavaagentVersion = "2.28.1-alpha"
val jettyVersion = "11.0.26"
val nettyVersion = "4.1.135.Final"

val officialAgentProbeExtension = sourceSets.create("officialAgentProbeExtension")
val officialAgentProbeApp = sourceSets.create("officialAgentProbeApp")
val officialAgentNettyProbeApp = sourceSets.create("officialAgentNettyProbeApp")
val officialAgentJava21ProbeApp = sourceSets.create("officialAgentJava21ProbeApp")

dependencies {
    compileOnly("io.opentelemetry:opentelemetry-api:$otelVersion")
    compileOnly("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure:$otelVersion")
    compileOnly("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure-spi:$otelVersion")
    compileOnly(
        "io.opentelemetry.javaagent:opentelemetry-javaagent-extension-api:$otelJavaagentVersion",
    )

    testImplementation("io.opentelemetry:opentelemetry-api:$otelVersion")
    testImplementation("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure:$otelVersion")
    testImplementation("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure-spi:$otelVersion")
    testImplementation(
        "io.opentelemetry.javaagent:opentelemetry-javaagent-extension-api:$otelJavaagentVersion",
    )
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.14.4")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.14.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.14.4")

    add(
        officialAgentProbeExtension.compileOnlyConfigurationName,
        "io.opentelemetry:opentelemetry-api:$otelVersion",
    )
    add(
        officialAgentProbeExtension.compileOnlyConfigurationName,
        "io.opentelemetry:opentelemetry-sdk-extension-autoconfigure-spi:$otelVersion",
    )
    add(
        officialAgentProbeExtension.compileOnlyConfigurationName,
        "io.opentelemetry:opentelemetry-sdk-trace:$otelVersion",
    )
    add(
        officialAgentProbeApp.implementationConfigurationName,
        "org.eclipse.jetty:jetty-server:$jettyVersion",
    )
    add(
        officialAgentProbeApp.implementationConfigurationName,
        "org.eclipse.jetty:jetty-servlet:$jettyVersion",
    )
    add(
        officialAgentProbeApp.runtimeOnlyConfigurationName,
        "org.slf4j:slf4j-simple:2.0.13",
    )
    add(
        officialAgentNettyProbeApp.implementationConfigurationName,
        "io.netty:netty-codec-http:$nettyVersion",
    )
    add(
        officialAgentNettyProbeApp.implementationConfigurationName,
        "io.netty:netty-handler:$nettyVersion",
    )
    add(
        officialAgentJava21ProbeApp.implementationConfigurationName,
        "io.opentelemetry:opentelemetry-api:$otelVersion",
    )
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
    filter {
        excludeTestsMatching("*OfficialAgentJettyRuntimeTest")
        excludeTestsMatching("*OfficialAgentNettyRuntimeTest")
        excludeTestsMatching("*OfficialAgentJava21ConcurrencyRuntimeTest")
    }
    dependsOn(tasks.jar)
    doFirst {
        systemProperty(
            "obi.test.extension.jar",
            tasks.jar.get().archiveFile.get().asFile.absolutePath,
        )
    }
}

tasks.named<JavaCompile>(officialAgentProbeApp.compileJavaTaskName) {
    options.release.set(11)
}

tasks.named<JavaCompile>(officialAgentNettyProbeApp.compileJavaTaskName) {
    options.release.set(8)
}

val officialAgentProbeExtensionJar by tasks.registering(Jar::class) {
    archiveFileName.set("obi-official-agent-probe-extension.jar")
    from(officialAgentProbeExtension.output)
}

val verifyOfficialAgentProbeExtensionJar by tasks.registering {
    dependsOn(officialAgentProbeExtensionJar)
    inputs.file(officialAgentProbeExtensionJar.flatMap { it.archiveFile })

    doLast {
        val jarFile = officialAgentProbeExtensionJar.get().archiveFile.get().asFile
        ZipFile(jarFile).use { zip ->
            val service =
                "META-INF/services/io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider"
            val serviceEntry = zip.getEntry(service)
            check(serviceEntry != null) { "Missing probe AutoConfigurationCustomizerProvider metadata" }
            val provider =
                zip.getInputStream(serviceEntry).bufferedReader(Charsets.UTF_8).use { it.readText() }.trim()
            check(
                provider ==
                    "io.opentelemetry.obi.java.extension.probe.OfficialAgentProbeExtension",
            ) { "Unexpected probe extension provider: $provider" }

            val forbidden =
                zip.entries().asSequence().firstOrNull {
                    it.name.startsWith("io/opentelemetry/api/") ||
                        it.name.startsWith("io/opentelemetry/context/") ||
                        it.name.startsWith("io/opentelemetry/javaagent/") ||
                        it.name.startsWith("io/opentelemetry/sdk/")
                }
            check(forbidden == null) { "Probe extension contains agent-provided class: ${forbidden?.name}" }
        }
    }
}

val officialAgentRuntimeTest by tasks.registering(Test::class) {
    group = "verification"
    description = "Run compatibility, Jetty, Netty, and Java 21 probes with both pinned official agents"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform()
    filter {
        includeTestsMatching("*OfficialAgentCompatibilityTest")
        includeTestsMatching("*OfficialAgentJettyRuntimeTest")
        includeTestsMatching("*OfficialAgentNettyRuntimeTest")
        includeTestsMatching("*OfficialAgentJava21ConcurrencyRuntimeTest")
    }
    dependsOn(
        tasks.jar,
        tasks.testClasses,
        rootProject.tasks.named("copyLoaderJar"),
        officialAgentProbeApp.classesTaskName,
        officialAgentNettyProbeApp.classesTaskName,
        officialAgentJava21ProbeApp.classesTaskName,
        officialAgentProbeExtensionJar,
        verifyOfficialAgentProbeExtensionJar,
    )
    inputs.file(tasks.jar.flatMap { it.archiveFile })
    inputs.file(rootProject.layout.buildDirectory.file("obi-java-agent.jar"))
    inputs.file(officialAgentProbeExtensionJar.flatMap { it.archiveFile })
    inputs.files(officialAgentProbeApp.runtimeClasspath)
    inputs.files(officialAgentNettyProbeApp.runtimeClasspath)
    inputs.files(officialAgentJava21ProbeApp.runtimeClasspath)
    val officialAgents =
        listOf("OBI_TEST_OTEL_AGENT", "OBI_TEST_SPLUNK_AGENT").associateWith {
            providers.environmentVariable(it)
        }
    officialAgents.forEach { (environmentName, agentPath) ->
        agentPath.orNull?.let { inputs.file(it).withPropertyName(environmentName) }
    }
    doFirst {
        officialAgents.forEach { (environmentName, agentPath) ->
            check(agentPath.isPresent) { "$environmentName must be set" }
        }
        systemProperty(
            "obi.test.extension.jar",
            tasks.jar.get().archiveFile.get().asFile.absolutePath,
        )
        systemProperty(
            "obi.test.packaged.agent",
            rootProject.layout.buildDirectory.file("obi-java-agent.jar").get().asFile.absolutePath,
        )
        systemProperty(
            "obi.test.official.agent.probe.extension.jar",
            officialAgentProbeExtensionJar.get().archiveFile.get().asFile.absolutePath,
        )
        systemProperty(
            "obi.test.official.agent.probe.app.classpath",
            officialAgentProbeApp.runtimeClasspath.asPath,
        )
        systemProperty(
            "obi.test.official.agent.netty.probe.app.classpath",
            officialAgentNettyProbeApp.runtimeClasspath.asPath,
        )
        systemProperty(
            "obi.test.official.agent.java21.probe.app.classpath",
            officialAgentJava21ProbeApp.runtimeClasspath.asPath,
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
            val agentListenerService =
                "META-INF/services/io.opentelemetry.javaagent.extension.AgentListener"
            val agentListenerEntry = zip.getEntry(agentListenerService)
            check(agentListenerEntry != null) { "Missing AgentListener SPI metadata" }
            val agentListener =
                zip.getInputStream(agentListenerEntry).bufferedReader(Charsets.UTF_8).use { it.readText() }.trim()
            check(
                agentListener ==
                    "io.opentelemetry.obi.java.extension.ObiDiagnosticsAgentListener",
            ) { "Unexpected AgentListener provider: $agentListener" }
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
    dependsOn(verifyExtensionJar, verifyOfficialAgentProbeExtensionJar)
}
