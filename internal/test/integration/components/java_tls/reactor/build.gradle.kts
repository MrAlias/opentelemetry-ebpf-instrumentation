plugins {
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.projectreactor.netty:reactor-netty-http:1.2.15")
}

application {
    mainClass.set("ReactorClient")
}
