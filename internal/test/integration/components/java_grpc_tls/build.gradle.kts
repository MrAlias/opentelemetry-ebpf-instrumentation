plugins { application }
repositories { mavenCentral() }
dependencies {
    implementation("io.grpc:grpc-netty-shaded:1.84.0")
    implementation("io.grpc:grpc-stub:1.84.0")
}
application { mainClass.set("fixture.Source") }
