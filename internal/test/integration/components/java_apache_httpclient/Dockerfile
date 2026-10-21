FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS proxy
WORKDIR /proxy
COPY internal/test/integration/components/java_httpclient_traceparent/proxy.go .
RUN CGO_ENABLED=0 go build -o proxy proxy.go && ./proxy certificate

FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS downstream
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/test/integration/components/java_apache_httpclient/downstream/main.go ./main.go
RUN CGO_ENABLED=0 go build -o /downstream main.go

FROM gradle:9.8.1-jdk21-noble@sha256:d879477a2197b2b8a5eb910d007f0b1594eb440aa2740baac17ea245fcfb02f7
WORKDIR /fixture
COPY internal/test/integration/components/java_apache_httpclient/Main.java ./
COPY internal/test/integration/components/java_apache_httpclient/build.gradle.kts ./
COPY --from=proxy /proxy/proxy.crt /proxy/proxy.key /proxy/proxy ./
COPY --from=downstream /downstream ./
RUN gradle compileJava runtimeLibraries --no-daemon && \
    keytool -importcert -noprompt -alias proxy -file proxy.crt \
      -keystore trust.p12 -storetype PKCS12 -storepass changeit
ENTRYPOINT ["java", "-Djavax.net.ssl.trustStore=/fixture/trust.p12", "-Djavax.net.ssl.trustStorePassword=changeit", "-cp", "build/classes/java/main:build/libs/*", "Main"]
