FROM gradle:9.8.0-jdk21-noble@sha256:0076fefe482103cf751a047aae94ba3b1db84e3893865125ecf8f14b6a02ec60 AS build
WORKDIR /app
COPY internal/test/integration/components/java_tls/reactor/ .
RUN gradle installDist --no-daemon

FROM gradle:9.8.0-jdk21-noble@sha256:0076fefe482103cf751a047aae94ba3b1db84e3893865125ecf8f14b6a02ec60
COPY --from=build /app/build/install/app /app
ENTRYPOINT ["/app/bin/app"]
