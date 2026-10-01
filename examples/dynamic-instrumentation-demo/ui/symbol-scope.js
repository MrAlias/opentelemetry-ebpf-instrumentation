(function exposeSymbolScope(root, factory) {
  const api = factory();
  root.OBISymbolScope = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(globalThis, function createSymbolScope() {
  const goRuntimePrefixes = [
    "bytes.", "cmp.", "context.", "crypto/", "encoding/", "errors.", "fmt.",
    "hash/", "internal/", "io.", "io/", "math.", "math/", "net.", "net/",
    "os.", "path.", "path/", "reflect.", "runtime.", "sort.", "strconv.",
    "strings.", "sync.", "sync/", "syscall.", "time.", "unicode.", "unicode/"
  ];
  const javaRuntimePrefixes = [
    "java.", "javax.", "jdk.", "sun.", "com.sun.", "net.bytebuddy.", "io.opentelemetry."
  ];
  const javaDependencyPrefixes = [
    "ch.qos.logback.", "com.fasterxml.", "com.google.", "io.grpc.", "io.netty.",
    "jakarta.", "kotlin.", "kotlinx.", "org.apache.", "org.eclipse.", "org.hibernate.",
    "org.jboss.", "org.jcp.", "org.junit.", "org.objectweb.asm.", "org.slf4j.",
    "org.springframework.", "okhttp3.", "okio."
  ];

  function startsWithAny(symbol, prefixes) {
    return prefixes.some((prefix) => symbol.startsWith(prefix));
  }

  function classifyGo(symbol) {
    if (symbol.startsWith("main.")) return "application";
    if (startsWithAny(symbol, goRuntimePrefixes)) return "runtime";
    return "dependency";
  }

  function classifyJava(symbol) {
    if (startsWithAny(symbol, javaRuntimePrefixes)) return "runtime";
    if (startsWithAny(symbol, javaDependencyPrefixes)) return "dependency";
    return "application";
  }

  function classifyNode(symbol) {
    if (symbol.startsWith("node:") || symbol.includes("/internal/")) return "runtime";
    if (symbol.includes("/node_modules/")) return "dependency";
    return "application";
  }

  function classify(symbol, languages = []) {
    const language = languages[0] || "";
    if (language === "go") return classifyGo(symbol);
    if (language === "java") return classifyJava(symbol);
    if (language === "nodejs") return classifyNode(symbol);
    return "application";
  }

  return { classify };
});
