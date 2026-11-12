// Package sdk holds the plugin interfaces (KRI, KNI, KSI, KLB, KDNS, KMS, mesh), plugin registration,
// conformance suites and fake plugins. It is its own Go module so that providers depend only on it and
// on the api module, never on the server.
//
// kri is the first interface (M3). Built-in runtimes implement it in-process; out-of-process plugins
// will speak the same interface over gRPC once the first one ships.
package sdk
