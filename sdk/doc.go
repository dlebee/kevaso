// Package sdk holds the plugin interfaces (KRI, KNI, KSI, KLB, KDNS, KMS, mesh), plugin registration,
// conformance suites and fake plugins. It is its own Go module so that providers depend only on it and
// on the api module, never on the server.
//
// It is empty until the first plugin interface lands (milestone M3).
package sdk
