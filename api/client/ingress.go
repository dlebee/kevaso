package client

// PathAgentIngress is where a host's agent gets the desired state of an ingress controller silo
// placed on it (?namespace=NS&name=SILO): the proxy-neutral routes, certificates (with their keys)
// and ACME challenges its driver renders (design §7.3). Only that silo's host gets an answer.
const PathAgentIngress = "/agent/ingress"
