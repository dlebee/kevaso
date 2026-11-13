package kplugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	pb "kevaso.com/core/sdk/kplugin/kpluginpb"
)

// The wire is gRPC (kpluginpb/kplugin.proto), like CSI. A plugin implements the Go interfaces in
// this package; Serve turns them into gRPC services and Client turns the services back into them,
// so neither side touches protobuf. Errors cross as CSI-style status codes.

func toStatus(err error) error {
	if err == nil {
		return nil
	}
	code := codes.Unknown
	switch {
	case errors.Is(err, ErrNotFound):
		code = codes.NotFound
	case errors.Is(err, ErrUnsupported):
		code = codes.Unimplemented
	case errors.Is(err, ErrConflict):
		code = codes.FailedPrecondition
	case errors.Is(err, ErrInProgress):
		code = codes.Aborted
	case errors.Is(err, context.DeadlineExceeded):
		code = codes.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		code = codes.Canceled
	}
	return status.Error(code, err.Error())
}

func fromStatus(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	var sentinel error
	switch st.Code() {
	case codes.NotFound:
		sentinel = ErrNotFound
	case codes.Unimplemented:
		sentinel = ErrUnsupported
	case codes.FailedPrecondition:
		sentinel = ErrConflict
	case codes.Aborted:
		sentinel = ErrInProgress
	default:
		return errors.New(st.Message())
	}
	msg := st.Message()
	if msg == sentinel.Error() {
		return sentinel
	}
	return fmt.Errorf("%s: %w", trimSuffix(msg, ": "+sentinel.Error()), sentinel)
}

func trimSuffix(s, suf string) string {
	if len(s) >= len(suf) && s[len(s)-len(suf):] == suf {
		return s[:len(s)-len(suf)]
	}
	return s
}

// ── conversions ──

func classesTo(cs []Class) []*pb.Class {
	out := make([]*pb.Class, 0, len(cs))
	for _, c := range cs {
		out = append(out, &pb.Class{Name: c.Name, Description: c.Description, OwnHostsOnly: c.OwnHostsOnly, Announce: c.Announce, NodePorts: c.NodePorts, Topology: c.Topology, Reach: c.Reach})
	}
	return out
}

func classesFrom(cs []*pb.Class) []Class {
	out := make([]Class, 0, len(cs))
	for _, c := range cs {
		out = append(out, Class{Name: c.GetName(), Description: c.GetDescription(), OwnHostsOnly: c.GetOwnHostsOnly(), Announce: c.GetAnnounce(), NodePorts: c.GetNodePorts(), Topology: c.GetTopology(), Reach: c.GetReach()})
	}
	return out
}

func hostInfoTo(h HostInfo) *pb.HostInfo {
	return &pb.HostInfo{Name: h.Name, Id: h.ID, Region: h.Region, PrivateAddress: h.PrivateAddress}
}

func hostInfoFrom(h *pb.HostInfo) HostInfo {
	return HostInfo{Name: h.GetName(), ID: h.GetId(), Region: h.GetRegion(), PrivateAddress: h.GetPrivateAddress()}
}

func hostInfosTo(hs []HostInfo) []*pb.HostInfo {
	out := make([]*pb.HostInfo, 0, len(hs))
	for _, h := range hs {
		out = append(out, hostInfoTo(h))
	}
	return out
}

func hostInfosFrom(hs []*pb.HostInfo) []HostInfo {
	var out []HostInfo
	for _, h := range hs {
		out = append(out, hostInfoFrom(h))
	}
	return out
}

func lbTo(lb LoadBalancer) *pb.LoadBalancer {
	m := &pb.LoadBalancer{Class: lb.Class, Id: lb.ID, Namespace: lb.Namespace, Name: lb.Name, Address: lb.Address,
		Backends: hostInfosTo(lb.Backends), Hosts: hostInfosTo(lb.Hosts)}
	for _, p := range lb.Ports {
		m.Ports = append(m.Ports, &pb.Port{Name: p.Name, Protocol: p.Protocol, Port: int32(p.Port), NodePort: int32(p.NodePort)})
	}
	return m
}

func lbFrom(m *pb.LoadBalancer) LoadBalancer {
	lb := LoadBalancer{Class: m.GetClass(), ID: m.GetId(), Namespace: m.GetNamespace(), Name: m.GetName(), Address: m.GetAddress(),
		Backends: hostInfosFrom(m.GetBackends()), Hosts: hostInfosFrom(m.GetHosts())}
	for _, p := range m.GetPorts() {
		lb.Ports = append(lb.Ports, Port{Name: p.GetName(), Protocol: p.GetProtocol(), Port: int(p.GetPort()), NodePort: int(p.GetNodePort())})
	}
	return lb
}

func recordTo(r Record) *pb.Record {
	return &pb.Record{Provider: r.Provider, Name: r.Name, Type: r.Type, Values: r.Values, Ttl: int32(r.TTL), Owner: r.Owner}
}

func recordFrom(m *pb.Record) Record {
	return Record{Provider: m.GetProvider(), Name: m.GetName(), Type: m.GetType(), Values: m.GetValues(), TTL: int(m.GetTtl()), Owner: m.GetOwner()}
}

func attachmentFrom(m *pb.Attachment) Attachment {
	return Attachment{Class: m.GetClass(), Handle: m.GetHandle(), Host: hostInfoFrom(m.GetHost())}
}

// ── server side ──

type identityServer struct {
	pb.UnimplementedIdentityServer
	p Plugin
}

func (s identityServer) GetPluginInfo(ctx context.Context, _ *pb.GetPluginInfoRequest) (*pb.PluginInfo, error) {
	i, err := s.p.Info(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.PluginInfo{Name: i.Name, Version: i.Version, Protocol: Protocol, Hosts: i.Hosts,
		LoadBalancers: classesTo(i.LoadBalancers), Storage: classesTo(i.Storage), Dns: i.DNS}, nil
}

type hostsServer struct {
	pb.UnimplementedHostsServer
	p HostDescriber
}

func (s hostsServer) DescribeHosts(ctx context.Context, r *pb.DescribeHostsRequest) (*pb.DescribeHostsResponse, error) {
	var in []Host
	for _, h := range r.GetHosts() {
		in = append(in, Host{Name: h.GetName(), Address: h.GetAddress()})
	}
	out, err := s.p.DescribeHosts(ctx, in)
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.DescribeHostsResponse{Hosts: hostInfosTo(out)}, nil
}

type lbServer struct {
	pb.UnimplementedLoadBalancersServer
	p LoadBalancers
}

func (s lbServer) EnsureLoadBalancer(ctx context.Context, r *pb.LoadBalancer) (*pb.LoadBalancerStatus, error) {
	st, err := s.p.EnsureLoadBalancer(ctx, lbFrom(r))
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.LoadBalancerStatus{Address: st.Address, SourceRanges: st.SourceRanges}, nil
}

func (s lbServer) DeleteLoadBalancer(ctx context.Context, r *pb.LoadBalancerRef) (*pb.DeleteLoadBalancerResponse, error) {
	err := s.p.DeleteLoadBalancer(ctx, LoadBalancerRef{Class: r.GetClass(), ID: r.GetId(), Address: r.GetAddress()})
	return &pb.DeleteLoadBalancerResponse{}, toStatus(err)
}

type volumesServer struct {
	pb.UnimplementedVolumesServer
	p Volumes
}

func (s volumesServer) EnsureVolume(ctx context.Context, r *pb.Volume) (*pb.VolumeStatus, error) {
	st, err := s.p.EnsureVolume(ctx, Volume{Class: r.GetClass(), ID: r.GetId(), Name: r.GetName(), SizeBytes: r.GetSizeBytes(), Region: r.GetRegion()})
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.VolumeStatus{Handle: st.Handle, Region: st.Region, SizeBytes: st.SizeBytes, SizeEnforced: st.SizeEnforced}, nil
}

func (s volumesServer) AttachVolume(ctx context.Context, r *pb.Attachment) (*pb.AttachmentStatus, error) {
	st, err := s.p.AttachVolume(ctx, attachmentFrom(r))
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.AttachmentStatus{Device: st.Device}, nil
}

func (s volumesServer) DetachVolume(ctx context.Context, r *pb.Attachment) (*pb.DetachVolumeResponse, error) {
	return &pb.DetachVolumeResponse{}, toStatus(s.p.DetachVolume(ctx, attachmentFrom(r)))
}

func (s volumesServer) DeleteVolume(ctx context.Context, r *pb.VolumeRef) (*pb.DeleteVolumeResponse, error) {
	return &pb.DeleteVolumeResponse{}, toStatus(s.p.DeleteVolume(ctx, VolumeRef{Class: r.GetClass(), Handle: r.GetHandle()}))
}

type nodeServer struct {
	pb.UnimplementedNodeServer
	p Node
}

func nodeMountFrom(m *pb.NodeMount) NodeMount {
	return NodeMount{Class: m.GetClass(), Handle: m.GetHandle(), ID: m.GetId(), Path: m.GetPath()}
}

func nodeMountTo(m NodeMount) *pb.NodeMount {
	return &pb.NodeMount{Class: m.Class, Handle: m.Handle, Id: m.ID, Path: m.Path}
}

func (s nodeServer) NodeMountVolume(ctx context.Context, r *pb.NodeMount) (*pb.NodeMountResponse, error) {
	return &pb.NodeMountResponse{}, toStatus(s.p.MountVolume(ctx, nodeMountFrom(r)))
}

func (s nodeServer) NodeUnmountVolume(ctx context.Context, r *pb.NodeMount) (*pb.NodeUnmountResponse, error) {
	return &pb.NodeUnmountResponse{}, toStatus(s.p.UnmountVolume(ctx, nodeMountFrom(r)))
}

type dnsServer struct {
	pb.UnimplementedDNSServer
	p DNS
}

func (s dnsServer) EnsureRecord(ctx context.Context, r *pb.Record) (*pb.EnsureRecordResponse, error) {
	return &pb.EnsureRecordResponse{}, toStatus(s.p.EnsureRecord(ctx, recordFrom(r)))
}

func (s dnsServer) DeleteRecord(ctx context.Context, r *pb.Record) (*pb.DeleteRecordResponse, error) {
	return &pb.DeleteRecordResponse{}, toStatus(s.p.DeleteRecord(ctx, recordFrom(r)))
}

// Server returns a gRPC server with p's services (the ones it implements) and the standard health
// service.
func Server(p Plugin) *grpc.Server {
	s := grpc.NewServer()
	pb.RegisterIdentityServer(s, identityServer{p: p})
	if x, ok := p.(HostDescriber); ok {
		pb.RegisterHostsServer(s, hostsServer{p: x})
	}
	if x, ok := p.(LoadBalancers); ok {
		pb.RegisterLoadBalancersServer(s, lbServer{p: x})
	}
	if x, ok := p.(Volumes); ok {
		pb.RegisterVolumesServer(s, volumesServer{p: x})
	}
	if x, ok := p.(DNS); ok {
		pb.RegisterDNSServer(s, dnsServer{p: x})
	}
	if x, ok := p.(Node); ok {
		pb.RegisterNodeServer(s, nodeServer{p: x})
	}
	healthpb.RegisterHealthServer(s, health.NewServer())
	return s
}

// Serve serves p on the unix socket at path (replacing a stale one) until ctx ends. The socket is
// 0660: the control plane runs as root; nobody else needs it.
func Serve(ctx context.Context, path string, p Plugin) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = l.Close()
		return err
	}
	s := Server(p)
	go func() {
		<-ctx.Done()
		s.GracefulStop()
	}()
	if err := s.Serve(l); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// ── client side ──

// Client calls a plugin over gRPC. It implements every interface; services a plugin doesn't serve
// answer ErrUnsupported.
type Client struct {
	Socket string
	conn   *grpc.ClientConn
	id     pb.IdentityClient
	hosts  pb.HostsClient
	lbs    pb.LoadBalancersClient
	vols   pb.VolumesClient
	dns    pb.DNSClient
	node   pb.NodeClient
	health healthpb.HealthClient
}

// Dial returns a client for the plugin at socket. Connecting is lazy: the first call connects.
func Dial(socket string) *Client {
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil { // only for a malformed target, which "unix://PATH" never is
		panic(err)
	}
	return &Client{Socket: socket, conn: conn, id: pb.NewIdentityClient(conn), hosts: pb.NewHostsClient(conn),
		lbs: pb.NewLoadBalancersClient(conn), vols: pb.NewVolumesClient(conn), dns: pb.NewDNSClient(conn), node: pb.NewNodeClient(conn), health: healthpb.NewHealthClient(conn)}
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Healthy asks the plugin's standard health service.
func (c *Client) Healthy(ctx context.Context) error {
	r, err := c.health.Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return err
	}
	if r.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("plugin at %s: %s", c.Socket, r.GetStatus())
	}
	return nil
}

// Info implements Plugin.
func (c *Client) Info(ctx context.Context) (Info, error) {
	r, err := c.id.GetPluginInfo(ctx, &pb.GetPluginInfoRequest{})
	if err != nil {
		return Info{}, fromStatus(err)
	}
	return Info{Name: r.GetName(), Version: r.GetVersion(), Protocol: r.GetProtocol(), Hosts: r.GetHosts(),
		LoadBalancers: classesFrom(r.GetLoadBalancers()), Storage: classesFrom(r.GetStorage()), DNS: r.GetDns()}, nil
}

// DescribeHosts implements HostDescriber.
func (c *Client) DescribeHosts(ctx context.Context, hosts []Host) ([]HostInfo, error) {
	req := &pb.DescribeHostsRequest{}
	for _, h := range hosts {
		req.Hosts = append(req.Hosts, &pb.Host{Name: h.Name, Address: h.Address})
	}
	r, err := c.hosts.DescribeHosts(ctx, req)
	if err != nil {
		return nil, fromStatus(err)
	}
	return hostInfosFrom(r.GetHosts()), nil
}

// EnsureLoadBalancer implements LoadBalancers.
func (c *Client) EnsureLoadBalancer(ctx context.Context, lb LoadBalancer) (LoadBalancerStatus, error) {
	r, err := c.lbs.EnsureLoadBalancer(ctx, lbTo(lb))
	if err != nil {
		return LoadBalancerStatus{}, fromStatus(err)
	}
	return LoadBalancerStatus{Address: r.GetAddress(), SourceRanges: r.GetSourceRanges()}, nil
}

// DeleteLoadBalancer implements LoadBalancers.
func (c *Client) DeleteLoadBalancer(ctx context.Context, ref LoadBalancerRef) error {
	_, err := c.lbs.DeleteLoadBalancer(ctx, &pb.LoadBalancerRef{Class: ref.Class, Id: ref.ID, Address: ref.Address})
	return fromStatus(err)
}

// EnsureVolume implements Volumes.
func (c *Client) EnsureVolume(ctx context.Context, v Volume) (VolumeStatus, error) {
	r, err := c.vols.EnsureVolume(ctx, &pb.Volume{Class: v.Class, Id: v.ID, Name: v.Name, SizeBytes: v.SizeBytes, Region: v.Region})
	if err != nil {
		return VolumeStatus{}, fromStatus(err)
	}
	return VolumeStatus{Handle: r.GetHandle(), Region: r.GetRegion(), SizeBytes: r.GetSizeBytes(), SizeEnforced: r.GetSizeEnforced()}, nil
}

// AttachVolume implements Volumes.
func (c *Client) AttachVolume(ctx context.Context, a Attachment) (AttachmentStatus, error) {
	r, err := c.vols.AttachVolume(ctx, &pb.Attachment{Class: a.Class, Handle: a.Handle, Host: hostInfoTo(a.Host)})
	if err != nil {
		return AttachmentStatus{}, fromStatus(err)
	}
	return AttachmentStatus{Device: r.GetDevice()}, nil
}

// DetachVolume implements Volumes.
func (c *Client) DetachVolume(ctx context.Context, a Attachment) error {
	_, err := c.vols.DetachVolume(ctx, &pb.Attachment{Class: a.Class, Handle: a.Handle, Host: hostInfoTo(a.Host)})
	return fromStatus(err)
}

// DeleteVolume implements Volumes.
func (c *Client) DeleteVolume(ctx context.Context, ref VolumeRef) error {
	_, err := c.vols.DeleteVolume(ctx, &pb.VolumeRef{Class: ref.Class, Handle: ref.Handle})
	return fromStatus(err)
}

// EnsureRecord implements DNS.
func (c *Client) EnsureRecord(ctx context.Context, r Record) error {
	_, err := c.dns.EnsureRecord(ctx, recordTo(r))
	return fromStatus(err)
}

// DeleteRecord implements DNS.
func (c *Client) DeleteRecord(ctx context.Context, r Record) error {
	_, err := c.dns.DeleteRecord(ctx, recordTo(r))
	return fromStatus(err)
}

// MountVolume implements Node.
func (c *Client) MountVolume(ctx context.Context, m NodeMount) error {
	_, err := c.node.NodeMountVolume(ctx, nodeMountTo(m))
	return fromStatus(err)
}

// UnmountVolume implements Node.
func (c *Client) UnmountVolume(ctx context.Context, m NodeMount) error {
	_, err := c.node.NodeUnmountVolume(ctx, nodeMountTo(m))
	return fromStatus(err)
}

var (
	_ Node          = (*Client)(nil)
	_ Plugin        = (*Client)(nil)
	_ HostDescriber = (*Client)(nil)
	_ LoadBalancers = (*Client)(nil)
	_ Volumes       = (*Client)(nil)
	_ DNS           = (*Client)(nil)
)
