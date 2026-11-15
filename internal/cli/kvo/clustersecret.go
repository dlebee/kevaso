package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Cluster secrets from the command line. Values come from a file or stdin, never from argv,
// the same way a Secret's do.
//
//	kvo create clustersecret NAME --plugin P [--plugin P2] [--host H]… [--description D] --from-file F|-
//	kvo set clustersecret NAME --from-file F|-
//	kvo get clustersecret [NAME] [--reveal]
//	kvo delete clustersecret NAME

type clusterOpts struct {
	plugins, hosts []string
	description    string
}

func createClusterSecret(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("create clustersecret needs a NAME: kvo create clustersecret NAME --plugin PLUGIN --from-file FILE|-")
	}
	if o.secret.literalSet || o.secret.generate {
		return errors.New("a clustersecret's value comes from --from-file FILE or --from-file - (stdin)")
	}
	if len(o.cluster.plugins) == 0 {
		return errors.New("a clustersecret needs a plugin: --plugin PLUGIN [--plugin PLUGIN]")
	}
	value, err := o.secret.value(stdin)
	if err != nil {
		return err
	}
	if value == nil {
		return errors.New("a clustersecret needs a value: --from-file FILE or --from-file - (stdin)")
	}
	s := &v1.ClusterSecret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterSecret"},
		ObjectMeta: meta.ObjectMeta{Name: o.args[1]},
		Spec:       v1.ClusterSecretSpec{Description: o.cluster.description, Plugins: o.cluster.plugins, Hosts: o.cluster.hosts, Value: value}}
	if err := c.Create(ctx, s); err != nil {
		return err
	}
	clear(value)
	_, _ = fmt.Fprintf(stdout, "clustersecret/%s created (version %d)\n", s.Name, s.Status.Version)
	return nil
}

func setClusterSecret(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	if len(o.args) != 2 || o.args[0] != "clustersecret" {
		return errors.New("usage: kvo set clustersecret NAME --from-file FILE|-")
	}
	if o.secret.literalSet || o.secret.generate {
		return errors.New("a clustersecret's value comes from --from-file FILE or --from-file - (stdin)")
	}
	value, err := o.secret.value(stdin)
	if err != nil {
		return err
	}
	if value == nil {
		return errors.New("set clustersecret needs the new value: --from-file FILE or --from-file - (stdin)")
	}
	defer clear(value)
	for attempt := 0; ; attempt++ {
		var s v1.ClusterSecret
		if err := c.Get(ctx, "ClusterSecret", "", o.args[1], &s); err != nil {
			return err
		}
		s.Spec.Value = value
		err := c.Update(ctx, &s)
		if client.IsConflict(err) && attempt < 3 {
			continue
		}
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "clustersecret/%s: version %d\n", s.Name, s.Status.Version)
		return nil
	}
}
