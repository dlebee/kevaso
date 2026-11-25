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
//	kvo create clustersecret NAME [--description D] (--from-file F|- | --from-file KEY=F…)
//	kvo set clustersecret NAME (--from-file F|- | --from-file KEY=F… | --remove-key KEY…)
//	kvo get clustersecret [NAME] [--reveal [--key KEY]]
//	kvo delete clustersecret NAME

type clusterOpts struct {
	description string
}

func createClusterSecret(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	if len(o.args) != 2 {
		return errors.New("create clustersecret needs a NAME: kvo create clustersecret NAME [--description TEXT] --from-file FILE|-")
	}
	if o.secret.literalSet() || o.secret.generate || len(o.secret.removeKeys) > 0 {
		return errors.New("a clustersecret's value comes from --from-file FILE, --from-file - (stdin) or --from-file KEY=FILE (repeatable)")
	}
	value, data, err := o.secret.keys(stdin)
	if err != nil {
		return err
	}
	defer clear(value)
	defer clearData(data)
	if value == nil && data == nil {
		return errors.New("a clustersecret needs a value: --from-file FILE, --from-file - (stdin) or --from-file KEY=FILE (repeatable)")
	}
	s := &v1.ClusterSecret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterSecret"},
		ObjectMeta: meta.ObjectMeta{Name: o.args[1]},
		Spec:       v1.ClusterSecretSpec{Description: o.cluster.description, Value: value, Data: data}}
	if err := c.Create(ctx, s); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "clustersecret/%s created (version %d%s)\n", s.Name, s.Status.Version, keysNote(s.Status.Keys))
	return nil
}

func setClusterSecret(ctx context.Context, c *client.Client, o opts, stdin io.Reader, stdout io.Writer) error {
	if len(o.args) >= 1 && o.args[0] == "secret" {
		return errors.New("a namespace secret changes with kvo secret set NAME (--from-file FILE|- | --from-file KEY=FILE… | --remove-key KEY…); kvo set is for a clustersecret")
	}
	if len(o.args) != 2 || o.args[0] != "clustersecret" {
		return errors.New("usage: kvo set clustersecret NAME (--from-file FILE|- | --from-file KEY=FILE… | --remove-key KEY…)")
	}
	if o.secret.literalSet() || o.secret.generate {
		return errors.New("a clustersecret's value comes from --from-file FILE, --from-file - (stdin) or --from-file KEY=FILE (repeatable)")
	}
	value, data, err := o.secret.keys(stdin)
	if err != nil {
		return err
	}
	defer clear(value)
	defer clearData(data)
	if value != nil && len(o.secret.removeKeys) > 0 {
		return errors.New("--from-file FILE replaces every key already: --remove-key goes with KEY=FILE, or alone")
	}
	if value == nil && data == nil && len(o.secret.removeKeys) == 0 {
		return errors.New("set clustersecret needs the new value: --from-file FILE, --from-file - (stdin), --from-file KEY=FILE (repeatable) or --remove-key KEY")
	}
	var s v1.ClusterSecret
	if err := retryUpdate(func() error {
		if err := c.Get(ctx, "ClusterSecret", "", o.args[1], &s); err != nil {
			return err
		}
		s.Spec.Value, s.Spec.SetData, s.Spec.RemoveKeys = value, data, o.secret.removeKeys
		return c.Update(ctx, &s)
	}); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "clustersecret/%s: version %d%s\n", s.Name, s.Status.Version, keysNote(s.Status.Keys))
	return nil
}
