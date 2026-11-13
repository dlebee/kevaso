package agent

import (
	"context"
	"errors"
	"net/http"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// Pulls (design §0.2): on a runtime that pulls registry images itself (kri.Puller), the agent
// pulls before Create and Reset, with the credential the control plane gives this host for that
// silo (its container.pull secret, or its namespace's default for the image's registry). The
// credential is asked for each pull, so a rotated secret is used by the next one, and held only
// for the pull: the runtime puts it in a throwaway auth file and removes it.

// ReasonImagePullFailed is the Ready (and, on a reset, Updated) condition's reason when a pull
// fails: the registry's own reason is the message.
const ReasonImagePullFailed = "ImagePullFailed"

// pull pulls s's image if rt pulls registry images, and returns the digest the host now has ("":
// not a puller, or an image built here).
func (a *Agent) pull(ctx context.Context, rt kri.Runtime, s *v1.Silo, image string) (string, error) {
	p, ok := rt.(kri.Puller)
	if !ok {
		return "", nil
	}
	auth, err := a.pullCredential(ctx, s, image)
	if err != nil {
		return "", &kri.PullError{Image: image, Reason: err.Error()}
	}
	if auth != nil {
		defer clear(auth.Password)
	}
	return p.Pull(ctx, idOf(s), image, auth)
}

// pullCredential asks the control plane for the credential to pull image for s, through the
// broker path (a host only gets it for silos placed on it). nil: none applies.
func (a *Agent) pullCredential(ctx context.Context, s *v1.Silo, image string) (*kri.RegistryAuth, error) {
	var resp client.BrokerResponse
	if err := a.Client.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
		Namespace: s.Namespace, Name: s.Name, UID: s.UID, Host: a.HostName,
		Request: client.BrokerRequest{Op: client.OpPullCredential, Name: image}}, &resp); err != nil {
		return nil, errors.New("the control plane can't be reached for the pull credential: " + err.Error())
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	if resp.Registry == nil {
		return nil, nil
	}
	return &kri.RegistryAuth{Server: resp.Registry.Server, Username: resp.Registry.Username, Password: resp.Registry.Password}, nil
}

// failReason is the condition reason for a failed create or reset.
func failReason(err error, otherwise string) string {
	if kri.IsPullError(err) {
		return ReasonImagePullFailed
	}
	return otherwise
}
