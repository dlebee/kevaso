package ingress_test

import (
	"context"
	"strings"
	"testing"

	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/sdk/kic"
)

// K-085: a proxy's refusal can echo what it refused, keys included (Kong's errors carry the
// certificate entity). No key material reaches a status, a log or an error, for any driver.

const echoedKey = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIKEYMATERIALkeymaterialKEYMATERIALkeymaterial0123456789\n-----END EC PRIVATE KEY-----\n"

// leaks says whether s carries any of the key's body.
func leaks(s string) bool {
	return strings.Contains(s, "KEYMATERIAL") || strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "s3cr3t")
}

func TestK085ARefusalThatEchoesAKeyIsRedacted(t *testing.T) {
	for _, r := range rigs(false) {
		t.Run(r.name, func(t *testing.T) {
			// The proxy refuses whatever carries the poisoned host, echoing a key (in a PEM block,
			// JSON-escaped as Kong does, cut by the tail, and as a key field).
			echo := "refused: " + echoedKey + ` {"cert":"x","key":"` + strings.ReplaceAll(echoedKey, "\n", `\n`) + `","password":"s3cr3t"} ` +
				strings.Repeat("y", 1900) + "\n" + echoedKey[20:] + " the end"
			r.px.Check = func(cfg []byte, _ map[string][]byte) string {
				if strings.Contains(string(cfg), poison) {
					return echo
				}
				return ""
			}
			if r.call != nil {
				call := r.call
				r.call = func(ctx context.Context, c kic.Call) (int, string, error) {
					if strings.Contains(string(c.Body), poison) {
						return 400, echo, nil
					}
					return call(ctx, c)
				}
			}
			w := want(route("shop/a", "a.example.com", 80), route("shop/bad", poison+".example.com", 81))
			res, err := ingress.ApplyEach(context.Background(), r.exec, r.call, r.driver, w, nil, "", &ingress.Memory{}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if res.LeftOut["shop/bad"] == "" {
				t.Fatalf("not refused: %+v", res)
			}
			for who, why := range res.LeftOut {
				if leaks(why) {
					t.Errorf("%s's reason carries key material: %s", who, why)
				}
			}
			if leaks(res.Rejected) || leaks(res.Held) || leaks(ingress.LeftOutMessage(res.LeftOut)) {
				t.Errorf("key material in the result: %+v", res)
			}
			// The class's own part refused with the same echo: held, and its reason clean too.
			w.State.Challenges = []kic.Challenge{{Token: poison, KeyAuthorization: poison + ".x"}}
			res, err = ingress.ApplyEach(context.Background(), r.exec, r.call, r.driver, w, nil, "", &ingress.Memory{}, 0)
			if err != nil || res.Held == "" {
				t.Fatalf("%+v %v", res, err)
			}
			if leaks(res.Held) || leaks(res.Rejected) {
				t.Errorf("key material in the held reason: %s", res.Held)
			}
		})
	}
}

// Apply itself: a rejection, and a command that fails (its output in the error).
func TestK085ApplyRedactsWhatTheProxySays(t *testing.T) {
	for _, r := range rigs(false) {
		t.Run(r.name, func(t *testing.T) {
			p, err := r.driver.Render(want(route("shop/bad", poison+".example.com", 81)).State)
			if err != nil {
				t.Fatal(err)
			}
			r.px.Check = func([]byte, map[string][]byte) string { return "bad: " + echoedKey }
			call := func(context.Context, kic.Call) (int, string, error) { return 400, `{"key":"s3cr3t"} ` + echoedKey, nil }
			res, err := ingress.Apply(context.Background(), r.exec, call, r.driver, p, "")
			if err != nil || res.Rejected == "" || leaks(res.Rejected) {
				t.Errorf("%+v %v", res, err)
			}
			if r.name == "kong" {
				return
			}
			failing := func(_ context.Context, argv []string, _ []byte) (int, string, error) {
				return 1, "cannot write: " + echoedKey, nil
			}
			if _, err := ingress.Apply(context.Background(), failing, nil, r.driver, p, ""); err == nil || leaks(err.Error()) {
				t.Errorf("error %v", err)
			}
		})
	}
}

func TestK085Redact(t *testing.T) {
	for in, want := range map[string]string{
		`nginx: [emerg] host not found in upstream "x:80" in /etc/nginx/nginx.conf:12`: `nginx: [emerg] host not found in upstream "x:80" in /etc/nginx/nginx.conf:12`,
		"a " + echoedKey + "b":                         "a [key material removed]\nb",
		`{"key":"-----BEGIN RSA PRIVATE KEY-----\nAAA`: `{"key":"[key material removed]`,
		"QUJD\nREVG\n-----END PRIVATE KEY----- rest":   "[key material removed] rest",
		`{"cert":"c","key":"abc\n","snis":[]}`:         `{"cert":"c","key":"[removed]","snis":[]}`,
		`{\"client_secret\":\"xyz\",\"name\":\"n\"}`:   `{\"client_secret\":\"[removed]\",\"name\":\"n\"}`,
	} {
		if got := ingress.Redact(in); got != want {
			t.Errorf("Redact(%q)\n= %q\nwant %q", in, got, want)
		}
	}
}
