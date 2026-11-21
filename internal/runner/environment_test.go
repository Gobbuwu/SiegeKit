package runner

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/report"
	"github.com/Gobbuwu/SiegeKit/internal/sandbox"
)

type describedExec struct {
	info sandbox.Info
	err  error
}

func (describedExec) Run(context.Context, sandbox.Spec) (*sandbox.Result, error) {
	return nil, errors.New("not used")
}

func (d describedExec) Describe(context.Context) (sandbox.Info, error) { return d.info, d.err }

func TestEnvironment(t *testing.T) {
	env := Environment(context.Background(), describedExec{info: sandbox.Info{Engine: "podman", Version: "5.7.0", Rootless: true, Cgroup: "v2"}})
	if env.OS != runtime.GOOS || env.Arch != runtime.GOARCH || env.Go != runtime.Version() || env.Engine == nil || *env.Engine != (report.Engine{Name: "podman", Version: "5.7.0", Rootless: true, Cgroup: "v2"}) {
		t.Fatalf("%+v", env)
	}
	if s := env.String(); s != runtime.GOOS+"/"+runtime.GOARCH+", SiegeKit built with "+runtime.Version()+", podman 5.7.0 rootless, cgroup v2" {
		t.Errorf("String() = %q", s)
	}
	for _, ex := range []Executor{nil, describedExec{err: errors.New("down")}} {
		if env := Environment(context.Background(), ex); env.Engine != nil || !strings.HasSuffix(env.String(), ", no container engine") {
			t.Errorf("%v: %+v", ex, env)
		}
	}
	// The HTML report names the environment.
	var b bytes.Buffer
	run := &report.Run{Target: "/x", Mode: "local", Environment: Environment(context.Background(), describedExec{info: sandbox.Info{Engine: "docker", Version: "29.10.0", Cgroup: "v1"}})}
	if err := report.WriteHTML(&b, run); err != nil || !strings.Contains(b.String(), "docker 29.10.0 rootful, cgroup v1") {
		t.Errorf("HTML report does not name the environment: %v", err)
	}
}
