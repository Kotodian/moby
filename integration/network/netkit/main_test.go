//go:build !windows

package netkit

import (
	"context"
	"os"
	"testing"

	"github.com/moby/moby/v2/internal/testutil"
	"github.com/moby/moby/v2/internal/testutil/environment"
	"github.com/moby/moby/v2/internal/testutil/fixtures/load"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var (
	testEnv     *environment.Execution
	baseContext context.Context
)

func TestMain(m *testing.M) {
	shutdown := testutil.ConfigureTracing()

	ctx, span := otel.Tracer("").Start(context.Background(), "integration/network/netkit/TestMain")
	baseContext = ctx

	var err error
	testEnv, err = environment.New(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.End()
		shutdown(ctx)
		panic(err)
	}

	if os.Getenv("DOCKERFILE") == "" {
		_ = os.Setenv("DOCKERFILE", "../../Dockerfile")
	}

	err = load.FrozenImagesLinux(ctx, testEnv.APIClient(), "busybox:latest")
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.End()
		shutdown(ctx)
		panic(err)
	}

	testEnv.Print()
	code := m.Run()
	if code != 0 {
		span.SetStatus(codes.Error, "m.Run() returned non-zero exit code")
	}
	span.SetAttributes(attribute.Int("exit", code))
	span.End()
	shutdown(ctx)
	os.Exit(code)
}

func setupTest(t *testing.T) context.Context {
	ctx := testutil.StartSpan(baseContext, t)
	environment.ProtectAll(ctx, t, testEnv)
	t.Cleanup(func() { testEnv.Clean(ctx, t) })
	return ctx
}
