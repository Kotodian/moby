//go:build !windows

package netkit

import (
	"context"
	"slices"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
	"github.com/moby/moby/v2/integration/internal/container"
	net "github.com/moby/moby/v2/integration/internal/network"
	"github.com/moby/moby/v2/internal/testutil"
	"github.com/moby/moby/v2/internal/testutil/environment"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/icmd"
	"gotest.tools/v3/skip"
)

const parentBridge = "docker0"

func TestDockerNetworkNetkit(t *testing.T) {
	skip.If(t, testEnv.IsRemoteDaemon())
	skip.If(t, testEnv.IsRootless(), "rootless mode has different view of network")
	skip.If(t, !environment.IsNetkitSupported(), "netkit requires Linux 6.7+")

	ctx := setupTest(t)
	apiClient := testEnv.APIClient()

	netName := "nk-test"
	net.CreateNoError(ctx, t, apiClient, netName,
		net.WithDriver("netkit"),
		net.WithIPAM("172.29.0.0/24", "172.29.0.1"),
	)
	defer net.RemoveNoError(ctx, t, apiClient, netName)

	first := container.Run(ctx, t, apiClient, container.WithName("nk-a"), container.WithNetworkMode(netName))
	second := container.Run(ctx, t, apiClient, container.WithName("nk-b"), container.WithNetworkMode(netName))
	defer container.Remove(ctx, t, apiClient, first, client.ContainerRemoveOptions{Force: true})
	defer container.Remove(ctx, t, apiClient, second, client.ContainerRemoveOptions{Force: true})

	result := container.ExecT(ctx, t, apiClient, first, []string{"sh", "-ec", "ip -d link show eth0"})
	assert.Check(t, is.Contains(result.Combined(), "netkit"))

	_, err := container.Exec(ctx, apiClient, second, []string{"ping", "-c", "1", "nk-a"})
	assert.NilError(t, err)

	info, err := apiClient.Info(ctx, client.InfoOptions{})
	assert.NilError(t, err)
	assert.Check(t, slices.Contains(info.Info.Plugins.Network, "netkit"))
}

func TestDockerNetworkNetkitUnsupported(t *testing.T) {
	skip.If(t, testEnv.IsRemoteDaemon())
	skip.If(t, testEnv.IsRootless(), "rootless mode has different view of network")
	skip.If(t, environment.IsNetkitSupported(), "kernel already supports netkit")

	ctx := setupTest(t)
	apiClient := testEnv.APIClient()
	skip.If(t, !linkExists(ctx, t, parentBridge), "docker0 bridge is not available")

	_, err := apiClient.NetworkCreate(ctx, "nk-unsupported", client.NetworkCreateOptions{
		Driver: "netkit",
		Options: map[string]string{
			"parent": parentBridge,
		},
	})
	assert.Check(t, err != nil)
	assert.Check(t, cerrdefs.IsNotImplemented(err))
	assert.Check(t, is.ErrorContains(err, "Linux 6.7+"))
}

func linkExists(ctx context.Context, t *testing.T, name string) bool {
	t.Helper()
	result := testutil.RunCommand(ctx, "ip", "link", "show", name)
	return result.ExitCode == icmd.Success.ExitCode
}
