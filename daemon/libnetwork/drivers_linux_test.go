//go:build linux

package libnetwork

import (
	"context"
	"net"
	"testing"

	"github.com/moby/moby/v2/daemon/libnetwork/config"
	"github.com/moby/moby/v2/daemon/libnetwork/drvregistry"
	"github.com/moby/moby/v2/daemon/libnetwork/portmapperapi"
	"github.com/moby/moby/v2/daemon/libnetwork/types"
	"gotest.tools/v3/assert"
)

func TestRegisterPortMappersRootfulNatDoesNotInstallRootlessPortDriver(t *testing.T) {
	var pms drvregistry.PortMappers
	assert.NilError(t, registerPortMappers(context.Background(), &pms, config.New(config.OptionRootless(false))))

	pm, err := pms.Get("nat")
	assert.NilError(t, err)

	pbs, err := pm.MapPorts(context.Background(), []portmapperapi.PortBindingReq{{
		PortBinding: types.PortBinding{
			Proto:       types.TCP,
			HostIP:      net.IPv4(127, 0, 0, 1),
			HostPort:    0,
			HostPortEnd: 0,
			Port:        80,
		},
	}})
	assert.NilError(t, err)
	t.Cleanup(func() {
		assert.NilError(t, pm.UnmapPorts(context.Background(), pbs))
	})

	assert.Check(t, pbs[0].PortDriverRemove == nil)
}
