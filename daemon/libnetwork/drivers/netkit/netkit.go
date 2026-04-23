//go:build linux

package netkit

import (
	"context"
	"net"
	"sync"

	"github.com/moby/moby/v2/daemon/libnetwork/datastore"
	"github.com/moby/moby/v2/daemon/libnetwork/driverapi"
	"github.com/moby/moby/v2/daemon/libnetwork/drivers/bridge"
	"github.com/moby/moby/v2/daemon/libnetwork/drvregistry"
	"github.com/moby/moby/v2/daemon/libnetwork/portmapperapi"
	"github.com/moby/moby/v2/daemon/libnetwork/scope"
	"github.com/moby/moby/v2/daemon/libnetwork/types"
)

type driver struct {
	store *datastore.Store

	portmappers         *drvregistry.PortMappers
	bridgeConfig        bridge.Configuration
	newPortRuntime      func(context.Context, string) (publishedPortRuntime, error)
	datapath            publishedPortDatapath
	datapathEndpoints   map[string]struct{}
	newEndpointDatapath func(context.Context) (endpointNetkitDatapath, error)
	endpointDatapath    endpointNetkitDatapath

	mu       sync.Mutex
	networks map[string]*network
	parents  map[string]*parentRuntime

	configNetwork sync.Mutex

	probeOnce sync.Once
	probeErr  error
	probe     func() error
}

type endpoint struct {
	id      string
	nid     string
	mac     net.HardwareAddr
	addr    *net.IPNet
	addrv6  *net.IPNet
	srcName string
	hostIf  string

	extConnConfig    *connectivityConfiguration
	portMapping      []portmapperapi.PortBinding
	portBindingState portBindingMode
	publishedParent  string

	dbIndex  uint64
	dbExists bool
}

type network struct {
	id     string
	driver *driver
	config *configuration

	mu        sync.Mutex
	endpoints map[string]*endpoint
}

type connectivityConfiguration struct {
	PortBindings []portmapperapi.PortBindingReq
	ExposedPorts []types.TransportPort
}

type portBindingMode struct {
	routed bool
	ipv4   bool
	ipv6   bool
}

type publishedPortRequest struct {
	Addr         *net.IPNet
	Addrv6       *net.IPNet
	PortBindings []portmapperapi.PortBindingReq
	Current      []portmapperapi.PortBinding
	CurrentMode  portBindingMode
	DesiredMode  portBindingMode
}

type publishedPortRuntime interface {
	AddEndpoint(ctx context.Context, ep4, ep6 *net.IPNet) error
	DelEndpoint(ctx context.Context, ep4, ep6 *net.IPNet) error
	ReconcilePortBindings(ctx context.Context, req publishedPortRequest) ([]portmapperapi.PortBinding, error)
	ReleasePortBindings(ctx context.Context, bindings []portmapperapi.PortBinding) error
	ClearConntrack(ep4, ep6 *net.IPNet, bindings []portmapperapi.PortBinding)
	Close(ctx context.Context) error
}

type parentRuntime struct {
	parent  string
	runtime publishedPortRuntime
	refs    int
}

func Register(r driverapi.Registerer, store *datastore.Store, pms *drvregistry.PortMappers, config bridge.Configuration) error {
	d := &driver{
		store:             store,
		portmappers:       pms,
		bridgeConfig:      config,
		networks:          map[string]*network{},
		parents:           map[string]*parentRuntime{},
		datapathEndpoints: map[string]struct{}{},
	}
	d.probe = d.probeNetkitSupport

	if err := d.initStore(); err != nil {
		return err
	}

	return r.RegisterDriver(NetworkType, d, driverapi.Capability{
		DataScope:         scope.Local,
		ConnectivityScope: scope.Global,
	})
}

func (d *driver) EndpointOperInfo(nid, eid string) (map[string]any, error) {
	return map[string]any{}, nil
}

func (d *driver) Type() string {
	return NetworkType
}

func (d *driver) IsBuiltIn() bool {
	return true
}
