//go:build linux

package netkit

import (
	"fmt"
	"net"

	"github.com/moby/moby/v2/daemon/libnetwork/ns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

var createNetkitFn = createNetkit

func createNetkit(hostIfName, containerIfName, parent, sboxKey string, mac net.HardwareAddr) error {
	_ = parent
	_ = mac

	netnsh, err := netns.GetFromPath(sboxKey)
	if err != nil {
		return fmt.Errorf("failed to open sandbox netns %q: %w", sboxKey, err)
	}
	defer netnsh.Close()

	// Scrub and PeerScrub must be set explicitly: the netlink library
	// always serialises these attributes, and the Go zero value maps to
	// NETKIT_SCRUB_NONE, which would silently override the kernel's
	// NETKIT_SCRUB_DEFAULT and leak skb->mark / skb->priority across
	// netns. These attributes are create-time only and cannot be changed
	// after the device exists.
	nk := &netlink.Netkit{
		LinkAttrs:  netlink.LinkAttrs{Name: hostIfName, TxQLen: 0},
		Mode:       netlink.NETKIT_MODE_L3,
		Policy:     netlink.NETKIT_POLICY_BLACKHOLE,
		PeerPolicy: netlink.NETKIT_POLICY_BLACKHOLE,
		Scrub:      netlink.NETKIT_SCRUB_DEFAULT,
		PeerScrub:  netlink.NETKIT_SCRUB_DEFAULT,
	}

	peerAttrs := &netlink.LinkAttrs{
		Name:      containerIfName,
		Namespace: netlink.NsFd(netnsh),
	}
	nk.SetPeerAttrs(peerAttrs)

	if err := ns.NlHandle().LinkAdd(nk); err != nil {
		return fmt.Errorf("failed to create netkit pair %s/%s: %w", hostIfName, containerIfName, err)
	}

	hostLink, err := ns.NlHandle().LinkByName(hostIfName)
	if err != nil {
		return fmt.Errorf("failed to find netkit primary %s: %w", hostIfName, err)
	}
	if err := ns.NlHandle().LinkSetUp(hostLink); err != nil {
		_ = ns.NlHandle().LinkDel(hostLink)
		return fmt.Errorf("failed to bring up netkit primary %s: %w", hostIfName, err)
	}
	return nil
}
