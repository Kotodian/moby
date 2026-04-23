//go:build linux

package environment

import "github.com/moby/moby/v2/pkg/parsers/kernel"

func IsNetkitSupported() bool {
	return kernel.CheckKernelVersion(6, 7, 0)
}
