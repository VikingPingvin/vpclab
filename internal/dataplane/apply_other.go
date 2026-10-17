//go:build !linux

package dataplane

import (
	"context"
	"errors"

	"github.com/VikingPingvin/vpclab/internal/plan"
)

type Options struct {
	RouterImage string
}

// Apply needs Linux network namespaces.
func Apply(context.Context, *plan.Plan, Options) error {
	return errors.New("the vpcsim data plane only runs on Linux")
}
