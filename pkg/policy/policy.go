package policy

import (
	"golang.org/x/exp/maps"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/aquasecurity/tracee/pkg/utils"
)

type Policy struct {
	ID                int
	Name              string
	EventsToTrace     map[events.ID]string
	UIDFilter         *filters.UIntFilter[uint32]
	PIDFilter         *filters.UIntFilter[uint32]
	NewPidFilter      *filters.BoolFilter
	MntNSFilter       *filters.UIntFilter[uint64]
	PidNSFilter       *filters.UIntFilter[uint64]
	UTSFilter         *filters.StringFilter
	CommFilter        *filters.StringFilter
	ContFilter        *filters.BoolFilter
	NewContFilter     *filters.BoolFilter
	ContIDFilter      *filters.StringFilter
	RetFilter         *filters.RetFilter
	ArgFilter         *filters.ArgFilter
	ContextFilter     *filters.ContextFilter
	ProcessTreeFilter *filters.ProcessTreeFilter
	BinaryFilter      *filters.BinaryFilter
	Follow            bool
}

func NewPolicy() *Policy {
	return &Policy{
		ID:                0,
		Name:              "",
		EventsToTrace:     map[events.ID]string{},
		UIDFilter:         filters.NewUInt32Filter(),
		PIDFilter:         filters.NewUInt32Filter(),
		NewPidFilter:      filters.NewBoolFilter(),
		MntNSFilter:       filters.NewUIntFilter(),
		PidNSFilter:       filters.NewUIntFilter(),
		UTSFilter:         filters.NewStringFilter(),
		CommFilter:        filters.NewStringFilter(),
		ContFilter:        filters.NewBoolFilter(),
		NewContFilter:     filters.NewBoolFilter(),
		ContIDFilter:      filters.NewStringFilter(),
		RetFilter:         filters.NewRetFilter(),
		ArgFilter:         filters.NewArgFilter(),
		ContextFilter:     filters.NewContextFilter(),
		ProcessTreeFilter: filters.NewProcessTreeFilter(),
		BinaryFilter:      filters.NewBinaryFilter(),
		Follow:            false,
	}
}

// ContainerFilterEnabled returns true when the policy has at least one container filter type enabled
func (p *Policy) ContainerFilterEnabled() bool {
	return (p.ContFilter.Enabled() && p.ContFilter.Value()) ||
		(p.NewContFilter.Enabled() && p.NewContFilter.Value()) ||
		p.ContIDFilter.Enabled()
}

func (p *Policy) Clone() (utils.Cloner, error) {
	if p == nil {
		return nil
	}

	n := NewPolicy()

	n.ID = p.ID
	n.Name = p.Name
	maps.Copy(n.EventsToTrace, p.EventsToTrace)
	if n.UIDFilter, err = cloneAndAssert[*UIntFilter[uint32]](p.UIDFilter); err != nil {
		return err
	}
	if n.PIDFilter, err = cloneAndAssert[*UIntFilter[uint32]](p.PIDFilter); err != nil {
		return err
	}
	if n.NewPidFilter, err = cloneAndAssert[*BoolFilter](p.NewPidFilter); err != nil {
		return err
	}
	if n.MntNSFilter, err = cloneAndAssert[*UIntFilter[uint64]](p.MntNSFilter); err != nil {
		return err
	}
	if n.PidNSFilter, err = cloneAndAssert[*UIntFilter[uint64]](p.PidNSFilter); err != nil {
		return err
	}
	if n.UTSFilter, err = cloneAndAssert[*StringFilter](p.UTSFilter); err != nil {
		return err
	}
	if n.CommFilter, err = cloneAndAssert[*StringFilter](p.CommFilter); err != nil {
		return err
	}
	if n.ContFilter, err = cloneAndAssert[*BoolFilter](p.ContFilter); err != nil {
		return err
	}
	if n.NewContFilter, err = cloneAndAssert[*BoolFilter](p.NewContFilter); err != nil {
		return err
	}
	if n.ContIDFilter, err = cloneAndAssert[*StringFilter](p.ContIDFilter); err != nil {
		return err
	}
	if n.RetFilter, err = cloneAndAssert[*RetFilter](p.RetFilter); err != nil {
		return err
	}
	if n.ArgFilter, err = cloneAndAssert[*ArgFilter](p.ArgFilter); err != nil {
		return err
	}
	if n.ContextFilter, err = cloneAndAssert[*ContextFilter](p.ContextFilter); err != nil {
		return err
	}
	if n.ProcessTreeFilter, err = cloneAndAssert[*ProcessTreeFilter](p.ProcessTreeFilter); err != nil {
		return err
	}
	if n.BinaryFilter, err = cloneAndAssert[*BinaryFilter](p.BinaryFilter); err != nil {
		return err
	}
	n.Follow = p.Follow

	return n
}
