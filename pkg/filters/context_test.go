package filters

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextFilterClone(t *testing.T) {
	t.Parallel()

	filter := NewContextFilter()
	err := filter.Parse("openat.context.processorId", "=0")
	require.NoError(t, err)

	cloneInterface := filter.Clone()
	copy, ok := cloneInterface.(*ContextFilter)
	if !ok {
		t.Errorf("Clone did not return an *ContextFilter")
	}

	if !reflect.DeepEqual(filter, copy) {
		t.Errorf("Clone did not produce an identical copy")
	}

	// ensure that changes to the copy do not affect the original
	err = copy.Parse("openat.context.pid", "=1")
	require.NoError(t, err)
	if reflect.DeepEqual(filter, copy) {
		t.Errorf("Changes to copied filter affected the original")
	}
}
