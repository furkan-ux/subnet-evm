// (c) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package testutils

import (
	"testing"
	"time"

	"github.com/ava-labs/subnet-evm/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// PredicateTest defines a unit test/benchmark for verifying a precompile predicate.
type PredicateTest struct {
	Config precompileconfig.Config

	PredicateContext *precompileconfig.PredicateContext

	StorageSlots         []byte
	Gas                  uint64
	GasErr, PredicateErr error
}

func (test PredicateTest) Run(t testing.TB) {
	t.Helper()
	require := require.New(t)

	var (
		gas                  uint64
		gasErr, predicateErr error
		predicate            = test.Config.(precompileconfig.Predicater)
	)

	gas, gasErr = predicate.PredicateGas(test.StorageSlots)
	if test.GasErr != nil {
		// If PredicateGas returns an error, the predicate fails verification and we will
		// never call VerifyPredicate.
		require.ErrorIs(gasErr, test.GasErr)
		return
	} else {
		require.NoError(gasErr)
	}
	require.Equal(test.Gas, gas)

	predicateErr = predicate.VerifyPredicate(test.PredicateContext, test.StorageSlots)
	if test.PredicateErr == nil {
		require.NoError(predicateErr)
	} else {
		require.ErrorIs(predicateErr, test.PredicateErr)
	}
}

func RunPredicateTests(t *testing.T, predicateTests map[string]PredicateTest) {
	t.Helper()

	for name, test := range predicateTests {
		t.Run(name, func(t *testing.T) {
			test.Run(t)
		})
	}
}

func (test PredicateTest) RunBenchmark(b *testing.B) {
	b.ReportAllocs()
	start := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		test.Run(b)
	}
	b.StopTimer()
	elapsed := uint64(time.Since(start))
	if elapsed < 1 {
		elapsed = 1
	}

	gasUsed := test.Gas * uint64(b.N)
	b.ReportMetric(float64(test.Gas), "gas/op")
	// Keep it as uint64, multiply 100 to get two digit float later
	mgasps := (100 * 1000 * gasUsed) / elapsed
	b.ReportMetric(float64(mgasps)/100, "mgas/s")
}

func RunPredicateBenchmarks(b *testing.B, predicateTests map[string]PredicateTest) {
	b.Helper()

	for name, test := range predicateTests {
		b.Run(name, func(b *testing.B) {
			test.RunBenchmark(b)
		})
	}
}
