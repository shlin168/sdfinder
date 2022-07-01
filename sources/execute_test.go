package sources

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/sdfinder/sources/base"
)

func TestExecute(t *testing.T) {
	sdnames := []string{"test1", "test2", "test3"}
	base.MustRegister("test1", &Test1{SDFinder: *base.NewSDFinder()})
	base.MustRegister("test2", &Test2{SDFinder: *base.NewSDFinder()})
	base.MustRegister("test3", &Test3{SDFinder: *base.NewSDFinder()})
	testqs := []base.SubdomainFinder{}
	for _, name := range sdnames {
		testqs = append(testqs, base.SDFinderMap[name])
	}
	cfg := GenDefaultConfig(sdnames, 1)
	exc, err := NewExecutorWithConfig(cfg)
	require.NoError(t, err)
	exc.Querier = NewQueriers(testqs...)
	assert.Equal(t, len(testqs), len(exc.Querier))

	exc.StartWorkers(context.Background())
	qChan := make(chan Query)
	resultChan := exc.SendToQueriersAndAggr(context.Background(), qChan)
	go func() {
		qChan <- Query{Domain: "abc.com", IP: "111.222.111.222"}
		close(qChan)
	}()
	outChan := exc.FlattenOutput(resultChan)
	var get []OutRecord
	for out := range outChan {
		get = append(get, out)
	}
	sort.Slice(get, func(i, j int) bool {
		return get[i].SubDomain < get[j].SubDomain
	})
	exp := []OutRecord{
		{
			Domain:    "abc.com",
			SubDomain: "abc.abc.com",
			RLPMethod: "related1/test1",
			RLPType:   base.RLPSubdomain,
		}, {
			Domain:    "abc.com",
			SubDomain: "cde.abc.com",
			RLPMethod: "related1/test1",
			RLPType:   base.RLPSubdomain,
		}, {
			Domain:    "abc.com",
			SubDomain: "rvsip.abc.com",
			RLPMethod: "related3/test3",
			RLPType:   base.RLPRelatedDomain,
			ExInfo:    map[string]string{"ip": "111.222.111.222"},
		}, {
			Domain:    "abc.com",
			SubDomain: "test.abc.com",
			RLPMethod: "related2/test2",
			RLPType:   base.RLPSubdomain,
		},
	}
	assert.Equal(t, exp, get)
	exc.CollectStat()
	assert.Equal(t, uint64(1), exc.Stat.DomainsCnt)
	assert.Equal(t, uint64(1), exc.Stat.IPsCnt)
	assert.Equal(t, uint64(4), exc.Stat.SubDomainsCnt)
	assert.Equal(t, uint64(4), exc.Stat.TotalOutputRow)
	assert.Equal(t, 3, len(exc.Stat.Finder))
	statMap := exc.Stat.Finder
	assert.Equal(t, uint64(1), statMap["test1"].DomainsCnt)
	assert.Equal(t, uint64(1), statMap["test1"].SuccessCnt)
	assert.Equal(t, uint64(2), statMap["test1"].RelatedDomainCnt)
	assert.Equal(t, uint64(1), statMap["test2"].DomainsCnt)
	assert.Equal(t, uint64(1), statMap["test2"].SuccessCnt)
	assert.Equal(t, uint64(1), statMap["test2"].RelatedDomainCnt)
	assert.Equal(t, uint64(1), statMap["test3"].DomainsCnt)
	assert.Equal(t, uint64(1), statMap["test3"].SuccessCnt)
	assert.Equal(t, uint64(1), statMap["test3"].RelatedDomainCnt)
}
