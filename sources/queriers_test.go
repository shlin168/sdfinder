package sources

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/shlin168/sdfinder/sources/base"
)

type Test1 struct{ base.SDFinder }

func (t1 *Test1) Get(ctx context.Context, domain string) (subdomains []string, err error) {
	defer func() { t1.RecordStat(subdomains, err) }()
	return []string{"abc.abc.com", "cde.abc.com"}, nil
}

func (Test1) Name() string { return "test1" }

func (Test1) RelatedMethod() string { return "related1" }

type Test2 struct{ base.SDFinder }

func (t2 *Test2) Get(ctx context.Context, domain string) (subdomains []string, err error) {
	defer func() { t2.RecordStat(subdomains, err) }()
	return []string{"test.abc.com"}, nil
}

func (Test2) Name() string { return "test2" }

func (Test2) RelatedMethod() string { return "related2" }

type Test3 struct{ base.SDFinder }

func (t3 *Test3) Get(ctx context.Context, ip string) (subdomains []string, err error) {
	defer func() { t3.RecordStat(subdomains, err) }()
	return []string{"rvsip.abc.com"}, nil
}

func (Test3) Name() string { return "test3" }

func (Test3) RelatedMethod() string { return "related3" }

func (Test3) RelatedType() string { return base.RLPRelatedDomain }

func (Test3) ServeType() base.InputType {
	return base.InputIP
}

func TestQueriers(t *testing.T) {
	sdFinder := base.NewSDFinder()
	sdFinder2 := base.NewSDFinder()
	sdFinder3 := base.NewSDFinder()
	testqs := []base.SubdomainFinder{&Test1{SDFinder: *sdFinder}, &Test2{SDFinder: *sdFinder2}, &Test3{SDFinder: *sdFinder3}}
	qs := NewQueriers(testqs...)
	assert.Equal(t, len(testqs), len(qs))

	var total int
	qs.Iter(func(*Querier) { total++ }, nil)
	assert.Equal(t, 3, total)

	total = 0
	filterT1 := func(item *Querier) bool { return item.Name == "test1" }
	qs.Iter(func(*Querier) { total++ }, filterT1)
	assert.Equal(t, 1, total)

	names := qs.GetNames(nil)
	sort.Strings(names)
	assert.Equal(t, []string{"test1", "test2", "test3"}, names)
	assert.Equal(t, []string{"test1"}, qs.GetNames(filterT1))

	qs.StartWorkers(context.Background(), nil)
	go func() {
		qs.Send(Query{Domain: "abc.com", IP: "111.222.111.222"}, nil)
		qs.Close(nil)
	}()
	var msg []Result
	for out := range qs.Aggr() {
		msg = append(msg, out)
	}
	sort.Slice(msg, func(i, j int) bool {
		return msg[i].RelationMethod < msg[j].RelationMethod
	})
	exp := []Result{
		{
			Domain:         "abc.com",
			Subdomains:     []string{"abc.abc.com", "cde.abc.com"},
			RelationMethod: "related1/test1",
			RelationType:   base.RLPSubdomain,
			IType:          base.InputDomain,
		}, {
			Domain:         "abc.com",
			Subdomains:     []string{"test.abc.com"},
			RelationMethod: "related2/test2",
			RelationType:   base.RLPSubdomain,
			IType:          base.InputDomain,
		}, {
			Domain:         "abc.com",
			IP:             "111.222.111.222",
			Subdomains:     []string{"rvsip.abc.com"},
			RelationMethod: "related3/test3",
			RelationType:   base.RLPRelatedDomain,
			IType:          base.InputIP,
		},
	}
	assert.Equal(t, exp, msg)

	statMap := qs.CollectStat()
	assert.Equal(t, 3, len(statMap))
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
