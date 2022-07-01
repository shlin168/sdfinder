package sources

import (
	"context"
	"sync"

	"github.com/shlin168/sdfinder/sources/base"
)

// Queriers stores all the enabled sources
type Queriers map[string]Querier

// Querier wrap base.SubdomainFinder with input and output channel for concurrency
// multiple goroutines (controlled by '-worker') consume query from Querier.In
// and output the result from source to Querier.Out
type Querier struct {
	Client base.SubdomainFinder // Statistic info can be accessed by Client.GetStat()
	In     chan Query
	Out    chan Result
}

// Query is the message format that sent to Querier.In, Domain OR IP is used for query base on
// base.SubdomainFinder.RelatedType()
type Query struct {
	Domain string
	IP     string
}

// Result is the API query result for each domain(ip), with result subdomains in list, which is flatten to OutRecord
// for json line file
type Result struct {
	Domain         string
	IP             string
	Subdomains     []string
	RelationMethod string // cert/crtsh, api/sublist3r, ...
	RelationType   string // related-domain, subdomains, ...
	IType          base.InputType
	Err            error
}

func NewQueriers(sfs ...base.SubdomainFinder) Queriers {
	qMap := make(map[string]Querier)
	for _, sdf := range sfs {
		qMap[sdf.Name()] = Querier{Client: sdf, In: make(chan Query), Out: make(chan Result)}
	}
	return qMap
}

func (q Queriers) CollectStat() map[string]base.Stat {
	stat := make(map[string]base.Stat)
	for name := range q {
		stat[name] = *q[name].Client.GetStat()
	}
	return stat
}

func (q Queriers) GetNames(filter func(name string) bool) []string {
	var result []string
	for name := range q {
		if filter == nil || filter(name) {
			result = append(result, name)
		}
	}
	return result
}

func (q Queriers) Iter(f func(name string), filter func(name string) bool) {
	for name := range q {
		if filter == nil || filter(name) {
			f(name)
		}
	}
}

func (q Queriers) Send(qItem Query, filter func(name string) bool) {
	q.Iter(func(name string) { q[name].In <- qItem }, filter)
}

func (q Queriers) StartWorkers(ctx context.Context, filter func(name string) bool) {
	q.Iter(func(name string) {
		var wg sync.WaitGroup
		wg.Add(q[name].Client.Workers())
		for i := 0; i < q[name].Client.Workers(); i++ {
			go func(name string, wg *sync.WaitGroup) {
				for query := range q[name].In {
					result := Result{
						Domain:         query.Domain,
						RelationMethod: q[name].Client.RelatedMethod() + "/" + string(name),
						RelationType:   q[name].Client.RelatedType(),
						IType:          base.InputDomain,
					}
					if q[name].Client.ServeType() == base.InputDomain {
						result.Subdomains, result.Err = q[name].Client.Get(ctx, query.Domain)
					} else if q[name].Client.ServeType() == base.InputIP {
						result.Subdomains, result.Err = q[name].Client.Get(ctx, query.IP)
						result.IP, result.IType = query.IP, base.InputIP
					}
					q[name].Out <- result
				}
				wg.Done()
			}(name, &wg)
		}
		go func(name string, wg *sync.WaitGroup) {
			wg.Wait()
			close(q[name].Out)
		}(name, &wg)
	}, filter)
}

func (q Queriers) Aggr() (outChan chan Result) {
	outChan = make(chan Result)
	var wg sync.WaitGroup
	wg.Add(len(q))
	q.Iter(func(name string) {
		go func(name string, wg *sync.WaitGroup) {
			for rst := range q[name].Out {
				outChan <- rst
			}
			wg.Done()
		}(name, &wg)
	}, nil)
	go func() {
		wg.Wait()
		close(outChan)
	}()
	return outChan
}

func (q Queriers) Close(filter func(name string) bool) {
	for name := range q {
		if filter == nil || filter(name) {
			close(q[name].In)
		}
	}
}
