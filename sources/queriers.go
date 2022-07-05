package sources

import (
	"context"
	"sync"

	"github.com/shlin168/sdfinder/sources/base"
)

// Queriers stores all the enabled sources
type Queriers []*Querier

// Querier wrap base.SubdomainFinder with input and output channel for concurrency
// multiple goroutines (controlled by '-worker') consume query from Querier.In
// and output the result to Querier.Out
type Querier struct {
	Name   string
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

// Result is the API query result for each domain(ip), with result subdomains in list,
// which is flatten to OutRecord for json line file
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
	q := Queriers{}
	for _, sdf := range sfs {
		q = append(q, &Querier{
			Name:   sdf.Name(),
			Client: sdf,
			In:     make(chan Query),
			Out:    make(chan Result),
		})
	}
	return q
}

func (q Queriers) CollectStat() map[string]base.Stat {
	stat := make(map[string]base.Stat)
	for _, item := range q {
		stat[item.Name] = *item.Client.GetStat()
	}
	return stat
}

func (q Queriers) GetNames(filter func(item *Querier) bool) []string {
	var result []string
	for _, item := range q {
		if filter == nil || filter(item) {
			result = append(result, item.Name)
		}
	}
	return result
}

func (q Queriers) Iter(f func(item *Querier), filter func(item *Querier) bool) {
	for _, item := range q {
		if filter == nil || filter(item) {
			f(item)
		}
	}
}

func (q Queriers) Send(qItem Query, filter func(item *Querier) bool) {
	q.Iter(func(item *Querier) { item.In <- qItem }, filter)
}

func (q Queriers) StartWorkers(ctx context.Context, filter func(item *Querier) bool) {
	q.Iter(func(item *Querier) {
		var wg sync.WaitGroup
		wg.Add(item.Client.Workers())
		for i := 0; i < item.Client.Workers(); i++ {
			go func(item *Querier, wg *sync.WaitGroup) {
				rm := item.Client.RelatedMethod() + "/" + string(item.Name)
				rt := item.Client.RelatedType()
				for query := range item.In {
					result := Result{
						Domain:         query.Domain,
						RelationMethod: rm,
						RelationType:   rt,
						IType:          base.InputDomain,
					}
					if item.Client.ServeType() == base.InputDomain {
						result.Subdomains, result.Err = item.Client.Get(ctx, query.Domain)
					} else if item.Client.ServeType() == base.InputIP {
						result.Subdomains, result.Err = item.Client.Get(ctx, query.IP)
						result.IP, result.IType = query.IP, base.InputIP
					}
					item.Out <- result
				}
				wg.Done()
			}(item, &wg)
		}
		go func(item *Querier, wg *sync.WaitGroup) {
			wg.Wait()
			close(item.Out)
		}(item, &wg)
	}, filter)
}

func (q Queriers) Aggr() (outChan chan Result) {
	outChan = make(chan Result)
	var wg sync.WaitGroup
	wg.Add(len(q))
	q.Iter(func(item *Querier) {
		go func(item *Querier, wg *sync.WaitGroup) {
			for rst := range item.Out {
				outChan <- rst
			}
			wg.Done()
		}(item, &wg)
	}, nil)
	go func() {
		wg.Wait()
		close(outChan)
	}()
	return outChan
}

func (q Queriers) Close(filter func(item *Querier) bool) {
	q.Iter(func(item *Querier) { close(item.In) }, filter)
}
