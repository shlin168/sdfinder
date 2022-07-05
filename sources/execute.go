package sources

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/shlin168/sdfinder/sources/base"
)

// Executor controls the workflow from given domain/ip to the result
// which has a global view among all the sources
type Executor struct {
	Querier      Queriers
	UniDomain    map[string]struct{} // dedup domain for queriers that take domain as input
	UniIP        map[string]struct{} // dedup ip for queriers that take domain as input
	UniSubDomain map[string]struct{} // dedup subdomain
	Stat         *Stat
}

// OutRecord is the json line format in output file
type OutRecord struct {
	Domain    string            `json:"root_domain"`
	SubDomain string            `json:"domain"`
	RLPMethod string            `json:"method"`
	RLPType   string            `json:"type"`
	ExInfo    map[string]string `json:"extra_info"`
}

// Stat records the statistic information for all query results
type Stat struct {
	DomainsCnt     uint64               `json:"domain,omitempty"`    // unique domains
	IPsCnt         uint64               `json:"ip,omitempty"`        // unique ips
	Finder         map[string]base.Stat `json:"detail,omitempty"`    // detail info of each finder
	SubDomainsCnt  uint64               `json:"subdomain,omitempty"` // unique subdomains
	TotalOutputRow uint64               `json:"out_rows,omitempty"`
}

// NewExecutorWithConfig initialize executor from name of source with default config
// if no name of source if given, using all available sources
func NewExecutor(worker int, sdns ...string) (*Executor, error) {
	if len(sdns) == 0 {
		var defaultSDFinders []string
		for name := range base.SDFinderMap {
			defaultSDFinders = append(defaultSDFinders, name)
		}
		sdns = defaultSDFinders
	}
	cfg := GenDefaultConfig(sdns, worker)
	return NewExecutorWithConfig(cfg)
}

// NewExecutorWithConfig initialize executor from config
func NewExecutorWithConfig(cfg *Config) (*Executor, error) {
	sdfinders := cfg.Init()
	if len(sdfinders) == 0 {
		return nil, fmt.Errorf("no sources init success")
	}
	e := &Executor{
		Querier:      NewQueriers(sdfinders...),
		Stat:         new(Stat),
		UniDomain:    make(map[string]struct{}),
		UniSubDomain: make(map[string]struct{}),
	}
	if len(e.Querier) == 0 {
		return nil, fmt.Errorf("no client init success")
	}
	ipOnly := func(item *Querier) bool { return item.Client.ServeType() == base.InputIP }
	if len(e.Querier.GetNames(ipOnly)) > 0 {
		e.UniIP = make(map[string]struct{})
	}
	logrus.Infof("init queriers: %v", e.Querier.GetNames(nil))
	e.Stat.Finder = make(map[string]base.Stat)
	return e, nil
}

// StartWorkers starts workers for every querier
func (e *Executor) StartWorkers(ctx context.Context) {
	e.Querier.StartWorkers(ctx, nil)
}

// CollectStat collects query information from all queriers,
// which should be invoked after all the queriers finish their jobs
func (e *Executor) CollectStat() {
	e.Stat.Finder = e.Querier.CollectStat()
}

// SendToQueriersAndAggr get the Query item from channel,
// send Query.Domain to queriers that serve domains, also send Query.IP to queriers that server IPs
// If domain or ip has been sent before, it will be skipped.
// The results from queriers are all sent to return channel for further processing
func (e *Executor) SendToQueriersAndAggr(ctx context.Context, qChan <-chan Query) chan Result {
	domainOnly := func(item *Querier) bool { return item.Client.ServeType() == base.InputDomain }
	domainQuerierNames := e.Querier.GetNames(domainOnly)
	ipOnly := func(item *Querier) bool { return item.Client.ServeType() == base.InputIP }
	ipQuerierNames := e.Querier.GetNames(ipOnly)
	go func() {
		for qItem := range qChan {
			// send queries to all domains finders
			if len(domainQuerierNames) > 0 {
				if _, hasseen := e.UniDomain[qItem.Domain]; !hasseen {
					e.UniDomain[qItem.Domain] = struct{}{}
					atomic.AddUint64(&e.Stat.DomainsCnt, 1)
					e.Querier.Send(qItem, domainOnly)
				}
			}
			// send queries to all ip finders
			if len(ipQuerierNames) > 0 {
				if _, hasseen := e.UniIP[qItem.IP]; !hasseen {
					e.UniIP[qItem.IP] = struct{}{}
					atomic.AddUint64(&e.Stat.IPsCnt, 1)
					e.Querier.Send(qItem, ipOnly)
				}
			}
		}
		e.Querier.Close(nil)
	}()
	// aggreate results and sends to one output channel
	return e.Querier.Aggr()
}

// FlattenOutput flattens the output from one line to multiple line
// [before] root_domain: 'google.com', subdomains: ['abc.google.com', 'abcd.google.com']
// [after]  root_domain: 'google.com', domain: 'abc.google.com'
//          root_domain: 'google.com', domain: 'abcd.google.com'
func (e *Executor) FlattenOutput(inChan chan Result) <-chan OutRecord {
	outChan := make(chan OutRecord)
	go func() {
		for sd := range inChan {
			if sd.Err != nil {
				switch sd.IType {
				case base.InputDomain:
					logrus.WithFields(logrus.Fields{"method": sd.RelationMethod, "domain": sd.Domain}).WithError(sd.Err).Warn("query")
				case base.InputIP:
					logrus.WithFields(logrus.Fields{"method": sd.RelationMethod, "ip": sd.IP}).WithError(sd.Err).Warn("query")
				}
				continue
			}
			for _, subdomain := range sd.Subdomains {
				if _, hasseen := e.UniSubDomain[subdomain]; !hasseen {
					atomic.AddUint64(&e.Stat.SubDomainsCnt, 1)
					e.UniSubDomain[subdomain] = struct{}{}
				}
				out := OutRecord{
					Domain:    sd.Domain,
					SubDomain: subdomain,
					RLPMethod: sd.RelationMethod,
					RLPType:   sd.RelationType,
				}
				if sd.IType == base.InputIP {
					out.ExInfo = map[string]string{"ip": sd.IP}
				}
				// change related method the 'related domain' if subdomain is not end with domain
				if !strings.HasSuffix(subdomain, "."+sd.Domain) {
					out.RLPType = base.RLPRelatedDomain
				}
				atomic.AddUint64(&e.Stat.TotalOutputRow, uint64(1))
				outChan <- out
			}
		}
		close(outChan)
	}()
	return outChan
}
