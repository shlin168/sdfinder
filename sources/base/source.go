package base

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const (
	DefaultQPS     = 1.0
	DefaultTimeout = 5 * time.Second
	DefaultWorker  = 1

	RLPRelatedDomain = "related-domain"
	RLPSubdomain     = "subdomain"
	RLPRvsDNS        = "reverse"

	FromCrawl = "crawl"
	FromAPI   = "api"
	FromCert  = "cert"
)

type InputType int

const (
	InputDomain InputType = iota
	InputIP
)

// SDFinderMap stores all available sources, while 'SubdomainFinder.Init(opts...)' is needed
// to actually let SubdomainFinder ready for work
var SDFinderMap = make(map[string]SubdomainFinder)

// MustRegister registers subdomain finder to 'SDFinderMap'
func MustRegister(sdname string, sdfinder SubdomainFinder) {
	if _, exist := SDFinderMap[sdname]; exist {
		panic(sdname + "has been registered")
	}
	SDFinderMap[sdname] = sdfinder
}

type SubdomainFinder interface {
	Init(...Option) error
	Get(context.Context, string) ([]string, error)
	Name() string
	ServeType() InputType
	RelatedMethod() string // reverse-whois/org, api/sublist3r, ...
	RelatedType() string   // related-domain, subdomains, ...
	GetStat() *Stat
	Workers() int
}

type SDFinder struct {
	RLimiter        *rate.Limiter
	Client          *http.Client
	Header          *http.Header
	URLbuilder      func(string) string // build different url base on input domain
	Parse           func([]byte) ([]string, error)
	TimeAfter       time.Time
	Stat            *Stat
	RetriesTimes    int
	RetriesInterval time.Duration
	Worker          int
}

type Stat struct {
	DomainsCnt       uint64 `json:"domain"` // total unique domains
	SuccessCnt       uint64 `json:"success,omitempty"`
	FoundCnt         uint64 `json:"found,omitempty"`
	NotFoundCnt      uint64 `json:"notfound,omitempty"`
	TimeoutCnt       uint64 `json:"timeout,omitempty"`
	ErrCnt           uint64 `json:"error,omitempty"`
	RelatedDomainCnt uint64 `json:"related"` // total related domain count (filter duplicate)
}

type Option func(*SDFinder) error

func NewSDFinder() *SDFinder {
	return &SDFinder{
		RLimiter: rate.NewLimiter(DefaultQPS, 1),
		Client:   &http.Client{Timeout: DefaultTimeout},
		Stat:     new(Stat),
		Worker:   DefaultWorker,
	}
}

func (sdf *SDFinder) Init(opts ...Option) error {
	for _, opt := range opts {
		if err := opt(sdf); err != nil {
			return err
		}
	}
	return nil
}

func QPS(qps float64) Option {
	return func(sdf *SDFinder) error {
		if qps <= 0 {
			return fmt.Errorf("qps should be positive")
		}
		sdf.RLimiter = rate.NewLimiter(rate.Limit(qps), 1)
		return nil
	}
}

func Timeout(timeout time.Duration) Option {
	return func(sdf *SDFinder) error {
		if timeout <= 0 {
			return fmt.Errorf("timeout should > 0s")
		}
		sdf.Client.Timeout = timeout
		return nil
	}
}

func Header(key, val string) Option {
	return func(sdf *SDFinder) error {
		if sdf.Header == nil {
			sdf.Header = &http.Header{}
		}
		sdf.Header.Set(key, val)
		return nil
	}
}

func TimeAfter(ta time.Time) Option {
	return func(sdf *SDFinder) error {
		sdf.TimeAfter = ta
		return nil
	}
}

func UrlBuilder(f func(string) string) Option {
	return func(sdf *SDFinder) error {
		if f == nil {
			return fmt.Errorf("empty url builder function")
		}
		sdf.URLbuilder = f
		return nil
	}
}

func Parse(f func([]byte) ([]string, error)) Option {
	return func(sdf *SDFinder) error {
		if f == nil {
			return fmt.Errorf("empty parse function")
		}
		sdf.Parse = f
		return nil
	}
}

func Retries(retries int, interval time.Duration) Option {
	return func(sdf *SDFinder) error {
		if retries < 0 {
			return fmt.Errorf("retries should >= 0")
		}
		if retries > 0 && interval <= 0 {
			return fmt.Errorf("retries interval should >= 0 when retries > 0")
		}
		sdf.RetriesTimes = retries
		sdf.RetriesInterval = interval
		return nil
	}
}

func Worker(num int) Option {
	return func(sdf *SDFinder) error {
		if num <= 0 {
			return fmt.Errorf("worker should > 0")
		}
		sdf.Worker = num
		return nil
	}
}

func (sdf SDFinder) Name() string {
	return "base"
}

func (sdf SDFinder) ServeType() InputType {
	return InputDomain
}

func (sdf SDFinder) RelatedMethod() string {
	return FromAPI
}

func (sdf SDFinder) RelatedType() string {
	return RLPSubdomain
}

func (sdf SDFinder) GetStat() *Stat {
	return sdf.Stat
}

func (sdf SDFinder) Workers() int {
	return sdf.Worker
}

// IsTimeout return whether an error is classified as **timeout** error
func IsTimeout(err error) bool {
	if err, ok := err.(net.Error); (ok && err.Timeout()) || os.IsTimeout(err) {
		return true
	}
	return false
}

func (sdf *SDFinder) RecordStat(subdomains []string, err error) {
	atomic.AddUint64(&sdf.Stat.DomainsCnt, uint64(1))
	if err != nil {
		if IsTimeout(err) {
			atomic.AddUint64(&sdf.Stat.TimeoutCnt, uint64(1))
		} else {
			atomic.AddUint64(&sdf.Stat.ErrCnt, uint64(1))
		}
	} else {
		atomic.AddUint64(&sdf.Stat.SuccessCnt, uint64(1))
		if len(subdomains) > 0 {
			atomic.AddUint64(&sdf.Stat.FoundCnt, uint64(1))
		} else {
			atomic.AddUint64(&sdf.Stat.NotFoundCnt, uint64(1))
		}
		atomic.AddUint64(&sdf.Stat.RelatedDomainCnt, uint64(len(subdomains)))
	}
}

func (sdf *SDFinder) Do(ctx context.Context, url string) ([]byte, error) {
	err := sdf.RLimiter.Wait(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if sdf.Header != nil {
		req.Header = *sdf.Header
	}
	rsp, err := sdf.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get rsp code: %d", rsp.StatusCode)
	}
	content, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func (sdf *SDFinder) Get(ctx context.Context, domain string) (subdomains []string, err error) {
	defer func() {
		sdf.RecordStat(subdomains, err)
	}()
	uniDomainMap := make(map[string]struct{})
	retryTimes := sdf.RetriesTimes
	for retryTimes >= 0 {
		retryTimes--
		content, err := sdf.Do(ctx, sdf.URLbuilder(domain))
		if err != nil {
			if retryTimes < 0 {
				return subdomains, err // retry n times and failed
			}
			time.Sleep(sdf.RetriesInterval)
			continue
		}
		sbs, err := sdf.Parse(content)
		if err != nil {
			return subdomains, err // no need to retry
		}
		// convert to lowercase and deduplicate using map
		for _, sb := range sbs {
			sblower := strings.ToLower(sb)
			uniDomainMap[sblower] = struct{}{}
		}
	}
	for sb := range uniDomainMap {
		subdomains = append(subdomains, sb)
	}
	return subdomains, nil
}
