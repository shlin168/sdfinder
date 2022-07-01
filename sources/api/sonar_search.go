package api

import (
	"context"
	"crypto/tls"

	pb "github.com/cgboal/sonarsearch/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/shlin168/sdfinder/sources/base"
)

// type: grpc
// rate limit: no
// github: https://github.com/Cgboal/SonarSearch/tree/ddd8c134e2e4a09ace434c5a76972c7895ebc58e
const NameSonarSearch = "sonarsearch/subdomains"
const NameSonarSearchRvs = "sonarsearch/reverse"

func init() {
	base.MustRegister(NameSonarSearch, NewSonarSearch())
	base.MustRegister(NameSonarSearchRvs, NewSonarSearchRvs())
}

type SonarSearch struct {
	base.SDFinder
	conn *grpc.ClientConn
	cli  pb.CrobatClient
}

func NewSonarSearch() *SonarSearch {
	return &SonarSearch{SDFinder: *base.NewSDFinder()}
}

func (ss *SonarSearch) Init(opts ...base.Option) error {
	config := &tls.Config{}
	ss.URLbuilder = func(domain string) string {
		return "crobat-rpc.omnisint.io:443"
	}
	var err error
	ss.conn, err = grpc.Dial(ss.URLbuilder(""), grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		return err
	}
	ss.cli = pb.NewCrobatClient(ss.conn)
	return ss.SDFinder.Init(opts...)
}

func (ss *SonarSearch) Close() error {
	return ss.conn.Close()
}

func (ss SonarSearch) Name() string {
	return NameSonarSearch
}

func (ss *SonarSearch) Get(ctx context.Context, domain string) (subdomains []string, err error) {
	defer func() {
		ss.RecordStat(subdomains, err)
	}()
	sbChan, err := ss.GetChan(ctx, domain)
	if err != nil {
		return nil, err
	}
	for sb := range sbChan {
		subdomains = append(subdomains, sb)
	}
	return subdomains, nil
}

func (ss *SonarSearch) GetChan(ctx context.Context, domain string) (chan string, error) {
	if err := ss.RLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	req := &pb.QueryRequest{Query: domain}
	res, err := ss.cli.GetSubdomains(ctx, req)
	if err != nil {
		return nil, err
	}
	resultChan := make(chan string)
	go func() {
		for {
			domain, err := res.Recv()
			if err != nil {
				close(resultChan)
				return
			}
			resultChan <- domain.Domain
		}
	}()
	return resultChan, nil
}

type SonarSearchRvs struct {
	SonarSearch
}

func NewSonarSearchRvs() *SonarSearchRvs {
	return &SonarSearchRvs{SonarSearch{SDFinder: *base.NewSDFinder()}}
}

func (ssr *SonarSearchRvs) Init(opts ...base.Option) error {
	return ssr.SonarSearch.Init(opts...)
}

func (ssr SonarSearchRvs) ServeType() base.InputType {
	return base.InputIP
}

func (ssr SonarSearchRvs) RelatedType() string {
	return base.RLPRvsDNS
}

func (ss SonarSearchRvs) Name() string {
	return NameSonarSearchRvs
}

func (ss *SonarSearchRvs) Get(ctx context.Context, ip string) (subdomains []string, err error) {
	defer func() {
		ss.RecordStat(subdomains, err)
	}()
	sbChan, err := ss.GetChan(ctx, ip)
	if err != nil {
		return nil, err
	}
	for sb := range sbChan {
		subdomains = append(subdomains, sb)
	}
	return subdomains, nil
}

func (ss *SonarSearchRvs) GetChan(ctx context.Context, ip string) (chan string, error) {
	if err := ss.RLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	req := &pb.QueryRequest{Query: ip}
	res, err := ss.cli.ReverseDNS(ctx, req)
	if err != nil {
		return nil, err
	}
	resultChan := make(chan string)
	go func() {
		for {
			domain, err := res.Recv()
			if err != nil {
				close(resultChan)
				return
			}
			resultChan <- domain.Domain
		}
	}()
	return resultChan, nil
}
