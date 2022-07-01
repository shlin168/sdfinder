package api

import (
	"encoding/json"

	"github.com/shlin168/sdfinder/sources/base"
)

// https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}
// rate limit: 1 reqs / 10s
const NameThreatCrowd = "threatcrowd"

func init() {
	base.MustRegister(NameThreatCrowd, NewThreatCrowd())
}

type ThreatCrowd struct{ base.SDFinder }
type ThreatCrowdRsp struct {
	RspCode    string   `json:"response_code"`
	Subdomains []string `json:"subdomains"`
}

func NewThreatCrowd() *ThreatCrowd {
	return &ThreatCrowd{*base.NewSDFinder()}
}

func (tc *ThreatCrowd) Init(opts ...base.Option) error {
	tc.URLbuilder = func(domain string) string {
		return "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" + domain
	}
	tc.Parse = func(content []byte) ([]string, error) {
		var tcrsp ThreatCrowdRsp
		if err := json.Unmarshal(content, &tcrsp); err != nil {
			return nil, err
		}
		return tcrsp.Subdomains, nil
	}
	return tc.SDFinder.Init(opts...)
}

func (tc ThreatCrowd) Name() string {
	return NameThreatCrowd
}
