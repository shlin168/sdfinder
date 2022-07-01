package api

import (
	"strings"

	"github.com/shlin168/sdfinder/sources/base"
)

// https://api.hackertarget.com/hostsearch/?q=<domain>
// rate limit: 2 req / s

// There is a limit of 50 API calls per day from a single IP address as a Free user.
// ref. https://hackertarget.com/ip-tools/
const NameHackerTarget = "hackertarget"

func init() {
	base.MustRegister(NameHackerTarget, NewHackerTarget())
}

type HackerTarget struct{ base.SDFinder }

func NewHackerTarget() *HackerTarget {
	return &HackerTarget{*base.NewSDFinder()}
}

func (ht *HackerTarget) Init(opts ...base.Option) error {
	ht.URLbuilder = func(domain string) string {
		return "https://api.hackertarget.com/hostsearch/?q=" + domain
	}
	ht.Parse = func(content []byte) ([]string, error) {
		var subdomains []string
		for _, domainIP := range strings.Split(string(content), "\n") {
			if endIdx := strings.Index(domainIP, ","); endIdx != -1 {
				subdomains = append(subdomains, domainIP[:endIdx])
			}
		}
		return subdomains, nil
	}
	return ht.SDFinder.Init(opts...)
}

func (HackerTarget) Name() string {
	return NameHackerTarget
}
