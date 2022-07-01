package api

import (
	"encoding/json"

	"github.com/shlin168/sdfinder/sources/base"
)

// https://api.sublist3r.com/search.php?domain={domain}
// rate limit: ?
const NameSublist3r = "sublist3r"

func init() {
	base.MustRegister(NameSublist3r, NewSublist3r())
}

type Sublist3r struct{ base.SDFinder }

func NewSublist3r() *Sublist3r {
	return &Sublist3r{*base.NewSDFinder()}
}

func (s3r *Sublist3r) Init(opts ...base.Option) error {
	s3r.URLbuilder = func(domain string) string {
		return "https://api.sublist3r.com/search.php?domain=" + domain
	}
	s3r.Parse = func(content []byte) ([]string, error) {
		var slrsp []string
		if err := json.Unmarshal(content, &slrsp); err != nil {
			return nil, err
		}
		return slrsp, nil
	}
	return s3r.SDFinder.Init(opts...)
}

func (s3r Sublist3r) Name() string {
	return NameSublist3r
}
