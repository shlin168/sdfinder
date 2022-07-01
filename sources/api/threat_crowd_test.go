package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/sdfinder/sources/base"
)

func NewMockTCServer() *httptest.Server {
	return httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(`{"response_code":"1","resolutions":[{"last_resolved":"2022-05-04","ip_address":"111.222.111.222"}],` +
			`"hashes":[],"emails":[""],"subdomains":["abc.abc.com","test.abc.com"],` +
			`"references":[],"votes":0,"permalink":"https:\/\/www.threatcrowd.org\/domain.php?domain=abc.com"}`))
	}))
}

func TestThreatCrowd(t *testing.T) {
	testSrv := NewMockTCServer()
	testSrv.Start()

	testURLBuilder := func(domain string) string {
		return fmt.Sprintf("%s/searchApi/v2/domain/report/?domain=", testSrv.URL) + domain
	}
	tc := NewThreatCrowd()
	require.NoError(t, tc.Init(base.UrlBuilder(testURLBuilder)))
	subdomains, err := tc.Get(context.Background(), "abc.com")
	require.NoError(t, err)
	sort.Strings(subdomains)
	exp := []string{
		"abc.abc.com",
		"test.abc.com",
	}
	assert.Equal(t, exp, subdomains)
	assert.Equal(t, tc.Stat.DomainsCnt, uint64(1))
	assert.Equal(t, tc.Stat.SuccessCnt, uint64(1))
	assert.Equal(t, tc.Stat.FoundCnt, uint64(1))
	assert.Equal(t, tc.Stat.RelatedDomainCnt, uint64(len(exp)))

	testSrv.Close()
}
