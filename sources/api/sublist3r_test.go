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

func NewMockS3rServer() *httptest.Server {
	return httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(`["abc.abc.com","mail.abc.com","server.abc.com","test.abc.com","www.abc.com"]`))
	}))
}

func TestSublist3r(t *testing.T) {
	testSrv := NewMockS3rServer()
	testSrv.Start()

	testURLBuilder := func(domain string) string { return fmt.Sprintf("%s/search.php?domain=", testSrv.URL) + domain }
	s3r := NewSublist3r()
	require.NoError(t, s3r.Init(base.UrlBuilder(testURLBuilder)))
	subdomains, err := s3r.Get(context.Background(), "abc.com")
	require.NoError(t, err)
	sort.Strings(subdomains)
	exp := []string{
		"abc.abc.com",
		"mail.abc.com",
		"server.abc.com",
		"test.abc.com",
		"www.abc.com",
	}
	assert.Equal(t, exp, subdomains)
	assert.Equal(t, s3r.Stat.DomainsCnt, uint64(1))
	assert.Equal(t, s3r.Stat.SuccessCnt, uint64(1))
	assert.Equal(t, s3r.Stat.FoundCnt, uint64(1))
	assert.Equal(t, s3r.Stat.RelatedDomainCnt, uint64(len(exp)))

	testSrv.Close()
}
