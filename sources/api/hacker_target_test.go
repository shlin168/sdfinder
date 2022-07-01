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

func NewMockHTServer() *httptest.Server {
	return httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(`abc.abc.com,123.34.2.1
mail.abc.com,234.32.7.32`))
	}))
}

func TestHackerTarget(t *testing.T) {
	testSrv := NewMockHTServer()
	testSrv.Start()

	testURLBuilder := func(domain string) string { return fmt.Sprintf("%s/hostsearch/?q=", testSrv.URL) + domain }
	ht := NewHackerTarget()
	require.NoError(t, ht.Init(base.UrlBuilder(testURLBuilder)))
	subdomains, err := ht.Get(context.Background(), "abc.com")
	require.NoError(t, err)
	sort.Strings(subdomains)
	assert.Equal(t, []string{
		"abc.abc.com",
		"mail.abc.com",
	}, subdomains)
	assert.Equal(t, ht.Stat.DomainsCnt, uint64(1))
	assert.Equal(t, ht.Stat.SuccessCnt, uint64(1))
	assert.Equal(t, ht.Stat.FoundCnt, uint64(1))
	assert.Equal(t, ht.Stat.RelatedDomainCnt, uint64(2))

	testSrv.Close()
}
