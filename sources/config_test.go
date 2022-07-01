package sources

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	// 'enabled' section is mandatory
	configContent := []byte(`
sources:
  hackertarget:
    qps: 1
    timeout: 3s
    worker: 1
`)
	_, err := ReadConfig(configContent)
	assert.Error(t, err, errors.New("no enbaled finders defined"))

	// test is not defined in 'sources', use default config
	for _, content := range [][]byte{
		[]byte(`
enabled:
  - test
sources:
  test2:
    qps: 1
    timeout: 3s
    worker: 1
`), []byte(`
enabled:
  - test
`),
	} {
		cfg, err := ReadConfig(content)
		assert.NoError(t, err)
		assert.Equal(t, []string{"test"}, cfg.EnabledSDFinders)
		assert.Equal(t, defaultConfig(), *cfg.GetConfig("test"))
	}

	// test contains custom config, not using default
	configContent = []byte(`
enabled:
  - test
  - test2
sources:
  test:
    qps: 0.1
    timeout: 3s
    retries:
      times: 1
      interval: 0.5s
    worker: 3
  test2:
    qps: 2
    timeout: 10s
    worker: 2
`)
	cfg, err := ReadConfig(configContent)
	assert.NoError(t, err)
	assert.Equal(t, []string{"test", "test2"}, cfg.EnabledSDFinders)
	testCfg := cfg.GetConfig("test")
	assert.Equal(t, 0.1, testCfg.QPS)
	assert.Equal(t, 3*time.Second, testCfg.Timeout)
	assert.Empty(t, testCfg.UserAgent)
	assert.Equal(t, 1, testCfg.Retries.Times)
	assert.Equal(t, 500*time.Millisecond, testCfg.Retries.Interval)
	assert.Equal(t, 3, testCfg.Worker)
	test2Cfg := cfg.GetConfig("test2")
	assert.Equal(t, 2.0, test2Cfg.QPS)
	assert.Equal(t, 10*time.Second, test2Cfg.Timeout)
	assert.Empty(t, test2Cfg.UserAgent)
	assert.Equal(t, 0, test2Cfg.Retries.Times)
	assert.Empty(t, test2Cfg.Retries.Interval)
	assert.Equal(t, 2, test2Cfg.Worker)

	// test input invalid config
	// if specify custom config, timeout, qps and worker are mandatory keys
	for _, invalidNoTimeout := range [][]byte{
		[]byte(`
enabled:
  - test
sources:
  test:
    qps: 1
    timeout: 1s
`), []byte(`
enabled:
  - test
sources:
  test2:
    qps: 1
    worker: 2
`), []byte(`
enabled:
  - test
sources:
  test2:
    timeout: 2s
    worker: 2
`),
	} {
		_, err = ReadConfig(invalidNoTimeout)
		assert.Error(t, err)
	}

	// qps should be given as positive float64
	for _, invalidQPS := range [][]byte{
		[]byte(`
enabled:
  - test
sources:
  test:
    timeout: 3s
    worker: 2
    `), []byte(`
enabled:
  - test
sources:
  test:
    qps: -1
    timeout: 3s
    worker: 3
    `)} {
		_, err = ReadConfig(invalidQPS)
		assert.Error(t, err)
	}

	// if retries times is given, there should contains retries interval > 0
	for _, invalidRetries := range [][]byte{
		[]byte(`
enabled:
  - test
sources:
  test:
    qps: 1
    timeout: 3s
    retries:
      times: 1
`), []byte(`
enabled:
  - test
sources:
  test:
    qps: 1
    timeout: 3s
    retries:
      times: -1
`)} {
		_, err = ReadConfig(invalidRetries)
		assert.Error(t, err)
	}
}
