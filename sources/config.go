package sources

import (
	"fmt"
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/shlin168/sdfinder/sources/api"
	"github.com/shlin168/sdfinder/sources/base"
	"github.com/shlin168/sdfinder/sources/cert"
	"github.com/shlin168/sdfinder/sources/crawl"
	"github.com/sirupsen/logrus"
)

const (
	DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.95 Safari/537.36"
	DefaultRetries   = 0
	DefaultWorker    = 1
)

type Config struct {
	EnabledSDFinders []string                  `yaml:"enabled"`
	SDFinder         map[string]SDFinderConfig `yaml:"sources"`
}

type SDFinderConfig struct {
	UserAgent string        `yaml:"user_agent"`
	Timeout   time.Duration `yaml:"timeout"`
	QPS       float64       `yaml:"qps"`
	Retries   RetrisConfig  `yaml:"retries"`
	Worker    int           `yaml:"worker"`
}

type RetrisConfig struct {
	Times    int           `yaml:"times"`
	Interval time.Duration `yaml:"interval"`
}

func GenDefaultConfig(enabled []string, worker int) *Config {
	if len(enabled) == 0 {
		for sdname := range base.SDFinderMap {
			enabled = append(enabled, sdname)
		}
	}
	cfg := &Config{EnabledSDFinders: enabled, SDFinder: make(map[string]SDFinderConfig)}
	for _, srcName := range enabled {
		dcfg := defaultConfig()
		dcfg.Worker = worker
		cfg.SDFinder[srcName] = dcfg
	}
	return cfg
}

func defaultConfig() SDFinderConfig {
	return SDFinderConfig{
		QPS:     base.DefaultQPS,
		Timeout: base.DefaultTimeout,
		Retries: RetrisConfig{
			Times: DefaultRetries,
		},
		UserAgent: DefaultUserAgent,
		Worker:    base.DefaultWorker,
	}
}

func ReadConfigFromFile(filename string) (*Config, error) {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read %q error: %v", filename, err)
	}
	return ReadConfig(buf)
}

func ReadConfig(buf []byte) (*Config, error) {
	validSDCfg := func(name string, sdCfg SDFinderConfig) error {
		if sdCfg.Timeout <= 0 {
			return fmt.Errorf("invalid timeout for %s", name)
		}
		if sdCfg.QPS <= 0 {
			return fmt.Errorf("invalid qps for %s", name)
		}
		if sdCfg.Retries.Times < 0 {
			return fmt.Errorf("invalid retries times for %s", name)
		}
		if sdCfg.Retries.Times > 0 && sdCfg.Retries.Interval <= 0 {
			return fmt.Errorf("invalid retries interval for %s when retries times is given", name)
		}
		if sdCfg.Worker <= 0 {
			return fmt.Errorf("invalid worker for %s", name)
		}
		return nil
	}
	cfg := &Config{}
	err := yaml.Unmarshal(buf, cfg)
	if err != nil {
		return nil, fmt.Errorf("unmarshal config err: %v", err)
	}
	if len(cfg.EnabledSDFinders) == 0 {
		return nil, fmt.Errorf("no enbaled finders defined")
	}
	if cfg.SDFinder == nil {
		cfg.SDFinder = make(map[string]SDFinderConfig)
	}
	// check for all given custom config no mater it's in enabled list or not
	for name, customCfg := range cfg.SDFinder {
		if err := validSDCfg(name, customCfg); err != nil {
			return nil, err
		}
	}
	for _, enabledSrcName := range cfg.EnabledSDFinders {
		if _, custCfgGiven := cfg.SDFinder[enabledSrcName]; custCfgGiven {
			continue
		}
		// If finder is in 'enabled' section list, while custom config is not given in
		// 'sources' section, use default config
		cfg.SDFinder[enabledSrcName] = defaultConfig()
	}
	return cfg, nil
}

func (cfg Config) GetConfig(name string) *SDFinderConfig {
	if sdCfg, exist := cfg.SDFinder[name]; exist {
		return &sdCfg
	}
	return nil
}

func (cfg Config) GetOptions(name string) (opts []base.Option) {
	sdcfg := cfg.GetConfig(name)
	if sdcfg == nil {
		return opts
	}
	if sdcfg.Timeout > 0 {
		opts = append(opts, base.Timeout(sdcfg.Timeout))
	}
	if sdcfg.QPS > 0 {
		opts = append(opts, base.QPS(sdcfg.QPS))
	}
	if sdcfg.Retries.Times > 0 {
		opts = append(opts, base.Retries(sdcfg.Retries.Times, sdcfg.Retries.Interval))
	}
	if sdcfg.Worker > 0 {
		opts = append(opts, base.Worker(sdcfg.Worker))
	}
	return opts
}

func (cfg Config) GetOptionsWithUserAgent(name string) (opts []base.Option) {
	opts = cfg.GetOptions(name)
	sdcfg := cfg.GetConfig(name)
	if len(sdcfg.UserAgent) > 0 {
		opts = append(opts, base.Header("User-Agent", sdcfg.UserAgent))
	}
	return opts
}

// init initializes finders in global SDFinderMap from config base on given name
func (cfg Config) init(name string) error {
	qopts := cfg.GetOptions(name)
	sdfinder, exist := base.SDFinderMap[name]
	if !exist {
		return fmt.Errorf("unknown subdomain finder")
	}
	switch name {
	case api.NameSublist3r: // trigger init() in api package
	case crawl.NameAbuseIPDB:
		qopts = cfg.GetOptionsWithUserAgent(name)
	case cert.NameCrtsh:
		// default not after = execution time in UTC
		qopts = append(qopts, base.TimeAfter(time.Now().UTC()))
	}
	if err := sdfinder.Init(qopts...); err != nil {
		return err
	}
	base.SDFinderMap[name] = sdfinder
	return nil
}

// Init initializes all enabled finders
func (cfg Config) Init() []base.SubdomainFinder {
	var initSDFinders []base.SubdomainFinder
	var failed []string
	for _, name := range cfg.EnabledSDFinders {
		if err := cfg.init(name); err != nil {
			logrus.WithField("name", name).WithError(err).Warn("init failed")
			failed = append(failed, name)
			continue
		}
		initSDFinders = append(initSDFinders, base.SDFinderMap[name])
	}
	if len(failed) > 0 {
		logrus.WithField("names", failed).Warn("not all given finders successfully init")
	}
	return initSDFinders
}
