package outboundgroup

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dlclark/regexp2"

	"github.com/Ruk1ng001/mihomo-mod/adapter/outbound"
	"github.com/Ruk1ng001/mihomo-mod/adapter/provider"
	"github.com/Ruk1ng001/mihomo-mod/common/structure"
	"github.com/Ruk1ng001/mihomo-mod/common/utils"
	C "github.com/Ruk1ng001/mihomo-mod/constant"
	types "github.com/Ruk1ng001/mihomo-mod/constant/provider"
)

var (
	errFormat            = errors.New("format error")
	errType              = errors.New("unsupported type")
	errMissProxy         = errors.New("`use` or `proxies` missing")
	errDuplicateProvider = errors.New("duplicate provider name")
)

type GroupCommonOption struct {
	outbound.BasicOption          // 继承自 BasicOption 的基本选项
	Name                 string   `group:"name" yaml:"name"`                                                       // 组的名称
	Type                 string   `group:"type" yaml:"type"`                                                       // 组的类型
	Proxies              []string `group:"proxies,omitempty" yaml:"proxies,omitempty"`                             // 代理列表，可选
	Use                  []string `group:"use,omitempty" yaml:"use,omitempty"`                                     // 使用的选项，可选
	URL                  string   `group:"url,omitempty" yaml:"url,omitempty"`                                     // 组的 URL，可选
	Interval             int      `group:"interval,omitempty" yaml:"interval,omitempty"`                           // 检测间隔，可选
	TestTimeout          int      `group:"timeout,omitempty" yaml:"timeout,omitempty"`                             // 测试超时时间，可选
	MaxFailedTimes       int      `group:"max-failed-times,omitempty" yaml:"max-failed-times,omitempty"`           // 最大失败次数，可选
	Lazy                 bool     `group:"lazy,omitempty" yaml:"lazy,omitempty"`                                   // 是否懒加载，可选
	DisableUDP           bool     `group:"disable-udp,omitempty" yaml:"disable-udp,omitempty"`                     // 是否禁用 UDP，可选
	Filter               string   `group:"filter,omitempty" yaml:"filter,omitempty"`                               // 过滤器，可选
	ExcludeFilter        string   `group:"exclude-filter,omitempty" yaml:"exclude-filter,omitempty"`               // 排除的过滤器，可选
	ExcludeType          string   `group:"exclude-type,omitempty" yaml:"exclude-type,omitempty"`                   // 排除的类型，可选
	ExpectedStatus       string   `group:"expected-status,omitempty" yaml:"expected-status,omitempty"`             // 期望的状态，可选
	IncludeAll           bool     `group:"include-all,omitempty" yaml:"include-all,omitempty"`                     // 是否包含所有项，可选
	IncludeAllProxies    bool     `group:"include-all-proxies,omitempty" yaml:"include-all-proxies,omitempty"`     // 是否包含所有代理，可选
	IncludeAllProviders  bool     `group:"include-all-providers,omitempty" yaml:"include-all-providers,omitempty"` // 是否包含所有提供者，可选
	Hidden               bool     `group:"hidden,omitempty" yaml:"hidden,omitempty"`                               // 是否隐藏，可选
	Icon                 string   `group:"icon,omitempty" yaml:"icon,omitempty"`                                   // 图标，可选
}

func ParseProxyGroup(config map[string]any, proxyMap map[string]C.Proxy, providersMap map[string]types.ProxyProvider, AllProxies []string, AllProviders []string) (C.ProxyAdapter, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})

	groupOption := &GroupCommonOption{
		Lazy: true,
	}
	if err := decoder.Decode(config, groupOption); err != nil {
		return nil, errFormat
	}

	if groupOption.Type == "" || groupOption.Name == "" {
		return nil, errFormat
	}

	groupName := groupOption.Name

	providers := []types.ProxyProvider{}

	if groupOption.IncludeAll {
		groupOption.IncludeAllProviders = true
		groupOption.IncludeAllProxies = true
	}

	if groupOption.IncludeAllProviders {
		groupOption.Use = AllProviders
	}
	if groupOption.IncludeAllProxies {
		if groupOption.Filter != "" {
			var filterRegs []*regexp2.Regexp
			for _, filter := range strings.Split(groupOption.Filter, "`") {
				filterReg := regexp2.MustCompile(filter, regexp2.None)
				filterRegs = append(filterRegs, filterReg)
			}
			for _, p := range AllProxies {
				for _, filterReg := range filterRegs {
					if mat, _ := filterReg.MatchString(p); mat {
						groupOption.Proxies = append(groupOption.Proxies, p)
					}
				}
			}
		} else {
			groupOption.Proxies = append(groupOption.Proxies, AllProxies...)
		}
		if len(groupOption.Proxies) == 0 && len(groupOption.Use) == 0 {
			groupOption.Proxies = []string{"COMPATIBLE"}
		}
	}

	if len(groupOption.Proxies) == 0 && len(groupOption.Use) == 0 {
		return nil, fmt.Errorf("%s: %w", groupName, errMissProxy)
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](groupOption.ExpectedStatus)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", groupName, err)
	}

	status := strings.TrimSpace(groupOption.ExpectedStatus)
	if status == "" {
		status = "*"
	}
	groupOption.ExpectedStatus = status

	if len(groupOption.Use) != 0 {
		PDs, err := getProviders(providersMap, groupOption.Use)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		// if test URL is empty, use the first health check URL of providers
		if groupOption.URL == "" {
			for _, pd := range PDs {
				if pd.HealthCheckURL() != "" {
					groupOption.URL = pd.HealthCheckURL()
					break
				}
			}
			if groupOption.URL == "" {
				groupOption.URL = C.DefaultTestURL
			}
		} else {
			addTestUrlToProviders(PDs, groupOption.URL, expectedStatus, groupOption.Filter, uint(groupOption.Interval))
		}
		providers = append(providers, PDs...)
	}

	if len(groupOption.Proxies) != 0 {
		ps, err := getProxies(proxyMap, groupOption.Proxies)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		if _, ok := providersMap[groupName]; ok {
			return nil, fmt.Errorf("%s: %w", groupName, errDuplicateProvider)
		}

		if groupOption.URL == "" {
			groupOption.URL = C.DefaultTestURL
		}

		// select don't need auto health check
		if groupOption.Type != "select" && groupOption.Type != "relay" {
			if groupOption.Interval == 0 {
				groupOption.Interval = 300
			}
		}

		hc := provider.NewHealthCheck(ps, groupOption.URL, uint(groupOption.TestTimeout), uint(groupOption.Interval), groupOption.Lazy, expectedStatus)

		pd, err := provider.NewCompatibleProvider(groupName, ps, hc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		providers = append([]types.ProxyProvider{pd}, providers...)
		providersMap[groupName] = pd
	}

	var group C.ProxyAdapter
	switch groupOption.Type {
	case "url-test":
		opts := parseURLTestOption(config)
		group = NewURLTest(groupOption, providers, opts...)
	case "select":
		group = NewSelector(groupOption, providers)
	case "fallback":
		group = NewFallback(groupOption, providers)
	case "load-balance":
		strategy := parseStrategy(config)
		return NewLoadBalance(groupOption, providers, strategy)
	case "relay":
		group = NewRelay(groupOption, providers)
	default:
		return nil, fmt.Errorf("%w: %s", errType, groupOption.Type)
	}

	return group, nil
}

func getProxies(mapping map[string]C.Proxy, list []string) ([]C.Proxy, error) {
	var ps []C.Proxy
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func getProviders(mapping map[string]types.ProxyProvider, list []string) ([]types.ProxyProvider, error) {
	var ps []types.ProxyProvider
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}

		if p.VehicleType() == types.Compatible {
			return nil, fmt.Errorf("proxy group %s can't contains in `use`", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func addTestUrlToProviders(providers []types.ProxyProvider, url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	if len(providers) == 0 || len(url) == 0 {
		return
	}

	for _, pd := range providers {
		pd.RegisterHealthCheckTask(url, expectedStatus, filter, interval)
	}
}
