package provider

import (
	"errors"
	"fmt"
	"time"

	"github.com/Ruk1ng001/mihomo-mod/common/structure"
	"github.com/Ruk1ng001/mihomo-mod/component/resource"
	C "github.com/Ruk1ng001/mihomo-mod/constant"
	P "github.com/Ruk1ng001/mihomo-mod/constant/provider"
)

var (
	errSubPath = errors.New("path is not subpath of home directory")
)

type ruleProviderSchema struct {
	Type     string `provider:"type"`
	Behavior string `provider:"behavior"`
	Path     string `provider:"path,omitempty"`
	URL      string `provider:"url,omitempty"`
	Proxy    string `provider:"proxy,omitempty"`
	Format   string `provider:"format,omitempty"`
	Interval int    `provider:"interval,omitempty"`
}

func ParseRuleProvider(name string, mapping map[string]interface{}, parse func(tp, payload, target string, params []string, subRules map[string][]C.Rule) (parsed C.Rule, parseErr error)) (P.RuleProvider, error) {
	schema := &ruleProviderSchema{}
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}
	behavior, err := P.ParseBehavior(schema.Behavior)
	if err != nil {
		return nil, err
	}
	format, err := P.ParseRuleFormat(schema.Format)
	if err != nil {
		return nil, err
	}

	var vehicle P.Vehicle
	switch schema.Type {
	case "file":
		path := C.Path.Resolve(schema.Path)
		vehicle = resource.NewFileVehicle(path)
	case "http":
		path := C.Path.GetPathByHash("rules", schema.URL)
		if schema.Path != "" {
			path = C.Path.Resolve(schema.Path)
			if !C.Path.IsSafePath(path) {
				return nil, fmt.Errorf("%w: %s", errSubPath, path)
			}
		}
		vehicle = resource.NewHTTPVehicle(schema.URL, path, schema.Proxy, nil, resource.DefaultHttpTimeout)
	default:
		return nil, fmt.Errorf("unsupported vehicle type: %s", schema.Type)
	}

	return NewRuleSetProvider(name, behavior, format, time.Duration(uint(schema.Interval))*time.Second, vehicle, parse), nil
}
