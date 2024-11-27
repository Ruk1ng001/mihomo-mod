package config

import (
	"container/list"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
	_ "unsafe"

	"github.com/Ruk1ng001/mihomo-mod/adapter"
	"github.com/Ruk1ng001/mihomo-mod/adapter/outbound"
	"github.com/Ruk1ng001/mihomo-mod/adapter/outboundgroup"
	"github.com/Ruk1ng001/mihomo-mod/adapter/provider"
	"github.com/Ruk1ng001/mihomo-mod/common/utils"
	"github.com/Ruk1ng001/mihomo-mod/component/auth"
	"github.com/Ruk1ng001/mihomo-mod/component/cidr"
	"github.com/Ruk1ng001/mihomo-mod/component/fakeip"
	"github.com/Ruk1ng001/mihomo-mod/component/geodata"
	P "github.com/Ruk1ng001/mihomo-mod/component/process"
	"github.com/Ruk1ng001/mihomo-mod/component/resolver"
	"github.com/Ruk1ng001/mihomo-mod/component/sniffer"
	"github.com/Ruk1ng001/mihomo-mod/component/trie"
	C "github.com/Ruk1ng001/mihomo-mod/constant"
	providerTypes "github.com/Ruk1ng001/mihomo-mod/constant/provider"
	snifferTypes "github.com/Ruk1ng001/mihomo-mod/constant/sniffer"
	"github.com/Ruk1ng001/mihomo-mod/dns"
	L "github.com/Ruk1ng001/mihomo-mod/listener"
	LC "github.com/Ruk1ng001/mihomo-mod/listener/config"
	"github.com/Ruk1ng001/mihomo-mod/log"
	R "github.com/Ruk1ng001/mihomo-mod/rules"
	RC "github.com/Ruk1ng001/mihomo-mod/rules/common"
	RP "github.com/Ruk1ng001/mihomo-mod/rules/provider"
	T "github.com/Ruk1ng001/mihomo-mod/tunnel"

	orderedmap "github.com/wk8/go-ordered-map/v2"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

// General config
type General struct {
	Inbound
	Mode                    T.TunnelMode      `json:"mode"`
	UnifiedDelay            bool              `json:"unified-delay"`
	LogLevel                log.LogLevel      `json:"log-level"`
	IPv6                    bool              `json:"ipv6"`
	Interface               string            `json:"interface-name"`
	RoutingMark             int               `json:"routing-mark"`
	GeoXUrl                 GeoXUrl           `json:"geox-url"`
	GeoAutoUpdate           bool              `json:"geo-auto-update"`
	GeoUpdateInterval       int               `json:"geo-update-interval"`
	GeodataMode             bool              `json:"geodata-mode"`
	GeodataLoader           string            `json:"geodata-loader"`
	GeositeMatcher          string            `json:"geosite-matcher"`
	TCPConcurrent           bool              `json:"tcp-concurrent"`
	FindProcessMode         P.FindProcessMode `json:"find-process-mode"`
	Sniffing                bool              `json:"sniffing"`
	GlobalClientFingerprint string            `json:"global-client-fingerprint"`
	GlobalUA                string            `json:"global-ua"`
	ETagSupport             bool              `json:"etag-support"`
	KeepAliveIdle           int               `json:"keep-alive-idle"`
	KeepAliveInterval       int               `json:"keep-alive-interval"`
	DisableKeepAlive        bool              `json:"disable-keep-alive"`
}

// Inbound config
type Inbound struct {
	Port              int            `json:"port"`
	SocksPort         int            `json:"socks-port"`
	RedirPort         int            `json:"redir-port"`
	TProxyPort        int            `json:"tproxy-port"`
	MixedPort         int            `json:"mixed-port"`
	Tun               LC.Tun         `json:"tun"`
	TuicServer        LC.TuicServer  `json:"tuic-server"`
	ShadowSocksConfig string         `json:"ss-config"`
	VmessConfig       string         `json:"vmess-config"`
	Authentication    []string       `json:"authentication"`
	SkipAuthPrefixes  []netip.Prefix `json:"skip-auth-prefixes"`
	LanAllowedIPs     []netip.Prefix `json:"lan-allowed-ips"`
	LanDisAllowedIPs  []netip.Prefix `json:"lan-disallowed-ips"`
	AllowLan          bool           `json:"allow-lan"`
	BindAddress       string         `json:"bind-address"`
	InboundTfo        bool           `json:"inbound-tfo"`
	InboundMPTCP      bool           `json:"inbound-mptcp"`
}

// GeoXUrl config
type GeoXUrl struct {
	GeoIp   string `json:"geo-ip"`
	Mmdb    string `json:"mmdb"`
	ASN     string `json:"asn"`
	GeoSite string `json:"geo-site"`
}

// Controller config
type Controller struct {
	ExternalController     string
	ExternalControllerTLS  string
	ExternalControllerUnix string
	ExternalControllerPipe string
	ExternalUI             string
	ExternalUIURL          string
	ExternalUIName         string
	ExternalDohServer      string
	Secret                 string
	Cors                   Cors
}

type Cors struct {
	AllowOrigins        []string
	AllowPrivateNetwork bool
}

// Experimental config
type Experimental struct {
	Fingerprints     []string
	QUICGoDisableGSO bool
	QUICGoDisableECN bool
	IP4PEnable       bool
}

// IPTables config
type IPTables struct {
	Enable           bool
	InboundInterface string
	Bypass           []string
	DnsRedirect      bool
}

// NTP config
type NTP struct {
	Enable        bool
	Server        string
	Port          int
	Interval      int
	DialerProxy   string
	WriteToSystem bool
}

// DNS config
type DNS struct {
	Enable                bool
	PreferH3              bool
	IPv6                  bool
	IPv6Timeout           uint
	UseSystemHosts        bool
	NameServer            []dns.NameServer
	Fallback              []dns.NameServer
	FallbackIPFilter      []C.IpMatcher
	FallbackDomainFilter  []C.DomainMatcher
	Listen                string
	EnhancedMode          C.DNSMode
	DefaultNameserver     []dns.NameServer
	CacheAlgorithm        string
	FakeIPRange           *fakeip.Pool
	Hosts                 *trie.DomainTrie[resolver.HostValue]
	NameServerPolicy      []dns.Policy
	ProxyServerNameserver []dns.NameServer
	DirectNameServer      []dns.NameServer
	DirectFollowPolicy    bool
}

// Profile config
type Profile struct {
	StoreSelected bool
	StoreFakeIP   bool
}

// TLS config
type TLS struct {
	Certificate     string
	PrivateKey      string
	CustomTrustCert []string
}

// Config is mihomo config manager
type Config struct {
	General       *General
	Controller    *Controller
	Experimental  *Experimental
	IPTables      *IPTables
	NTP           *NTP
	DNS           *DNS
	Hosts         *trie.DomainTrie[resolver.HostValue]
	Profile       *Profile
	Rules         []C.Rule
	SubRules      map[string][]C.Rule
	Users         []auth.AuthUser
	Proxies       map[string]C.Proxy
	Listeners     map[string]C.InboundListener
	Providers     map[string]providerTypes.ProxyProvider
	RuleProviders map[string]providerTypes.RuleProvider
	Tunnels       []LC.Tunnel
	Sniffer       *sniffer.Config
	TLS           *TLS
}

type RawCors struct {
	AllowOrigins        []string `yaml:"allow-origins,omitempty" json:"allow-origins,omitempty"`
	AllowPrivateNetwork bool     `yaml:"allow-private-network,omitempty" json:"allow-private-network,omitempty"`
}

type RawDNS struct {
	Enable                       bool                                `yaml:"enable,omitempty" json:"enable,omitempty"`
	PreferH3                     bool                                `yaml:"prefer-h3,omitempty" json:"prefer-h3,omitempty"`
	IPv6                         bool                                `yaml:"ipv6,omitempty" json:"ipv6,omitempty"`
	IPv6Timeout                  uint                                `yaml:"ipv6-timeout,omitempty" json:"ipv6-timeout,omitempty"`
	UseHosts                     bool                                `yaml:"use-hosts,omitempty" json:"use-hosts,omitempty"`
	UseSystemHosts               bool                                `yaml:"use-system-hosts,omitempty" json:"use-system-hosts,omitempty"`
	RespectRules                 bool                                `yaml:"respect-rules,omitempty" json:"respect-rules,omitempty"`
	NameServer                   []string                            `yaml:"nameserver,omitempty" json:"nameserver,omitempty"`
	Fallback                     []string                            `yaml:"fallback,omitempty" json:"fallback,omitempty"`
	FallbackFilter               RawFallbackFilter                   `yaml:"fallback-filter,omitempty" json:"fallback-filter,omitempty"`
	Listen                       string                              `yaml:"listen,omitempty" json:"listen,omitempty"`
	EnhancedMode                 C.DNSMode                           `yaml:"enhanced-mode,omitempty" json:"enhanced-mode,omitempty"`
	FakeIPRange                  string                              `yaml:"fake-ip-range,omitempty" json:"fake-ip-range,omitempty"`
	FakeIPFilter                 []string                            `yaml:"fake-ip-filter,omitempty" json:"fake-ip-filter,omitempty"`
	FakeIPFilterMode             C.FilterMode                        `yaml:"fake-ip-filter-mode,omitempty" json:"fake-ip-filter-mode,omitempty"`
	DefaultNameserver            []string                            `yaml:"default-nameserver,omitempty" json:"default-nameserver,omitempty"`
	CacheAlgorithm               string                              `yaml:"cache-algorithm,omitempty" json:"cache-algorithm,omitempty"`
	NameServerPolicy             *orderedmap.OrderedMap[string, any] `yaml:"nameserver-policy,omitempty" json:"nameserver-policy,omitempty"`
	ProxyServerNameserver        []string                            `yaml:"proxy-server-nameserver,omitempty" json:"proxy-server-nameserver,omitempty"`
	DirectNameServer             []string                            `yaml:"direct-nameserver,omitempty" json:"direct-nameserver,omitempty"`
	DirectNameServerFollowPolicy bool                                `yaml:"direct-nameserver-follow-policy,omitempty" json:"direct-nameserver-follow-policy,omitempty"`
}

type RawFallbackFilter struct {
	GeoIP     bool     `yaml:"geoip,omitempty" json:"geoip,omitempty"`
	GeoIPCode string   `yaml:"geoip-code,omitempty" json:"geoip-code,omitempty"`
	IPCIDR    []string `yaml:"ipcidr,omitempty" json:"ipcidr,omitempty"`
	Domain    []string `yaml:"domain,omitempty" json:"domain,omitempty"`
	GeoSite   []string `yaml:"geosite,omitempty" json:"geosite,omitempty"`
}

type RawClashForAndroid struct {
	AppendSystemDNS   bool   `yaml:"append-system-dns,omitempty" json:"append-system-dns,omitempty"`
	UiSubtitlePattern string `yaml:"ui-subtitle-pattern,omitempty" json:"ui-subtitle-pattern,omitempty"`
}

type RawNTP struct {
	Enable        bool   `yaml:"enable,omitempty" json:"enable,omitempty"`
	Server        string `yaml:"server,omitempty" json:"server,omitempty"`
	Port          int    `yaml:"port,omitempty" json:"port,omitempty"`
	Interval      int    `yaml:"interval,omitempty" json:"interval,omitempty"`
	DialerProxy   string `yaml:"dialer-proxy,omitempty" json:"dialer-proxy,omitempty"`
	WriteToSystem bool   `yaml:"write-to-system,omitempty" json:"write-to-system,omitempty"`
}

type RawTun struct {
	Enable              bool       `yaml:"enable,omitempty" json:"enable,omitempty"`
	Device              string     `yaml:"device,omitempty" json:"device,omitempty"`
	Stack               C.TUNStack `yaml:"stack,omitempty" json:"stack,omitempty"`
	DNSHijack           []string   `yaml:"dns-hijack,omitempty" json:"dns-hijack,omitempty"`
	AutoRoute           bool       `yaml:"auto-route,omitempty" json:"auto-route,omitempty"`
	AutoDetectInterface bool       `yaml:"auto-detect-interface,omitempty"`

	MTU                    uint32         `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	GSO                    bool           `yaml:"gso,omitempty" json:"gso,omitempty"`
	GSOMaxSize             uint32         `yaml:"gso-max-size,omitempty" json:"gso-max-size,omitempty"`
	Inet6Address           []netip.Prefix `yaml:"inet6-address,omitempty" json:"inet6-address,omitempty"`
	IPRoute2TableIndex     int            `yaml:"iproute2-table-index,omitempty" json:"iproute2-table-index,omitempty"`
	IPRoute2RuleIndex      int            `yaml:"iproute2-rule-index,omitempty" json:"iproute2-rule-index,omitempty"`
	AutoRedirect           bool           `yaml:"auto-redirect,omitempty" json:"auto-redirect,omitempty"`
	AutoRedirectInputMark  uint32         `yaml:"auto-redirect-input-mark,omitempty" json:"auto-redirect-input-mark,omitempty"`
	AutoRedirectOutputMark uint32         `yaml:"auto-redirect-output-mark,omitempty" json:"auto-redirect-output-mark,omitempty"`
	StrictRoute            bool           `yaml:"strict-route,omitempty" json:"strict-route,omitempty"`
	RouteAddress           []netip.Prefix `yaml:"route-address,omitempty" json:"route-address,omitempty"`
	RouteAddressSet        []string       `yaml:"route-address-set,omitempty" json:"route-address-set,omitempty"`
	RouteExcludeAddress    []netip.Prefix `yaml:"route-exclude-address,omitempty" json:"route-exclude-address,omitempty"`
	RouteExcludeAddressSet []string       `yaml:"route-exclude-address-set,omitempty" json:"route-exclude-address-set,omitempty"`
	IncludeInterface       []string       `yaml:"include-interface,omitempty" json:"include-interface,omitempty"`
	ExcludeInterface       []string       `yaml:"exclude-interface,omitempty" json:"exclude-interface,omitempty"`
	IncludeUID             []uint32       `yaml:"include-uid,omitempty" json:"include-uid,omitempty"`
	IncludeUIDRange        []string       `yaml:"include-uid-range,omitempty" json:"include-uid-range,omitempty"`
	ExcludeUID             []uint32       `yaml:"exclude-uid,omitempty" json:"exclude-uid,omitempty"`
	ExcludeUIDRange        []string       `yaml:"exclude-uid-range,omitempty" json:"exclude-uid-range,omitempty"`
	IncludeAndroidUser     []int          `yaml:"include-android-user,omitempty" json:"include-android-user,omitempty"`
	IncludePackage         []string       `yaml:"include-package,omitempty" json:"include-package,omitempty"`
	ExcludePackage         []string       `yaml:"exclude-package,omitempty" json:"exclude-package,omitempty"`
	EndpointIndependentNat bool           `yaml:"endpoint-independent-nat,omitempty" json:"endpoint-independent-nat,omitempty"`
	UDPTimeout             int64          `yaml:"udp-timeout,omitempty" json:"udp-timeout,omitempty"`
	FileDescriptor         int            `yaml:"file-descriptor,omitempty" json:"file-descriptor,omitempty"`

	Inet4RouteAddress        []netip.Prefix `yaml:"inet4-route-address,omitempty" json:"inet4-route-address,omitempty"`
	Inet6RouteAddress        []netip.Prefix `yaml:"inet6-route-address,omitempty" json:"inet6-route-address,omitempty"`
	Inet4RouteExcludeAddress []netip.Prefix `yaml:"inet4-route-exclude-address,omitempty" json:"inet4-route-exclude-address,omitempty"`
	Inet6RouteExcludeAddress []netip.Prefix `yaml:"inet6-route-exclude-address,omitempty" json:"inet6-route-exclude-address,omitempty"`
}

type RawTuicServer struct {
	Enable                bool              `yaml:"enable,omitempty" json:"enable,omitempty"`
	Listen                string            `yaml:"listen,omitempty" json:"listen,omitempty"`
	Token                 []string          `yaml:"token,omitempty" json:"token,omitempty"`
	Users                 map[string]string `yaml:"users,omitempty" json:"users,omitempty"`
	Certificate           string            `yaml:"certificate,omitempty" json:"certificate,omitempty"`
	PrivateKey            string            `yaml:"private-key,omitempty" json:"private-key,omitempty"`
	CongestionController  string            `yaml:"congestion-controller,omitempty" json:"congestion-controller,omitempty"`
	MaxIdleTime           int               `yaml:"max-idle-time,omitempty" json:"max-idle-time,omitempty"`
	AuthenticationTimeout int               `yaml:"authentication-timeout,omitempty" json:"authentication-timeout,omitempty"`
	ALPN                  []string          `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	MaxUdpRelayPacketSize int               `yaml:"max-udp-relay-packet-size,omitempty" json:"max-udp-relay-packet-size,omitempty"`
	CWND                  int               `yaml:"cwnd,omitempty" json:"cwnd,omitempty"`
}

type RawIPTables struct {
	Enable           bool     `yaml:"enable,omitempty" json:"enable,omitempty"`
	InboundInterface string   `yaml:"inbound-interface,omitempty" json:"inbound-interface,omitempty"`
	Bypass           []string `yaml:"bypass,omitempty" json:"bypass,omitempty"`
	DnsRedirect      bool     `yaml:"dns-redirect,omitempty" json:"dns-redirect,omitempty"`
}

type RawExperimental struct {
	Fingerprints     []string `yaml:"fingerprints,omitempty" json:"fingerprints,omitempty"`
	QUICGoDisableGSO bool     `yaml:"quic-go-disable-gso,omitempty" json:"quic-go-disable-gso,omitempty"`
	QUICGoDisableECN bool     `yaml:"quic-go-disable-ecn,omitempty" json:"quic-go-disable-ecn,omitempty"`
	IP4PEnable       bool     `yaml:"dialer-ip4p-convert,omitempty" json:"dialer-ip4p-convert,omitempty"`
}

type RawProfile struct {
	StoreSelected bool `yaml:"store-selected,omitempty" json:"store-selected,omitempty"`
	StoreFakeIP   bool `yaml:"store-fake-ip,omitempty" json:"store-fake-ip,omitempty"`
}

type RawGeoXUrl struct {
	GeoIp   string `yaml:"geoip,omitempty" json:"geoip,omitempty"`
	Mmdb    string `yaml:"mmdb,omitempty" json:"mmdb,omitempty"`
	ASN     string `yaml:"asn,omitempty" json:"asn,omitempty"`
	GeoSite string `yaml:"geosite,omitempty" json:"geosite,omitempty"`
}

type RawSniffer struct {
	Enable          bool     `yaml:"enable,omitempty" json:"enable,omitempty"`
	OverrideDest    bool     `yaml:"override-destination,omitempty" json:"override-destination,omitempty"`
	Sniffing        []string `yaml:"sniffing,omitempty" json:"sniffing,omitempty"`
	ForceDomain     []string `yaml:"force-domain,omitempty" json:"force-domain,omitempty"`
	SkipSrcAddress  []string `yaml:"skip-src-address,omitempty" json:"skip-src-address,omitempty"`
	SkipDstAddress  []string `yaml:"skip-dst-address,omitempty" json:"skip-dst-address,omitempty"`
	SkipDomain      []string `yaml:"skip-domain,omitempty" json:"skip-domain,omitempty"`
	Ports           []string `yaml:"port-whitelist,omitempty" json:"port-whitelist,omitempty"`
	ForceDnsMapping bool     `yaml:"force-dns-mapping,omitempty" json:"force-dns-mapping,omitempty"`
	ParsePureIp     bool     `yaml:"parse-pure-ip,omitempty" json:"parse-pure-ip,omitempty"`

	Sniff map[string]RawSniffingConfig `yaml:"sniff,omitempty" json:"sniff,omitempty"`
}

type RawSniffingConfig struct {
	Ports        []string `yaml:"ports,omitempty" json:"ports,omitempty"`
	OverrideDest *bool    `yaml:"override-destination,omitempty" json:"override-destination,omitempty"`
}

type RawTLS struct {
	Certificate     string   `yaml:"certificate,omitempty" json:"certificate,omitempty"`
	PrivateKey      string   `yaml:"private-key,omitempty" json:"private-key,omitempty"`
	CustomTrustCert []string `yaml:"custom-certifactes,omitempty" json:"custom-certifactes,omitempty"`
}

type RawConfig struct {
	Port                    int               `yaml:"port,omitempty" json:"port,omitempty"`
	SocksPort               int               `yaml:"socks-port,omitempty" json:"socks-port,omitempty"`
	RedirPort               int               `yaml:"redir-port,omitempty" json:"redir-port,omitempty"`
	TProxyPort              int               `yaml:"tproxy-port,omitempty" json:"tproxy-port,omitempty"`
	MixedPort               int               `yaml:"mixed-port,omitempty" json:"mixed-port,omitempty"`
	ShadowSocksConfig       string            `yaml:"ss-config,omitempty" json:"ss-config,omitempty"`
	VmessConfig             string            `yaml:"vmess-config,omitempty" json:"vmess-config,omitempty"`
	InboundTfo              bool              `yaml:"inbound-tfo,omitempty" json:"inbound-tfo,omitempty"`
	InboundMPTCP            bool              `yaml:"inbound-mptcp,omitempty" json:"inbound-mptcp,omitempty"`
	Authentication          []string          `yaml:"authentication,omitempty" json:"authentication,omitempty"`
	SkipAuthPrefixes        []netip.Prefix    `yaml:"skip-auth-prefixes,omitempty" json:"skip-auth-prefixes,omitempty"`
	LanAllowedIPs           []netip.Prefix    `yaml:"lan-allowed-ips,omitempty" json:"lan-allowed-ips,omitempty"`
	LanDisAllowedIPs        []netip.Prefix    `yaml:"lan-disallowed-ips,omitempty" json:"lan-disallowed-ips,omitempty"`
	AllowLan                bool              `yaml:"allow-lan,omitempty" json:"allow-lan,omitempty"`
	BindAddress             string            `yaml:"bind-address,omitempty" json:"bind-address,omitempty"`
	Mode                    T.TunnelMode      `yaml:"mode,omitempty" json:"mode,omitempty"`
	UnifiedDelay            bool              `yaml:"unified-delay,omitempty" json:"unified-delay,omitempty"`
	LogLevel                log.LogLevel      `yaml:"log-level,omitempty" json:"log-level,omitempty"`
	IPv6                    bool              `yaml:"ipv6,omitempty" json:"ipv6,omitempty"`
	ExternalController      string            `yaml:"external-controller,omitempty" json:"external-controller,omitempty"`
	ExternalControllerPipe  string            `yaml:"external-controller-pipe,omitempty" json:"external-controller-pipe,omitempty"`
	ExternalControllerUnix  string            `yaml:"external-controller-unix,omitempty" json:"external-controller-unix,omitempty"`
	ExternalControllerTLS   string            `yaml:"external-controller-tls,omitempty" json:"external-controller-tls,omitempty"`
	ExternalControllerCors  RawCors           `yaml:"external-controller-cors,omitempty" json:"external-controller-cors,omitempty"`
	ExternalUI              string            `yaml:"external-ui,omitempty" json:"external-ui,omitempty"`
	ExternalUIURL           string            `yaml:"external-ui-url,omitempty" json:"external-ui-url,omitempty"`
	ExternalUIName          string            `yaml:"external-ui-name,omitempty" json:"external-ui-name,omitempty"`
	ExternalDohServer       string            `yaml:"external-doh-server,omitempty" json:"external-doh-server,omitempty"`
	Secret                  string            `yaml:"secret,omitempty" json:"secret,omitempty"`
	Interface               string            `yaml:"interface-name,omitempty" json:"interface-name,omitempty"`
	RoutingMark             int               `yaml:"routing-mark,omitempty" json:"routing-mark,omitempty"`
	Tunnels                 []LC.Tunnel       `yaml:"tunnels,omitempty" json:"tunnels,omitempty"`
	GeoAutoUpdate           bool              `yaml:"geo-auto-update,omitempty" json:"geo-auto-update,omitempty"`
	GeoUpdateInterval       int               `yaml:"geo-update-interval,omitempty" json:"geo-update-interval,omitempty"`
	GeodataMode             bool              `yaml:"geodata-mode,omitempty" json:"geodata-mode,omitempty"`
	GeodataLoader           string            `yaml:"geodata-loader,omitempty" json:"geodata-loader,omitempty"`
	GeositeMatcher          string            `yaml:"geosite-matcher,omitempty" json:"geosite-matcher,omitempty"`
	TCPConcurrent           bool              `yaml:"tcp-concurrent,omitempty" json:"tcp-concurrent,omitempty"`
	FindProcessMode         P.FindProcessMode `yaml:"find-process-mode,omitempty" json:"find-process-mode,omitempty"`
	GlobalClientFingerprint string            `yaml:"global-client-fingerprint,omitempty" json:"global-client-fingerprint,omitempty"`
	GlobalUA                string            `yaml:"global-ua,omitempty" json:"global-ua,omitempty"`
	ETagSupport             bool              `yaml:"etag-support,omitempty" json:"etag-support,omitempty"`
	KeepAliveIdle           int               `yaml:"keep-alive-idle,omitempty" json:"keep-alive-idle,omitempty"`
	KeepAliveInterval       int               `yaml:"keep-alive-interval,omitempty" json:"keep-alive-interval,omitempty"`
	DisableKeepAlive        bool              `yaml:"disable-keep-alive,omitempty" json:"disable-keep-alive,omitempty"`

	ProxyProvider map[string]map[string]any `yaml:"proxy-providers,omitempty" json:"proxy-providers,omitempty"`
	RuleProvider  map[string]map[string]any `yaml:"rule-providers,omitempty" json:"rule-providers,omitempty"`
	Proxy         []map[string]any          `yaml:"proxies,omitempty" json:"proxies,omitempty"`
	ProxyGroup    []map[string]any          `yaml:"proxy-groups,omitempty" json:"proxy-groups,omitempty"`
	Rule          []string                  `yaml:"rules,omitempty" json:"rules,omitempty"`
	SubRules      map[string][]string       `yaml:"sub-rules,omitempty" json:"sub-rules,omitempty"`
	Listeners     []map[string]any          `yaml:"listeners,omitempty" json:"listeners,omitempty"`
	Hosts         map[string]any            `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	DNS           RawDNS                    `yaml:"dns,omitempty" json:"dns,omitempty"`
	NTP           RawNTP                    `yaml:"ntp,omitempty" json:"ntp,omitempty"`
	Tun           RawTun                    `yaml:"tun,omitempty" json:"tun,omitempty"`
	TuicServer    RawTuicServer             `yaml:"tuic-server,omitempty" json:"tuic-server,omitempty"`
	IPTables      RawIPTables               `yaml:"iptables,omitempty" json:"iptables,omitempty"`
	Experimental  RawExperimental           `yaml:"experimental,omitempty" json:"experimental,omitempty"`
	Profile       RawProfile                `yaml:"profile,omitempty" json:"profile,omitempty"`
	GeoXUrl       RawGeoXUrl                `yaml:"geox-url,omitempty" json:"geox-url,omitempty"`
	Sniffer       RawSniffer                `yaml:"sniffer,omitempty" json:"sniffer,omitempty"`
	TLS           RawTLS                    `yaml:"tls,omitempty" json:"tls,omitempty"`

	ClashForAndroid RawClashForAndroid `yaml:"clash-for-android,omitempty" json:"clash-for-android,omitempty"`
}

var (
	GroupsList             = list.New()
	ProxiesList            = list.New()
	ParsingProxiesCallback func(groupsList *list.List, proxiesList *list.List)
)

// Parse config
func Parse(buf []byte) (*Config, error) {
	rawCfg, err := UnmarshalRawConfig(buf)
	if err != nil {
		return nil, err
	}

	return ParseRawConfig(rawCfg)
}

func DefaultRawConfig() *RawConfig {
	return &RawConfig{
		AllowLan:          false,
		BindAddress:       "*",
		LanAllowedIPs:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		IPv6:              true,
		Mode:              T.Rule,
		GeoAutoUpdate:     false,
		GeoUpdateInterval: 24,
		GeodataMode:       geodata.GeodataMode(),
		GeodataLoader:     "memconservative",
		UnifiedDelay:      false,
		Authentication:    []string{},
		LogLevel:          log.INFO,
		Hosts:             map[string]any{},
		Rule:              []string{},
		Proxy:             []map[string]any{},
		ProxyGroup:        []map[string]any{},
		TCPConcurrent:     false,
		FindProcessMode:   P.FindProcessStrict,
		GlobalUA:          "clash.meta/" + C.Version,
		ETagSupport:       true,
		DNS: RawDNS{
			Enable:         false,
			IPv6:           false,
			UseHosts:       true,
			UseSystemHosts: true,
			IPv6Timeout:    100,
			EnhancedMode:   C.DNSMapping,
			FakeIPRange:    "198.18.0.1/16",
			FallbackFilter: RawFallbackFilter{
				GeoIP:     true,
				GeoIPCode: "CN",
				IPCIDR:    []string{},
				GeoSite:   []string{},
			},
			DefaultNameserver: []string{
				"114.114.114.114",
				"223.5.5.5",
				"8.8.8.8",
				"1.0.0.1",
			},
			NameServer: []string{
				"https://doh.pub/dns-query",
				"tls://223.5.5.5:853",
			},
			FakeIPFilter: []string{
				"dns.msftnsci.com",
				"www.msftnsci.com",
				"www.msftconnecttest.com",
			},
			FakeIPFilterMode: C.FilterBlackList,
		},
		NTP: RawNTP{
			Enable:        false,
			WriteToSystem: false,
			Server:        "time.apple.com",
			Port:          123,
			Interval:      30,
		},
		Tun: RawTun{
			Enable:              false,
			Device:              "",
			Stack:               C.TunGvisor,
			DNSHijack:           []string{"0.0.0.0:53"}, // default hijack all dns query
			AutoRoute:           true,
			AutoDetectInterface: true,
			Inet6Address:        []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		},
		TuicServer: RawTuicServer{
			Enable:                false,
			Token:                 nil,
			Users:                 nil,
			Certificate:           "",
			PrivateKey:            "",
			Listen:                "",
			CongestionController:  "",
			MaxIdleTime:           15000,
			AuthenticationTimeout: 1000,
			ALPN:                  []string{"h3"},
			MaxUdpRelayPacketSize: 1500,
		},
		IPTables: RawIPTables{
			Enable:           false,
			InboundInterface: "lo",
			Bypass:           []string{},
			DnsRedirect:      true,
		},
		Experimental: RawExperimental{
			// https://github.com/quic-go/quic-go/issues/4178
			// Quic-go currently cannot automatically fall back on platforms that do not support ecn, so this feature is turned off by default.
			QUICGoDisableECN: true,
		},
		Profile: RawProfile{
			StoreSelected: true,
		},
		GeoXUrl: RawGeoXUrl{
			Mmdb:    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
			ASN:     "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb",
			GeoIp:   "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
			GeoSite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
		},
		Sniffer: RawSniffer{
			Enable:          false,
			Sniff:           map[string]RawSniffingConfig{},
			ForceDomain:     []string{},
			SkipDomain:      []string{},
			Ports:           []string{},
			ForceDnsMapping: true,
			ParsePureIp:     true,
			OverrideDest:    true,
		},
		ExternalUIURL: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
		ExternalControllerCors: RawCors{
			AllowOrigins:        []string{"*"},
			AllowPrivateNetwork: true,
		},
	}
}

func UnmarshalRawConfig(buf []byte) (*RawConfig, error) {
	// config with default value
	rawCfg := DefaultRawConfig()

	if err := yaml.Unmarshal(buf, rawCfg); err != nil {
		return nil, err
	}

	return rawCfg, nil
}

func ParseRawConfig(rawCfg *RawConfig) (*Config, error) {
	config := &Config{}
	log.Infoln("Start initial configuration in progress") //Segment finished in xxm
	startTime := time.Now()

	general, err := parseGeneral(rawCfg)
	if err != nil {
		return nil, err
	}
	config.General = general

	// We need to temporarily apply some configuration in general and roll back after parsing the complete configuration.
	// The loading and downloading of geodata in the parseRules and parseRuleProviders rely on these.
	// This implementation is very disgusting, but there is currently no better solution
	rollback := temporaryUpdateGeneral(config.General)
	defer rollback()

	controller, err := parseController(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Controller = controller

	experimental, err := parseExperimental(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Experimental = experimental

	iptables, err := parseIPTables(rawCfg)
	if err != nil {
		return nil, err
	}
	config.IPTables = iptables

	ntpCfg, err := parseNTP(rawCfg)
	if err != nil {
		return nil, err
	}
	config.NTP = ntpCfg

	profile, err := parseProfile(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Profile = profile

	tlsCfg, err := parseTLS(rawCfg)
	if err != nil {
		return nil, err
	}
	config.TLS = tlsCfg

	proxies, providers, err := parseProxies(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Proxies = proxies
	config.Providers = providers

	listener, err := parseListeners(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Listeners = listener

	log.Infoln("Geodata Loader mode: %s", geodata.LoaderName())
	log.Infoln("Geosite Matcher implementation: %s", geodata.SiteMatcherName())
	ruleProviders, err := parseRuleProviders(rawCfg)
	if err != nil {
		return nil, err
	}
	config.RuleProviders = ruleProviders

	subRules, err := parseSubRules(rawCfg, proxies, ruleProviders)
	if err != nil {
		return nil, err
	}
	config.SubRules = subRules

	rules, err := parseRules(rawCfg.Rule, proxies, ruleProviders, subRules, "rules")
	if err != nil {
		return nil, err
	}
	config.Rules = rules

	hosts, err := parseHosts(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Hosts = hosts

	dnsCfg, err := parseDNS(rawCfg, hosts, ruleProviders)
	if err != nil {
		return nil, err
	}
	config.DNS = dnsCfg

	err = parseTun(rawCfg.Tun, config.General)
	if err != nil {
		return nil, err
	}

	err = parseTuicServer(rawCfg.TuicServer, config.General)
	if err != nil {
		return nil, err
	}

	config.Users = parseAuthentication(rawCfg.Authentication)

	config.Tunnels = rawCfg.Tunnels
	// verify tunnels
	for _, t := range config.Tunnels {
		if len(t.Proxy) > 0 {
			if _, ok := config.Proxies[t.Proxy]; !ok {
				return nil, fmt.Errorf("tunnel proxy %s not found", t.Proxy)
			}
		}
	}

	config.Sniffer, err = parseSniffer(rawCfg.Sniffer, ruleProviders)
	if err != nil {
		return nil, err
	}

	elapsedTime := time.Since(startTime) / time.Millisecond                     // duration in ms
	log.Infoln("Initial configuration complete, total time: %dms", elapsedTime) //Segment finished in xxm

	return config, nil
}

//go:linkname temporaryUpdateGeneral
func temporaryUpdateGeneral(general *General) func()

func parseGeneral(cfg *RawConfig) (*General, error) {
	return &General{
		Inbound: Inbound{
			Port:              cfg.Port,
			SocksPort:         cfg.SocksPort,
			RedirPort:         cfg.RedirPort,
			TProxyPort:        cfg.TProxyPort,
			MixedPort:         cfg.MixedPort,
			ShadowSocksConfig: cfg.ShadowSocksConfig,
			VmessConfig:       cfg.VmessConfig,
			AllowLan:          cfg.AllowLan,
			SkipAuthPrefixes:  cfg.SkipAuthPrefixes,
			LanAllowedIPs:     cfg.LanAllowedIPs,
			LanDisAllowedIPs:  cfg.LanDisAllowedIPs,
			BindAddress:       cfg.BindAddress,
			InboundTfo:        cfg.InboundTfo,
			InboundMPTCP:      cfg.InboundMPTCP,
		},
		UnifiedDelay: cfg.UnifiedDelay,
		Mode:         cfg.Mode,
		LogLevel:     cfg.LogLevel,
		IPv6:         cfg.IPv6,
		Interface:    cfg.Interface,
		RoutingMark:  cfg.RoutingMark,
		GeoXUrl: GeoXUrl{
			GeoIp:   cfg.GeoXUrl.GeoIp,
			Mmdb:    cfg.GeoXUrl.Mmdb,
			ASN:     cfg.GeoXUrl.ASN,
			GeoSite: cfg.GeoXUrl.GeoSite,
		},
		GeoAutoUpdate:           cfg.GeoAutoUpdate,
		GeoUpdateInterval:       cfg.GeoUpdateInterval,
		GeodataMode:             cfg.GeodataMode,
		GeodataLoader:           cfg.GeodataLoader,
		GeositeMatcher:          cfg.GeositeMatcher,
		TCPConcurrent:           cfg.TCPConcurrent,
		FindProcessMode:         cfg.FindProcessMode,
		GlobalClientFingerprint: cfg.GlobalClientFingerprint,
		GlobalUA:                cfg.GlobalUA,
		ETagSupport:             cfg.ETagSupport,
		KeepAliveIdle:           cfg.KeepAliveIdle,
		KeepAliveInterval:       cfg.KeepAliveInterval,
		DisableKeepAlive:        cfg.DisableKeepAlive,
	}, nil
}

func parseController(cfg *RawConfig) (*Controller, error) {
	return &Controller{
		ExternalController:     cfg.ExternalController,
		ExternalUI:             cfg.ExternalUI,
		ExternalUIURL:          cfg.ExternalUIURL,
		ExternalUIName:         cfg.ExternalUIName,
		Secret:                 cfg.Secret,
		ExternalControllerPipe: cfg.ExternalControllerPipe,
		ExternalControllerUnix: cfg.ExternalControllerUnix,
		ExternalControllerTLS:  cfg.ExternalControllerTLS,
		ExternalDohServer:      cfg.ExternalDohServer,
		Cors: Cors{
			AllowOrigins:        cfg.ExternalControllerCors.AllowOrigins,
			AllowPrivateNetwork: cfg.ExternalControllerCors.AllowPrivateNetwork,
		},
	}, nil
}

func parseExperimental(cfg *RawConfig) (*Experimental, error) {
	return &Experimental{
		Fingerprints:     cfg.Experimental.Fingerprints,
		QUICGoDisableGSO: cfg.Experimental.QUICGoDisableGSO,
		QUICGoDisableECN: cfg.Experimental.QUICGoDisableECN,
		IP4PEnable:       cfg.Experimental.IP4PEnable,
	}, nil
}

func parseIPTables(cfg *RawConfig) (*IPTables, error) {
	return &IPTables{
		Enable:           cfg.IPTables.Enable,
		InboundInterface: cfg.IPTables.InboundInterface,
		Bypass:           cfg.IPTables.Bypass,
		DnsRedirect:      cfg.IPTables.DnsRedirect,
	}, nil
}

func parseNTP(cfg *RawConfig) (*NTP, error) {
	return &NTP{
		Enable:        cfg.NTP.Enable,
		Server:        cfg.NTP.Server,
		Port:          cfg.NTP.Port,
		Interval:      cfg.NTP.Interval,
		DialerProxy:   cfg.NTP.DialerProxy,
		WriteToSystem: cfg.NTP.WriteToSystem,
	}, nil
}

func parseProfile(cfg *RawConfig) (*Profile, error) {
	return &Profile{
		StoreSelected: cfg.Profile.StoreSelected,
		StoreFakeIP:   cfg.Profile.StoreFakeIP,
	}, nil
}

func parseTLS(cfg *RawConfig) (*TLS, error) {
	return &TLS{
		Certificate:     cfg.TLS.Certificate,
		PrivateKey:      cfg.TLS.PrivateKey,
		CustomTrustCert: cfg.TLS.CustomTrustCert,
	}, nil
}

func parseProxies(cfg *RawConfig) (proxies map[string]C.Proxy, providersMap map[string]providerTypes.ProxyProvider, err error) {
	proxies = make(map[string]C.Proxy)
	providersMap = make(map[string]providerTypes.ProxyProvider)
	proxiesConfig := cfg.Proxy
	groupsConfig := cfg.ProxyGroup
	providersConfig := cfg.ProxyProvider

	var (
		proxyList  []string
		AllProxies []string
		hasGlobal  bool
	)
	proxiesList := list.New()
	groupsList := list.New()

	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
	proxies["REJECT-DROP"] = adapter.NewProxy(outbound.NewRejectDrop())
	proxies["COMPATIBLE"] = adapter.NewProxy(outbound.NewCompatible())
	proxies["PASS"] = adapter.NewProxy(outbound.NewPass())
	proxyList = append(proxyList, "DIRECT", "REJECT")

	// parse proxy
	for idx, mapping := range proxiesConfig {
		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy %d: %w", idx, err)
		}

		if _, exist := proxies[proxy.Name()]; exist {
			return nil, nil, fmt.Errorf("proxy %s is the duplicate name", proxy.Name())
		}
		proxies[proxy.Name()] = proxy
		proxyList = append(proxyList, proxy.Name())
		AllProxies = append(AllProxies, proxy.Name())
		proxiesList.PushBack(mapping)
	}

	// keep the original order of ProxyGroups in config file
	for idx, mapping := range groupsConfig {
		groupName, existName := mapping["name"].(string)
		if !existName {
			return nil, nil, fmt.Errorf("proxy group %d: missing name", idx)
		}
		if groupName == "GLOBAL" {
			hasGlobal = true
		}
		proxyList = append(proxyList, groupName)
		groupsList.PushBack(mapping)
	}

	// check if any loop exists and sort the ProxyGroups
	if err := proxyGroupsDagSort(groupsConfig); err != nil {
		return nil, nil, err
	}

	var AllProviders []string
	// parse and initial providers
	for name, mapping := range providersConfig {
		if name == provider.ReservedName {
			return nil, nil, fmt.Errorf("can not defined a provider called `%s`", provider.ReservedName)
		}

		pd, err := provider.ParseProxyProvider(name, mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("parse proxy provider %s error: %w", name, err)
		}

		providersMap[name] = pd
		AllProviders = append(AllProviders, name)
	}

	slices.Sort(AllProxies)
	slices.Sort(AllProviders)

	// parse proxy group
	for idx, mapping := range groupsConfig {
		group, err := outboundgroup.ParseProxyGroup(mapping, proxies, providersMap, AllProxies, AllProviders)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy group[%d]: %w", idx, err)
		}

		groupName := group.Name()
		if _, exist := proxies[groupName]; exist {
			return nil, nil, fmt.Errorf("proxy group %s: the duplicate name", groupName)
		}

		proxies[groupName] = adapter.NewProxy(group)
	}

	var ps []C.Proxy
	for _, v := range proxyList {
		if proxies[v].Type() == C.Pass {
			continue
		}
		ps = append(ps, proxies[v])
	}
	hc := provider.NewHealthCheck(ps, "", 5000, 0, true, nil)
	pd, _ := provider.NewCompatibleProvider(provider.ReservedName, ps, hc)
	providersMap[provider.ReservedName] = pd

	if !hasGlobal {
		global := outboundgroup.NewSelector(
			&outboundgroup.GroupCommonOption{
				Name: "GLOBAL",
			},
			[]providerTypes.ProxyProvider{pd},
		)
		proxies["GLOBAL"] = adapter.NewProxy(global)
	}
	ProxiesList = proxiesList
	GroupsList = groupsList
	if ParsingProxiesCallback != nil {
		// refresh tray menu
		go ParsingProxiesCallback(GroupsList, ProxiesList)
	}
	return proxies, providersMap, nil
}

func parseListeners(cfg *RawConfig) (listeners map[string]C.InboundListener, err error) {
	listeners = make(map[string]C.InboundListener)
	for index, mapping := range cfg.Listeners {
		listener, err := L.ParseListener(mapping)
		if err != nil {
			return nil, fmt.Errorf("proxy %d: %w", index, err)
		}

		if _, exist := mapping[listener.Name()]; exist {
			return nil, fmt.Errorf("listener %s is the duplicate name", listener.Name())
		}

		listeners[listener.Name()] = listener

	}
	return
}

func parseRuleProviders(cfg *RawConfig) (ruleProviders map[string]providerTypes.RuleProvider, err error) {
	RP.SetTunnel(T.Tunnel)
	ruleProviders = map[string]providerTypes.RuleProvider{}
	// parse rule provider
	for name, mapping := range cfg.RuleProvider {
		rp, err := RP.ParseRuleProvider(name, mapping, R.ParseRule)
		if err != nil {
			return nil, err
		}

		ruleProviders[name] = rp
	}
	return
}

func parseSubRules(cfg *RawConfig, proxies map[string]C.Proxy, ruleProviders map[string]providerTypes.RuleProvider) (subRules map[string][]C.Rule, err error) {
	subRules = map[string][]C.Rule{}
	for name := range cfg.SubRules {
		subRules[name] = make([]C.Rule, 0)
	}
	for name, rawRules := range cfg.SubRules {
		if len(name) == 0 {
			return nil, fmt.Errorf("sub-rule name is empty")
		}
		var rules []C.Rule
		rules, err = parseRules(rawRules, proxies, ruleProviders, subRules, fmt.Sprintf("sub-rules[%s]", name))
		if err != nil {
			return nil, err
		}
		subRules[name] = rules
	}

	if err = verifySubRule(subRules); err != nil {
		return nil, err
	}

	return
}

func verifySubRule(subRules map[string][]C.Rule) error {
	for name := range subRules {
		err := verifySubRuleCircularReferences(name, subRules, []string{})
		if err != nil {
			return err
		}
	}
	return nil
}

func verifySubRuleCircularReferences(n string, subRules map[string][]C.Rule, arr []string) error {
	isInArray := func(v string, array []string) bool {
		for _, c := range array {
			if v == c {
				return true
			}
		}
		return false
	}

	arr = append(arr, n)
	for i, rule := range subRules[n] {
		if rule.RuleType() == C.SubRules {
			if _, ok := subRules[rule.Adapter()]; !ok {
				return fmt.Errorf("sub-rule[%d:%s] error: [%s] not found", i, n, rule.Adapter())
			}
			if isInArray(rule.Adapter(), arr) {
				arr = append(arr, rule.Adapter())
				return fmt.Errorf("sub-rule error: circular references [%s]", strings.Join(arr, "->"))
			}

			if err := verifySubRuleCircularReferences(rule.Adapter(), subRules, arr); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseRules(rulesConfig []string, proxies map[string]C.Proxy, ruleProviders map[string]providerTypes.RuleProvider, subRules map[string][]C.Rule, format string) ([]C.Rule, error) {
	var rules []C.Rule

	// parse rules
	for idx, line := range rulesConfig {
		rule := trimArr(strings.Split(line, ","))
		var (
			payload  string
			target   string
			params   []string
			ruleName = strings.ToUpper(rule[0])
		)

		l := len(rule)

		if ruleName == "NOT" || ruleName == "OR" || ruleName == "AND" || ruleName == "SUB-RULE" || ruleName == "DOMAIN-REGEX" || ruleName == "PROCESS-NAME-REGEX" || ruleName == "PROCESS-PATH-REGEX" {
			target = rule[l-1]
			payload = strings.Join(rule[1:l-1], ",")
		} else {
			if l < 2 {
				return nil, fmt.Errorf("%s[%d] [%s] error: format invalid", format, idx, line)
			}
			if l < 4 {
				rule = append(rule, make([]string, 4-l)...)
			}
			if ruleName == "MATCH" {
				l = 2
			}
			if l >= 3 {
				l = 3
				payload = rule[1]
			}
			target = rule[l-1]
			params = rule[l:]
		}
		if _, ok := proxies[target]; !ok {
			if ruleName != "SUB-RULE" {
				return nil, fmt.Errorf("%s[%d] [%s] error: proxy [%s] not found", format, idx, line, target)
			} else if _, ok = subRules[target]; !ok {
				return nil, fmt.Errorf("%s[%d] [%s] error: sub-rule [%s] not found", format, idx, line, target)
			}
		}

		params = trimArr(params)
		parsed, parseErr := R.ParseRule(ruleName, payload, target, params, subRules)
		if parseErr != nil {
			return nil, fmt.Errorf("%s[%d] [%s] error: %s", format, idx, line, parseErr.Error())
		}

		for _, name := range parsed.ProviderNames() {
			if _, ok := ruleProviders[name]; !ok {
				return nil, fmt.Errorf("%s[%d] [%s] error: rule set [%s] not found", format, idx, line, name)
			}
		}

		rules = append(rules, parsed)
	}

	return rules, nil
}

func parseHosts(cfg *RawConfig) (*trie.DomainTrie[resolver.HostValue], error) {
	tree := trie.New[resolver.HostValue]()

	// add default hosts
	hostValue, _ := resolver.NewHostValueByIPs(
		[]netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})})
	if err := tree.Insert("localhost", hostValue); err != nil {
		log.Errorln("insert localhost to host error: %s", err.Error())
	}

	if len(cfg.Hosts) != 0 {
		for domain, anyValue := range cfg.Hosts {
			if str, ok := anyValue.(string); ok && str == "lan" {
				if addrs, err := net.InterfaceAddrs(); err != nil {
					log.Errorln("insert lan to host error: %s", err)
				} else {
					ips := make([]netip.Addr, 0)
					for _, addr := range addrs {
						if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
							if ip, err := netip.ParseAddr(ipnet.IP.String()); err == nil {
								ips = append(ips, ip)
							}
						}
					}
					anyValue = ips
				}
			}
			value, err := resolver.NewHostValue(anyValue)
			if err != nil {
				return nil, fmt.Errorf("%s is not a valid value", anyValue)
			}
			if value.IsDomain {
				node := tree.Search(value.Domain)
				for node != nil && node.Data().IsDomain {
					if node.Data().Domain == domain {
						return nil, fmt.Errorf("%s, there is a cycle in domain name mapping", domain)
					}
					node = tree.Search(node.Data().Domain)
				}
			}
			_ = tree.Insert(domain, value)
		}
	}
	tree.Optimize()

	return tree, nil
}

func hostWithDefaultPort(host string, defPort string) (string, error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return "", err
		}
		host = host + ":" + defPort
		if hostname, port, err = net.SplitHostPort(host); err != nil {
			return "", err
		}
	}

	return net.JoinHostPort(hostname, port), nil
}

func parseNameServer(servers []string, respectRules bool, preferH3 bool) ([]dns.NameServer, error) {
	var nameservers []dns.NameServer

	for idx, server := range servers {
		server = parsePureDNSServer(server)
		u, err := url.Parse(server)
		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		proxyName := u.Fragment

		var addr, dnsNetType string
		params := map[string]string{}
		switch u.Scheme {
		case "udp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "" // UDP
		case "tcp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "tcp" // TCP
		case "tls":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "tcp-tls" // DNS over TLS
		case "http", "https":
			addr, err = hostWithDefaultPort(u.Host, "443")
			dnsNetType = "https" // DNS over HTTPS
			if u.Scheme == "http" {
				addr, err = hostWithDefaultPort(u.Host, "80")
			}
			if err == nil {
				proxyName = ""
				clearURL := url.URL{Scheme: u.Scheme, Host: addr, Path: u.Path, User: u.User}
				addr = clearURL.String()
				if len(u.Fragment) != 0 {
					for _, s := range strings.Split(u.Fragment, "&") {
						arr := strings.Split(s, "=")
						if len(arr) == 0 {
							continue
						} else if len(arr) == 1 {
							proxyName = arr[0]
						} else if len(arr) == 2 {
							params[arr[0]] = arr[1]
						} else {
							params[arr[0]] = strings.Join(arr[1:], "=")
						}
					}
				}
			}
		case "quic":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "quic" // DNS over QUIC
		case "system":
			dnsNetType = "system" // System DNS
		case "dhcp":
			addr = server[len("dhcp://"):] // some special notation cannot be parsed by url
			dnsNetType = "dhcp"            // UDP from DHCP
			if addr == "system" {          // Compatible with old writing "dhcp://system"
				dnsNetType = "system"
				addr = ""
			}
		case "rcode":
			dnsNetType = "rcode"
			addr = u.Host
			switch addr {
			case "success",
				"format_error",
				"server_failure",
				"name_error",
				"not_implemented",
				"refused":
			default:
				err = fmt.Errorf("unsupported RCode type: %s", addr)
			}
		default:
			return nil, fmt.Errorf("DNS NameServer[%d] unsupport scheme: %s", idx, u.Scheme)
		}

		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		if respectRules && len(proxyName) == 0 {
			proxyName = dns.RespectRules
		}

		nameserver := dns.NameServer{
			Net:       dnsNetType,
			Addr:      addr,
			ProxyName: proxyName,
			Params:    params,
			PreferH3:  preferH3,
		}
		if slices.ContainsFunc(nameservers, nameserver.Equal) {
			continue // skip duplicates nameserver
		}

		nameservers = append(nameservers, nameserver)
	}
	return nameservers, nil
}

func init() {
	dns.ParseNameServer = func(servers []string) ([]dns.NameServer, error) { // using by wireguard
		return parseNameServer(servers, false, false)
	}
}

func parsePureDNSServer(server string) string {
	addPre := func(server string) string {
		return "udp://" + server
	}

	if server == "system" {
		return "system://"
	}

	if ip, err := netip.ParseAddr(server); err != nil {
		if strings.Contains(server, "://") {
			return server
		}
		return addPre(server)
	} else {
		if ip.Is4() {
			return addPre(server)
		} else {
			return addPre("[" + server + "]")
		}
	}
}

func parseNameServerPolicy(nsPolicy *orderedmap.OrderedMap[string, any], ruleProviders map[string]providerTypes.RuleProvider, respectRules bool, preferH3 bool) ([]dns.Policy, error) {
	var policy []dns.Policy

	for pair := nsPolicy.Oldest(); pair != nil; pair = pair.Next() {
		k, v := pair.Key, pair.Value
		servers, err := utils.ToStringSlice(v)
		if err != nil {
			return nil, err
		}
		nameservers, err := parseNameServer(servers, respectRules, preferH3)
		if err != nil {
			return nil, err
		}
		kLower := strings.ToLower(k)
		if strings.Contains(kLower, ",") {
			if strings.Contains(kLower, "geosite:") {
				subkeys := strings.Split(k, ":")
				subkeys = subkeys[1:]
				subkeys = strings.Split(subkeys[0], ",")
				for _, subkey := range subkeys {
					newKey := "geosite:" + subkey
					policy = append(policy, dns.Policy{Domain: newKey, NameServers: nameservers})
				}
			} else if strings.Contains(kLower, "rule-set:") {
				subkeys := strings.Split(k, ":")
				subkeys = subkeys[1:]
				subkeys = strings.Split(subkeys[0], ",")
				for _, subkey := range subkeys {
					newKey := "rule-set:" + subkey
					policy = append(policy, dns.Policy{Domain: newKey, NameServers: nameservers})
				}
			} else {
				subkeys := strings.Split(k, ",")
				for _, subkey := range subkeys {
					policy = append(policy, dns.Policy{Domain: subkey, NameServers: nameservers})
				}
			}
		} else {
			if strings.Contains(kLower, "geosite:") {
				policy = append(policy, dns.Policy{Domain: "geosite:" + k[8:], NameServers: nameservers})
			} else if strings.Contains(kLower, "rule-set:") {
				policy = append(policy, dns.Policy{Domain: "rule-set:" + k[9:], NameServers: nameservers})
			} else {
				policy = append(policy, dns.Policy{Domain: k, NameServers: nameservers})
			}
		}
	}

	for idx, p := range policy {
		domain, nameservers := p.Domain, p.NameServers

		if strings.HasPrefix(domain, "rule-set:") {
			domainSetName := domain[9:]
			matcher, err := parseDomainRuleSet(domainSetName, "dns.nameserver-policy", ruleProviders)
			if err != nil {
				return nil, err
			}
			policy[idx] = dns.Policy{Matcher: matcher, NameServers: nameservers}
		} else if strings.HasPrefix(domain, "geosite:") {
			country := domain[8:]
			matcher, err := RC.NewGEOSITE(country, "dns.nameserver-policy")
			if err != nil {
				return nil, err
			}
			policy[idx] = dns.Policy{Matcher: matcher, NameServers: nameservers}
		} else {
			if _, valid := trie.ValidAndSplitDomain(domain); !valid {
				return nil, fmt.Errorf("DNS ResoverRule invalid domain: %s", domain)
			}
		}
	}

	return policy, nil
}

func parseDNS(rawCfg *RawConfig, hosts *trie.DomainTrie[resolver.HostValue], ruleProviders map[string]providerTypes.RuleProvider) (*DNS, error) {
	cfg := rawCfg.DNS
	if cfg.Enable && len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("if DNS configuration is turned on, NameServer cannot be empty")
	}

	if cfg.RespectRules && len(cfg.ProxyServerNameserver) == 0 {
		return nil, fmt.Errorf("if “respect-rules” is turned on, “proxy-server-nameserver” cannot be empty")
	}

	dnsCfg := &DNS{
		Enable:         cfg.Enable,
		Listen:         cfg.Listen,
		PreferH3:       cfg.PreferH3,
		IPv6Timeout:    cfg.IPv6Timeout,
		IPv6:           cfg.IPv6,
		UseSystemHosts: cfg.UseSystemHosts,
		EnhancedMode:   cfg.EnhancedMode,
	}
	var err error
	if dnsCfg.NameServer, err = parseNameServer(cfg.NameServer, cfg.RespectRules, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.Fallback, err = parseNameServer(cfg.Fallback, cfg.RespectRules, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.NameServerPolicy, err = parseNameServerPolicy(cfg.NameServerPolicy, ruleProviders, cfg.RespectRules, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.ProxyServerNameserver, err = parseNameServer(cfg.ProxyServerNameserver, false, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.DirectNameServer, err = parseNameServer(cfg.DirectNameServer, false, cfg.PreferH3); err != nil {
		return nil, err
	}
	dnsCfg.DirectFollowPolicy = cfg.DirectNameServerFollowPolicy

	if len(cfg.DefaultNameserver) == 0 {
		return nil, errors.New("default nameserver should have at least one nameserver")
	}
	if dnsCfg.DefaultNameserver, err = parseNameServer(cfg.DefaultNameserver, false, cfg.PreferH3); err != nil {
		return nil, err
	}
	// check default nameserver is pure ip addr
	for _, ns := range dnsCfg.DefaultNameserver {
		if ns.Net == "system" {
			continue
		}
		host, _, err := net.SplitHostPort(ns.Addr)
		if err != nil || net.ParseIP(host) == nil {
			u, err := url.Parse(ns.Addr)
			if err == nil && net.ParseIP(u.Host) == nil {
				if ip, _, err := net.SplitHostPort(u.Host); err != nil || net.ParseIP(ip) == nil {
					return nil, errors.New("default nameserver should be pure IP")
				}
			}
		}
	}

	fakeIPRange, err := netip.ParsePrefix(cfg.FakeIPRange)
	T.SetFakeIPRange(fakeIPRange)
	if cfg.EnhancedMode == C.DNSFakeIP {
		if err != nil {
			return nil, err
		}

		var fakeIPTrie *trie.DomainTrie[struct{}]
		if len(dnsCfg.Fallback) != 0 {
			fakeIPTrie = trie.New[struct{}]()
			for _, fb := range dnsCfg.Fallback {
				if net.ParseIP(fb.Addr) != nil {
					continue
				}
				_ = fakeIPTrie.Insert(fb.Addr, struct{}{})
			}
		}

		// fake ip skip host filter
		host, err := parseDomain(cfg.FakeIPFilter, fakeIPTrie, "dns.fake-ip-filter", ruleProviders)
		if err != nil {
			return nil, err
		}

		pool, err := fakeip.New(fakeip.Options{
			IPNet:       fakeIPRange,
			Size:        1000,
			Host:        host,
			Mode:        cfg.FakeIPFilterMode,
			Persistence: rawCfg.Profile.StoreFakeIP,
		})
		if err != nil {
			return nil, err
		}

		dnsCfg.FakeIPRange = pool
	}

	if len(cfg.Fallback) != 0 {
		if cfg.FallbackFilter.GeoIP {
			matcher, err := RC.NewGEOIP(cfg.FallbackFilter.GeoIPCode, "dns.fallback-filter.geoip", false, true)
			if err != nil {
				return nil, fmt.Errorf("load GeoIP dns fallback filter error, %w", err)
			}
			dnsCfg.FallbackIPFilter = append(dnsCfg.FallbackIPFilter, matcher.DnsFallbackFilter())
		}
		if len(cfg.FallbackFilter.IPCIDR) > 0 {
			cidrSet := cidr.NewIpCidrSet()
			for idx, ipcidr := range cfg.FallbackFilter.IPCIDR {
				err = cidrSet.AddIpCidrForString(ipcidr)
				if err != nil {
					return nil, fmt.Errorf("DNS FallbackIP[%d] format error: %w", idx, err)
				}
			}
			err = cidrSet.Merge()
			if err != nil {
				return nil, err
			}
			matcher := cidrSet // dns.fallback-filter.ipcidr
			dnsCfg.FallbackIPFilter = append(dnsCfg.FallbackIPFilter, matcher)
		}
		if len(cfg.FallbackFilter.Domain) > 0 {
			domainTrie := trie.New[struct{}]()
			for idx, domain := range cfg.FallbackFilter.Domain {
				err = domainTrie.Insert(domain, struct{}{})
				if err != nil {
					return nil, fmt.Errorf("DNS FallbackDomain[%d] format error: %w", idx, err)
				}
			}
			matcher := domainTrie.NewDomainSet() // dns.fallback-filter.domain
			dnsCfg.FallbackDomainFilter = append(dnsCfg.FallbackDomainFilter, matcher)
		}
		if len(cfg.FallbackFilter.GeoSite) > 0 {
			log.Warnln("replace fallback-filter.geosite with nameserver-policy, it will be removed in the future")
			for idx, geoSite := range cfg.FallbackFilter.GeoSite {
				matcher, err := RC.NewGEOSITE(geoSite, "dns.fallback-filter.geosite")
				if err != nil {
					return nil, fmt.Errorf("DNS FallbackGeosite[%d] format error: %w", idx, err)
				}
				dnsCfg.FallbackDomainFilter = append(dnsCfg.FallbackDomainFilter, matcher)
			}
		}
	}

	if cfg.UseHosts {
		dnsCfg.Hosts = hosts
	}

	if cfg.CacheAlgorithm == "" || cfg.CacheAlgorithm == "lru" {
		dnsCfg.CacheAlgorithm = "lru"
	} else {
		dnsCfg.CacheAlgorithm = "arc"
	}

	return dnsCfg, nil
}

func parseAuthentication(rawRecords []string) []auth.AuthUser {
	var users []auth.AuthUser
	for _, line := range rawRecords {
		if user, pass, found := strings.Cut(line, ":"); found {
			users = append(users, auth.AuthUser{User: user, Pass: pass})
		}
	}
	return users
}

func parseTun(rawTun RawTun, general *General) error {
	tunAddressPrefix := T.FakeIPRange()
	if !tunAddressPrefix.IsValid() {
		tunAddressPrefix = netip.MustParsePrefix("198.18.0.1/16")
	}
	tunAddressPrefix = netip.PrefixFrom(tunAddressPrefix.Addr(), 30)

	if !general.IPv6 || !verifyIP6() {
		rawTun.Inet6Address = nil
	}

	general.Tun = LC.Tun{
		Enable:              rawTun.Enable,
		Device:              rawTun.Device,
		Stack:               rawTun.Stack,
		DNSHijack:           rawTun.DNSHijack,
		AutoRoute:           rawTun.AutoRoute,
		AutoDetectInterface: rawTun.AutoDetectInterface,

		MTU:                    rawTun.MTU,
		GSO:                    rawTun.GSO,
		GSOMaxSize:             rawTun.GSOMaxSize,
		Inet4Address:           []netip.Prefix{tunAddressPrefix},
		Inet6Address:           rawTun.Inet6Address,
		IPRoute2TableIndex:     rawTun.IPRoute2TableIndex,
		IPRoute2RuleIndex:      rawTun.IPRoute2RuleIndex,
		AutoRedirect:           rawTun.AutoRedirect,
		AutoRedirectInputMark:  rawTun.AutoRedirectInputMark,
		AutoRedirectOutputMark: rawTun.AutoRedirectOutputMark,
		StrictRoute:            rawTun.StrictRoute,
		RouteAddress:           rawTun.RouteAddress,
		RouteAddressSet:        rawTun.RouteAddressSet,
		RouteExcludeAddress:    rawTun.RouteExcludeAddress,
		RouteExcludeAddressSet: rawTun.RouteExcludeAddressSet,
		IncludeInterface:       rawTun.IncludeInterface,
		ExcludeInterface:       rawTun.ExcludeInterface,
		IncludeUID:             rawTun.IncludeUID,
		IncludeUIDRange:        rawTun.IncludeUIDRange,
		ExcludeUID:             rawTun.ExcludeUID,
		ExcludeUIDRange:        rawTun.ExcludeUIDRange,
		IncludeAndroidUser:     rawTun.IncludeAndroidUser,
		IncludePackage:         rawTun.IncludePackage,
		ExcludePackage:         rawTun.ExcludePackage,
		EndpointIndependentNat: rawTun.EndpointIndependentNat,
		UDPTimeout:             rawTun.UDPTimeout,
		FileDescriptor:         rawTun.FileDescriptor,

		Inet4RouteAddress:        rawTun.Inet4RouteAddress,
		Inet6RouteAddress:        rawTun.Inet6RouteAddress,
		Inet4RouteExcludeAddress: rawTun.Inet4RouteExcludeAddress,
		Inet6RouteExcludeAddress: rawTun.Inet6RouteExcludeAddress,
	}

	return nil
}

func parseTuicServer(rawTuic RawTuicServer, general *General) error {
	general.TuicServer = LC.TuicServer{
		Enable:                rawTuic.Enable,
		Listen:                rawTuic.Listen,
		Token:                 rawTuic.Token,
		Users:                 rawTuic.Users,
		Certificate:           rawTuic.Certificate,
		PrivateKey:            rawTuic.PrivateKey,
		CongestionController:  rawTuic.CongestionController,
		MaxIdleTime:           rawTuic.MaxIdleTime,
		AuthenticationTimeout: rawTuic.AuthenticationTimeout,
		ALPN:                  rawTuic.ALPN,
		MaxUdpRelayPacketSize: rawTuic.MaxUdpRelayPacketSize,
		CWND:                  rawTuic.CWND,
	}
	return nil
}

func parseSniffer(snifferRaw RawSniffer, ruleProviders map[string]providerTypes.RuleProvider) (*sniffer.Config, error) {
	snifferConfig := &sniffer.Config{
		Enable:          snifferRaw.Enable,
		ForceDnsMapping: snifferRaw.ForceDnsMapping,
		ParsePureIp:     snifferRaw.ParsePureIp,
	}
	loadSniffer := make(map[snifferTypes.Type]sniffer.SnifferConfig)

	if len(snifferRaw.Sniff) != 0 {
		for sniffType, sniffConfig := range snifferRaw.Sniff {
			find := false
			ports, err := utils.NewUnsignedRangesFromList[uint16](sniffConfig.Ports)
			if err != nil {
				return nil, err
			}
			overrideDest := snifferRaw.OverrideDest
			if sniffConfig.OverrideDest != nil {
				overrideDest = *sniffConfig.OverrideDest
			}
			for _, snifferType := range snifferTypes.List {
				if snifferType.String() == strings.ToUpper(sniffType) {
					find = true
					loadSniffer[snifferType] = sniffer.SnifferConfig{
						Ports:        ports,
						OverrideDest: overrideDest,
					}
				}
			}

			if !find {
				return nil, fmt.Errorf("not find the sniffer[%s]", sniffType)
			}
		}
	} else {
		if snifferConfig.Enable && len(snifferRaw.Sniffing) != 0 {
			// Deprecated: Use Sniff instead
			log.Warnln("Deprecated: Use Sniff instead")
		}
		globalPorts, err := utils.NewUnsignedRangesFromList[uint16](snifferRaw.Ports)
		if err != nil {
			return nil, err
		}

		for _, snifferName := range snifferRaw.Sniffing {
			find := false
			for _, snifferType := range snifferTypes.List {
				if snifferType.String() == strings.ToUpper(snifferName) {
					find = true
					loadSniffer[snifferType] = sniffer.SnifferConfig{
						Ports:        globalPorts,
						OverrideDest: snifferRaw.OverrideDest,
					}
				}
			}

			if !find {
				return nil, fmt.Errorf("not find the sniffer[%s]", snifferName)
			}
		}
	}

	snifferConfig.Sniffers = loadSniffer

	forceDomain, err := parseDomain(snifferRaw.ForceDomain, nil, "sniffer.force-domain", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in force-domain, error:%w", err)
	}
	snifferConfig.ForceDomain = forceDomain

	skipSrcAddress, err := parseIPCIDR(snifferRaw.SkipSrcAddress, nil, "sniffer.skip-src-address", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in skip-src-address, error:%w", err)
	}
	snifferConfig.SkipSrcAddress = skipSrcAddress

	skipDstAddress, err := parseIPCIDR(snifferRaw.SkipDstAddress, nil, "sniffer.skip-src-address", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in skip-dst-address, error:%w", err)
	}
	snifferConfig.SkipDstAddress = skipDstAddress

	skipDomain, err := parseDomain(snifferRaw.SkipDomain, nil, "sniffer.skip-domain", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in skip-domain, error:%w", err)
	}
	snifferConfig.SkipDomain = skipDomain

	return snifferConfig, nil
}

func parseIPCIDR(addresses []string, cidrSet *cidr.IpCidrSet, adapterName string, ruleProviders map[string]providerTypes.RuleProvider) (matchers []C.IpMatcher, err error) {
	var matcher C.IpMatcher
	for _, ipcidr := range addresses {
		ipcidrLower := strings.ToLower(ipcidr)
		if strings.Contains(ipcidrLower, "geoip:") {
			subkeys := strings.Split(ipcidr, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, country := range subkeys {
				matcher, err = RC.NewGEOIP(country, adapterName, false, false)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else if strings.Contains(ipcidrLower, "rule-set:") {
			subkeys := strings.Split(ipcidr, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, domainSetName := range subkeys {
				matcher, err = parseIPRuleSet(domainSetName, adapterName, ruleProviders)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else {
			if cidrSet == nil {
				cidrSet = cidr.NewIpCidrSet()
			}
			err = cidrSet.AddIpCidrForString(ipcidr)
			if err != nil {
				return nil, err
			}
		}
	}
	if !cidrSet.IsEmpty() {
		err = cidrSet.Merge()
		if err != nil {
			return nil, err
		}
		matcher = cidrSet
		matchers = append(matchers, matcher)
	}
	return
}

func parseDomain(domains []string, domainTrie *trie.DomainTrie[struct{}], adapterName string, ruleProviders map[string]providerTypes.RuleProvider) (matchers []C.DomainMatcher, err error) {
	var matcher C.DomainMatcher
	for _, domain := range domains {
		domainLower := strings.ToLower(domain)
		if strings.Contains(domainLower, "geosite:") {
			subkeys := strings.Split(domain, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, country := range subkeys {
				matcher, err = RC.NewGEOSITE(country, adapterName)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else if strings.Contains(domainLower, "rule-set:") {
			subkeys := strings.Split(domain, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, domainSetName := range subkeys {
				matcher, err = parseDomainRuleSet(domainSetName, adapterName, ruleProviders)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else {
			if domainTrie == nil {
				domainTrie = trie.New[struct{}]()
			}
			err = domainTrie.Insert(domain, struct{}{})
			if err != nil {
				return nil, err
			}
		}
	}
	if !domainTrie.IsEmpty() {
		matcher = domainTrie.NewDomainSet()
		matchers = append(matchers, matcher)
	}
	return
}

func parseIPRuleSet(domainSetName string, adapterName string, ruleProviders map[string]providerTypes.RuleProvider) (C.IpMatcher, error) {
	if rp, ok := ruleProviders[domainSetName]; !ok {
		return nil, fmt.Errorf("not found rule-set: %s", domainSetName)
	} else {
		switch rp.Behavior() {
		case providerTypes.Domain:
			return nil, fmt.Errorf("rule provider type error, except ipcidr,actual %s", rp.Behavior())
		case providerTypes.Classical:
			log.Warnln("%s provider is %s, only matching it contain ip rule", rp.Name(), rp.Behavior())
		default:
		}
	}
	return RP.NewRuleSet(domainSetName, adapterName, false, true)
}

func parseDomainRuleSet(domainSetName string, adapterName string, ruleProviders map[string]providerTypes.RuleProvider) (C.DomainMatcher, error) {
	if rp, ok := ruleProviders[domainSetName]; !ok {
		return nil, fmt.Errorf("not found rule-set: %s", domainSetName)
	} else {
		switch rp.Behavior() {
		case providerTypes.IPCIDR:
			return nil, fmt.Errorf("rule provider type error, except domain,actual %s", rp.Behavior())
		case providerTypes.Classical:
			log.Warnln("%s provider is %s, only matching it contain domain rule", rp.Name(), rp.Behavior())
		default:
		}
	}
	return RP.NewRuleSet(domainSetName, adapterName, false, true)
}
