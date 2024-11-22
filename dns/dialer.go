package dns

// export functions from tunnel module

import "github.com/ruk1ng001/mihomo-mod/tunnel"

const RespectRules = tunnel.DnsRespectRules

type dnsDialer = tunnel.DNSDialer

var newDNSDialer = tunnel.NewDNSDialer
