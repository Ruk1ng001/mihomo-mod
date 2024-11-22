package constant

import (
	"net"

	N "github.com/ruk1ng001/mihomo-mod/common/net"

	"github.com/gofrs/uuid/v5"
)

type PlainContext interface {
	ID() uuid.UUID
}

type ConnContext interface {
	PlainContext
	Metadata() *Metadata
	Conn() *N.BufferedConn
}

type PacketConnContext interface {
	PlainContext
	Metadata() *Metadata
	PacketConn() net.PacketConn
}
