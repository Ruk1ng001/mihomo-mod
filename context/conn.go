package context

import (
	"github.com/Ruk1ng001/mihomo-mod/common/utils"
	"net"

	N "github.com/Ruk1ng001/mihomo-mod/common/net"
	C "github.com/Ruk1ng001/mihomo-mod/constant"

	"github.com/gofrs/uuid/v5"
)

type ConnContext struct {
	id       uuid.UUID
	metadata *C.Metadata
	conn     *N.BufferedConn
}

func NewConnContext(conn net.Conn, metadata *C.Metadata) *ConnContext {
	return &ConnContext{
		id:       utils.NewUUIDV4(),
		metadata: metadata,
		conn:     N.NewBufferedConn(conn),
	}
}

// ID implement C.ConnContext ID
func (c *ConnContext) ID() uuid.UUID {
	return c.id
}

// Metadata implement C.ConnContext Metadata
func (c *ConnContext) Metadata() *C.Metadata {
	return c.metadata
}

// Conn implement C.ConnContext Conn
func (c *ConnContext) Conn() *N.BufferedConn {
	return c.conn
}
