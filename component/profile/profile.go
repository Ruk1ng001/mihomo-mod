package profile

import (
	"github.com/Ruk1ng001/mihomo-mod/common/atomic"
)

// StoreSelected is a global switch for storing selected proxy to cache
var StoreSelected = atomic.NewBool(true)
