package inbound

import (
	"github.com/ruk1ng001/mihomo-mod/component/auth"
	authStore "github.com/ruk1ng001/mihomo-mod/listener/auth"
)

type AuthUser struct {
	Username string `inbound:"username"`
	Password string `inbound:"password"`
}

type AuthUsers []AuthUser

func (a AuthUsers) GetAuthStore() auth.AuthStore {
	if a != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
		if len(a) == 0 {
			return authStore.Nil
		}
		users := make([]auth.AuthUser, len(a))
		for i, user := range a {
			users[i] = auth.AuthUser{
				User: user.Username,
				Pass: user.Password,
			}
		}
		authenticator := auth.NewAuthenticator(users)
		return authStore.NewAuthStore(authenticator)
	}
	return authStore.Default
}
