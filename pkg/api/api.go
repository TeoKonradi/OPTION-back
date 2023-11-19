package api

import (
	"github.com/wawilow108/option/pkg/config"
)

type Api struct {
	Session *config.Session
}

func NewApi(session *config.Session) *Api {
	return &Api{
		Session: session,
	}
}
