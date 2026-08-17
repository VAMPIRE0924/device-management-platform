package nodeadapter

import "fmt"

type TaskRef struct {
	Type string `json:"type"`
	ID   int    `json:"id"`
}

var allowedTaskTypes = map[string]struct{}{
	"portForward": {},
	"socks5":      {},
	"httpProxy":   {},
	"secret":      {},
	"p2p":         {},
	"file":        {},
}

func (ref TaskRef) Validate() error {
	if _, allowed := allowedTaskTypes[ref.Type]; !allowed {
		return fmt.Errorf("unsupported NPS task type %q", ref.Type)
	}
	if ref.ID < 1 {
		return fmt.Errorf("NPS task id must be positive")
	}
	return nil
}

func (ref TaskRef) Key() (string, error) {
	if err := ref.Validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d", ref.Type, ref.ID), nil
}
