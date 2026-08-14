package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type Resolver struct{}

func (Resolver) Resolve(_ context.Context, reference string) (string, error) {
	reference = strings.TrimSpace(reference)
	switch {
	case strings.HasPrefix(reference, "env://"):
		name := strings.TrimPrefix(reference, "env://")
		if name == "" {
			return "", fmt.Errorf("empty environment secret name")
		}
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			return "", fmt.Errorf("environment secret %s is not configured", name)
		}
		return value, nil
	case strings.HasPrefix(reference, "file://"):
		path := strings.TrimPrefix(reference, "file://")
		if path == "" {
			return "", fmt.Errorf("empty secret file path")
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		value := strings.TrimSpace(string(content))
		if value == "" {
			return "", fmt.Errorf("secret file is empty")
		}
		return value, nil
	case strings.HasPrefix(reference, "secret://"), strings.HasPrefix(reference, "vault://"):
		return "", fmt.Errorf("external secret provider is not configured for %s", reference)
	default:
		return "", fmt.Errorf("unsupported secret reference")
	}
}
