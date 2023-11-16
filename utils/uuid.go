// File: pkg/utils/uuid.go

package utils

import (
	"github.com/clwg/netsecutils/config"
	"github.com/google/uuid"
)

// GenerateUUIDv5 generates a UUID version 5 based on the provided name.
func GenerateUUIDv5(name string) (uuid.UUID, error) {
	namespace, err := uuid.Parse(config.UUIDv5Namespace)
	if err != nil {
		return uuid.Nil, err // Return an error if the namespace UUID is invalid
	}
	return uuid.NewSHA1(namespace, []byte(name)), nil
}