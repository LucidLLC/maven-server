package util

import (
	"crypto/rand"
	"encoding/base64"
)

func RandomString() string {
	b := make([]byte, 40)
	rand.Read(b)
	str := base64.StdEncoding.EncodeToString(b)

	return str
}
