package model

import (
	"regexp"
	"time"
)

var (
	UsernamePattern = regexp.MustCompile(`([A-Za-z0-9_]{3,16})`)
)

type User struct {
	Id           string    `bson:"_id"`
	CreatedAt    time.Time `bson:"createdAt"`
	Username     string    `bson:"username"`
	PasswordHash string    `bson:"passwordHash"`
	DisplayName  string    `bson:"displayName"`
	Permissions  []string  `bson:"permissions"`
}
