package model

import (
	"github.com/gofrs/uuid"
)

type Team struct {
	Id          uuid.UUID `bson:"_id"`
	Name        string    `bson:"name"`
	DisplayName string    `bson:"displayName"`

	Members []uuid.UUID `bson:"members"`
}
