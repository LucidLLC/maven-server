package model

import (
	"fmt"
)

type TeamMember struct {
	ID          string   `bson:"_id"`
	Permissions []string `bson:"permissions"`
}

func (t *TeamMember) HasPermission(s string) error {
	for _, x := range t.Permissions {
		if x == s {
			return nil
		}
	}
	return fmt.Errorf("team member does not have permission '%s'", s)
}

type Team struct {
	Id          string `bson:"_id"`
	Name        string `bson:"name"`
	DisplayName string `bson:"displayName"`

	Members map[string]TeamMember `bson:"members"`
}
