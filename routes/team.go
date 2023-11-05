package routes

import (
	"context"
	"log"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/ninjaswtf/maven/middleware/auth"
	"github.com/ninjaswtf/maven/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type TeamRoutesHandler struct {
	RouteRegistrar
	DB *mongo.Database
}

func (t *TeamRoutesHandler) Register(e *echo.Group) {
	teamGroup := e.Group("/team")
	{
		teamGroup.POST("/create", t.Create, middleware.KeyAuth(auth.ValidateJWT))
	}
}

type TeamCreationRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}
type TeamDeletionRequest struct {
	Name string
}

type TeamAddMemberRequest struct {
	Name string
}
type TeamRemoveMemberRequest struct {
	Name string
}

func (t *TeamRoutesHandler) Create(c echo.Context) error {
	var teamCreateRequest TeamCreationRequest

	if err := c.Bind(&teamCreateRequest); err != nil {
		log.Println(err)
		return c.JSON(http.StatusBadRequest, model.NewError(http.StatusBadRequest, "invalid body"))
	}

	cursor, err := t.DB.Collection("teams").Aggregate(context.Background(), bson.A{
		bson.D{
			bson.E{Key: "$match",
				Value: bson.D{
					bson.E{Key: "$text",
						Value: bson.D{
							bson.E{Key: "$search", Value: teamCreateRequest.Name},
							bson.E{Key: "$caseSensitive", Value: false},
						},
					},
				},
			},
		},
		bson.D{bson.E{Key: "$count", Value: "matching_names"}},
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, model.NewError(http.StatusInternalServerError, err.Error()))
	}

	teamCounts := cursor.RemainingBatchLength()

	if teamCounts > 0 {
		cursor.Close(context.Background())
		return c.JSON(http.StatusBadRequest, model.NewError(http.StatusBadRequest, "team name taken"))
	}

	teamId, _ := uuid.NewV4()

	creatorId := c.Get("userId").(string)

	team := &model.Team{
		Id:          teamId.String(),
		Name:        teamCreateRequest.Name,
		DisplayName: teamCreateRequest.DisplayName,
		Members: map[string]model.TeamMember{
			creatorId: model.TeamMember{
				ID:          creatorId,
				Permissions: []string{model.TeamOwner},
			},
		},
	}

	_, err = t.DB.Collection("teams").InsertOne(context.Background(), team)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, model.NewError(http.StatusInternalServerError, err.Error()))
	}

	return c.JSON(http.StatusOK, team)
}
func Delete(c echo.Context) error {
	return nil
}
func AddMember(c echo.Context) error {
	return nil
}
func RemoveMember(c echo.Context) error {
	return nil
}
