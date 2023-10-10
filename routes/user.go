package routes

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/ninjaswtf/maven/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthResponse struct{}

type UserRoutesHandler struct {
	DB *mongo.Database
}

func (u *UserRoutesHandler) Register(e *echo.Group) {
	authGroup := e.Group("/auth")
	{
		authGroup.POST("/signup", u.Signup)
	}
}

func (u *UserRoutesHandler) Signup(c echo.Context) error {
	var signupRequest AuthRequest

	if err := c.Bind(&signupRequest); err != nil {
		log.Println(err)
		return c.JSON(http.StatusBadRequest, model.NewError(http.StatusBadRequest, "invalid body"))
	}

	cursor, err := u.DB.Collection("users").Aggregate(context.Background(), bson.A{
		bson.D{
			bson.E{Key: "$match",
				Value: bson.D{
					bson.E{Key: "$text",
						Value: bson.D{
							bson.E{Key: "$search", Value: signupRequest.Username},
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

	userCounts := cursor.RemainingBatchLength()

	if userCounts > 0 {
		cursor.Close(context.Background())
		return c.JSON(http.StatusBadRequest, model.NewError(http.StatusBadRequest, "username taken"))
	}

	// create the user

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(signupRequest.Password), 12)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, model.NewError(http.StatusInternalServerError, err.Error()))
	}

	userId, _ := uuid.NewV4()

	createdAt := time.Now()

	createdUser := &model.User{
		Id:           userId.String(),
		Username:     signupRequest.Username,
		DisplayName:  signupRequest.Username,
		PasswordHash: string(hashedPassword),
		Permissions:  []string{},
	}

	u.DB.Collection("users").InsertOne(context.Background(), createdUser)

	authToken, refreshToken, err := createTokenPairForUser(createdUser)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, model.NewError(http.StatusInternalServerError, err.Error()))
	}

	cookie := new(http.Cookie)
	{
		cookie.Name = "mavenRefreshToken"
		cookie.Value = refreshToken
		cookie.Expires = createdAt.Add(7 * 24 * time.Hour)
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Secure = true
		cookie.HttpOnly = true
	}
	c.SetCookie(cookie)

	return c.String(http.StatusOK, authToken)
}

func (u *UserRoutesHandler) Login(c echo.Context) error {
	u.DB.Collection("users").FindOne(context.Background(), bson.M{
		"$text": bson.M{
			"$search":        "",
			"$caseSensitive": true,
		},
	})
	return nil
}
func (*UserRoutesHandler) Logout(c echo.Context) error {
	c.SetCookie(&http.Cookie{
		Name:     "mavenRefreshToken",
		Secure:   true,
		Expires:  time.Now(),
		SameSite: http.SameSiteNoneMode,
		HttpOnly: true,
	})
	return nil
}
func (*UserRoutesHandler) GenerateToken(c echo.Context) error {
	return nil
}

func createTokenPairForUser(user *model.User) (string, string, error) {

	createdAt := time.Now()
	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat": jwt.NewNumericDate(createdAt),
		"sub": user.Id,
		"exp": jwt.NewNumericDate(createdAt.Add(24 * time.Hour)),
		"use": "identity",
		"scopes": []string{
			model.IdentityScope,
		},
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat": jwt.NewNumericDate(createdAt),
		"sub": user.Id,
		"exp": jwt.NewNumericDate(createdAt.Add(7 * 24 * time.Hour)),
		"use": "refresh",
	})

	signedAuthToken, err := authToken.SignedString([]byte(os.Getenv("JWT_SECRET")))

	if err != nil {
		return "", "", err
	}
	signedRefreshToken, err := refreshToken.SignedString([]byte(os.Getenv("JWT_SECRET")))

	if err != nil {
		return "", "", err
	}

	return signedAuthToken, signedRefreshToken, nil
}
