package routes

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/ninjaswtf/maven/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var (
	UsernamePattern = regexp.MustCompile("^([a-zA-Z0-9_]{3,16})$")
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
		authGroup.POST("/login", u.Login)
		authGroup.POST("/refresh", u.Refresh)
	}
}

func (u *UserRoutesHandler) Signup(c echo.Context) error {
	var signupRequest AuthRequest

	if err := c.Bind(&signupRequest); err != nil {
		log.Println(err)
		return c.JSON(http.StatusBadRequest, model.NewError(http.StatusBadRequest, "invalid body"))
	}

	if !UsernamePattern.MatchString(signupRequest.Username) {
		return c.JSON(http.StatusBadRequest, "invalid username")
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

	authToken, refreshToken, err := createTokenPairForUser(createdUser.Id)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, model.NewError(http.StatusInternalServerError, err.Error()))
	}

	c.SetCookie(&http.Cookie{
		Name:     "mavenRefreshToken",
		Value:    refreshToken,
		Expires:  createdAt.Add(7 * 24 * time.Hour),
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
		HttpOnly: true,
	})

	return c.String(http.StatusOK, authToken)
}

func (u *UserRoutesHandler) Login(c echo.Context) error {
	var signinRequest AuthRequest

	if err := c.Bind(&signinRequest); err != nil {
		log.Println(err)
		return c.JSON(http.StatusBadRequest, model.NewError(http.StatusBadRequest, "invalid body"))
	}

	result := u.DB.Collection("users").FindOne(context.Background(), bson.M{
		"$text": bson.M{
			"$search":        signinRequest.Username,
			"$caseSensitive": false,
		},
	})

	if err := result.Err(); err != nil {
		return c.JSON(http.StatusUnauthorized, "could not find user")
	}

	var user model.User

	if err := result.Decode(&user); err != nil {
		return c.JSON(http.StatusUnauthorized, "could not find user")
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(signinRequest.Password))

	// passwords don't match - disallow login
	if err != nil {
		return c.JSON(http.StatusUnauthorized, "incorrect password")
	}

	now := time.Now()
	authToken, refreshToken, err := createTokenPairForUser(user.Id)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, model.NewError(http.StatusInternalServerError, err.Error()))
	}

	c.SetCookie(&http.Cookie{
		Name:     "mavenRefreshToken",
		Value:    refreshToken,
		Expires:  now.Add(7 * 24 * time.Hour),
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
		HttpOnly: true,
	})

	return c.String(http.StatusOK, authToken)
}

func (*UserRoutesHandler) Refresh(c echo.Context) error {
	refreshToken, err := c.Cookie("mavenRefreshToken")

	if err != nil {
		return c.String(http.StatusUnauthorized, "no token found")
	}

	var claims jwt.MapClaims

	parsedJWT, err := jwt.ParseWithClaims(refreshToken.Value, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid token")
		}

		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	if !parsedJWT.Valid {
		return c.String(http.StatusUnauthorized, "invalid token")
	}

	if claims["use"] != "refresh" {
		return c.String(http.StatusUnauthorized, "invalid use of token")
	}

	newAuthToken, newRefreshToken, err := createTokenPairForUser(claims["sub"].(string))

	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	now := time.Now()

	c.SetCookie(&http.Cookie{
		Name:     "mavenRefreshToken",
		Value:    newRefreshToken,
		Expires:  now.Add(7 * 24 * time.Hour),
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
		HttpOnly: true,
	})

	return c.String(http.StatusOK, newAuthToken)

}

func (*UserRoutesHandler) Logout(c echo.Context) error {
	c.SetCookie(&http.Cookie{
		Name:     "mavenRefreshToken",
		Secure:   true,
		Expires:  time.Now(),
		SameSite: http.SameSiteNoneMode,
		HttpOnly: true,
	})
	return c.String(http.StatusOK, "logged out")
}

func (*UserRoutesHandler) GenerateToken(c echo.Context) error {
	return nil
}

func createTokenPairForUser(userId string) (string, string, error) {

	createdAt := time.Now()
	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat": jwt.NewNumericDate(createdAt),
		"sub": userId,
		"exp": jwt.NewNumericDate(createdAt.Add(24 * time.Hour)),
		"use": "identity",
		"scopes": []string{
			model.IdentityScope,
		},
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat": jwt.NewNumericDate(createdAt),
		"sub": userId,
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
