package auth

import (
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

func ValidateJWT(token string, c echo.Context) (bool, error) {
	var claims jwt.MapClaims

	parsedJWT, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid token")
		}

		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return false, err
	}

	if !parsedJWT.Valid {
		return false, errors.New("invalid token")
	}

	c.Set("userId", claims["sub"])

	return true, nil
}
