package routes

import "github.com/labstack/echo/v4"

type RouteRegistrar interface {
	Register(*echo.Group)
}

type UserRoutes interface {
	RouteRegistrar
	Signup(c echo.Context) error
	Login(c echo.Context) error
	Logout(c echo.Context) error
	GenerateToken(c echo.Context) error
}

type TeamRoutes interface {
	RouteRegistrar
	Create(c echo.Context) error
	Delete(c echo.Context) error
	AddMember(c echo.Context) error
	RemoveMember(c echo.Context) error
}

type RepositoryRoutes interface {
	RouteRegistrar
	Upload(c echo.Context) error
	Download(c echo.Context) error
}

type ArtifactRoutes interface {
	RouteRegistrar
	Get(c echo.Context) error
	Delete(c echo.Context) error
}
