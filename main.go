package main

import (
	"context"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/ninjaswtf/maven/routes"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mongoDBConnection *mongo.Client
)

func init() {
	godotenv.Load()

	connection, err := mongo.Connect(context.Background(), options.Client().ApplyURI(os.Getenv("MONGODB_URI")))

	if err != nil {
		log.Fatalln(err)
	}

	mongoDBConnection = connection
}

func main() {

	userHandler := &routes.UserRoutesHandler{
		DB: mongoDBConnection.Database(os.Getenv("MONGODB_DATABASE")),
	}

	e := echo.New()

	defaultConfig := middleware.DefaultCORSConfig

	defaultConfig.AllowCredentials = true

	defaultConfig.AllowOriginFunc = func(origin string) (bool, error) {
		return true, nil
	}
	e.Use(middleware.CORSWithConfig(defaultConfig))

	apiGroup := e.Group("/v1/api")

	userHandler.Register(apiGroup)

	e.Start(":1337")

	// http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	if r.Method == http.MethodGet {
	// 		f, err := os.Open("." + r.URL.String())

	// 		if err != nil {
	// 			w.WriteHeader(404)
	// 			return
	// 		}

	// 		content, _ := io.ReadAll(f)

	// 		w.WriteHeader(200)
	// 		w.Write(content)
	// 	} else if r.Method == http.MethodPut {
	// 		// would do a verification or something here

	// 		path := r.URL.String()

	// 		directory, file := filepath.Split("./" + path)

	// 		os.MkdirAll(directory, os.ModePerm)

	// 		b, _ := io.ReadAll(r.Body)
	// 		if file == "maven-metadata.xml" {

	// 			var metadata util.ArtifactMetadata

	// 			log.Println(xml.Unmarshal(b, &metadata), metadata)
	// 		}

	// 		os.WriteFile("./"+path, b, os.ModePerm)
	// 	}
	// })
	// http.ListenAndServe(":1337", nil)
}
