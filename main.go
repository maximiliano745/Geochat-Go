package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"

	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"github.com/maximiliano745/Geochat-Go/pkg/websocket"
)

var SECRET_KEY = []byte("gosecretkey")

type User struct {
	FirstName string `json:"firstname" bson:"firstname"`
	LastName  string `json:"lastname" bson:"lastname"`
	Email     string `json:"email" bson:"email"`
	Password  string `json:"password" bson:"password"`
}

type Email struct {
	Email string `json:"email" bson:"email"`
	Name  string `json:"name" bson:"name"`
	Msg   string `json:"message" bson:"message"`
}

func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

func GenerateJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, err := token.SignedString(SECRET_KEY)
	if err != nil {
		log.Println("Error in JWT token generation")
		return "", err
	}
	return tokenString, nil
}

func userLogin(response http.ResponseWriter, request *http.Request) {

	response.Header().Set("Content-Type", "application/json")
	var user User
	var dbuser User

	json.NewDecoder(request.Body).Decode(&user)

	fmt.Println("")
	fmt.Println("\n -------------- Aca estamos en el Login. ---------------- ")
	fmt.Println("")

	collection := client.Database("geochat").Collection("user")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbuser)
	cancel()

	if err == nil {

		fmt.Println("Login Email Existente...")
		response.Write([]byte(`{"message": Email Existente......"` + `"}`))

		userPass := []byte(user.Password)
		dbPass := []byte(dbuser.Password)

		passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)

		if passErr != nil {
			log.Println("passErr: ", passErr)
			response.Write([]byte(`{false}`))
			return
		}
		jwtToken, err := GenerateJWT()
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{"message":"` + err.Error() + `"}`))
			return
		}
		log.Println("\nUsuario: ", user)

		response.Write([]byte(`{"Usuario":"` + user.Email + `"}`))
		response.Write([]byte(`{"token":"` + jwtToken + `"}`))
		response.Write([]byte(`{"true"}`))

		return
	} else {
		fmt.Println("Login Email Inexistente: ", err)
		response.Write([]byte(`{false}`))
		return

	}

}

func userSignup(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	var user User
	var dbuser User

	json.NewDecoder(request.Body).Decode(&user)

	//log.Print(user.Email)

	collection := client.Database("geochat").Collection("user")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbuser)
	cancel()

	if err == nil {
		fmt.Println("Signuo Email Existente: ", err)
		response.Write([]byte(`{"message": Email Existente"` + `"}`))
		return
	} else {

		user.Password = getHash([]byte(user.Password))
		collection := client.Database("geochat").Collection("user")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cancel()
		result, _ := collection.InsertOne(ctx, user)
		json.NewEncoder(response).Encode(result)
		fmt.Println("Signup: Guardado Con Exito......")
		response.Write([]byte(`{"message": Signup Guardado Con Exito"` + `"}`))
	}

}

func userEmail(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	var mail Email
	json.NewDecoder(request.Body).Decode(&mail)

	auth := smtp.PlainAuth("", "maxiargento745@gmail.com", "rwkycxemzftxidxi", "smtp.gmail.com")

	to := []string{mail.Email}
	msg := []byte("To: " + mail.Email + "\r\n" +
		"Subject: Geochat..!!!\r\n" +
		"\r\n" +
		"Esto es la Invitacion de Contacto de GEOCHAT  ---------------->   " + mail.Msg + "")
	err := smtp.SendMail("smtp.gmail.com:587", auth, "maxiargento745@gmail.com", to, msg)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("Email enviado con exito...!!!!!")
	}
}

func serveWs(pool *websocket.Pool, w http.ResponseWriter, r *http.Request) {
	fmt.Println("----------------  WebSocket Endpoint Hit -------------------")
	conn, err := websocket.Upgrade(w, r)
	if err != nil {
		fmt.Fprintf(w, "%+v\n", err)
	}

	client := &websocket.Client{
		Conn: conn,
		Pool: pool,
	}

	pool.Register <- client
	client.Read()
}

var client *mongo.Client

func main() {

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},                  // All origins
		AllowedMethods: []string{"GET", "POST", "PUT"}, // Allowing only get, just an example
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	client, _ = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	cancel()

	router := mux.NewRouter()
	router.HandleFunc("/api/user/login", userLogin).Methods("GET")
	http.Handle("/", router)

	router.HandleFunc("/api/user/login", userLogin).Methods("POST")
	router.HandleFunc("/api/user/signup", userSignup).Methods("POST")
	router.HandleFunc("/api/user/mail", userEmail).Methods("POST")

	pool := websocket.NewPool()
	go pool.Start()

	router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(pool, w, r)
	})

	port := "8080"
	log.Println("Aplication Comenzo en: " + port)
	log.Fatal(http.ListenAndServe(":8080", c.Handler(router)))

}
