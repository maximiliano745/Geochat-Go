package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
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

type Task struct {
	ID   string `json:"id"`
	Name string `json:"name"`
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

// Login Native------------------------------------------------------------------------- NATIVO------------
func userLoginNative(w http.ResponseWriter, r *http.Request) {

	var status bool
	var msg string

	fmt.Println("\n -------------- Aca estamos en el Login Nativo. ---------------- ")

	if r.Method != http.MethodPost {
		msg = "Error metodo request"
		http.Error(w, "Error metodo request", http.StatusMethodNotAllowed)
		return
	}

	var formData User
	if err := json.NewDecoder(r.Body).Decode(&formData); err != nil {
		msg = "Error NewDecorer..."
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	fmt.Println("Email:", formData.Email)
	fmt.Println("Password:", formData.Password)

	// Incluir el correo electrónico en las reclamaciones
	claims := jwt.MapClaims{
		"email": formData.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(), // Caducidad del token
	}

	// Generar el token JWT con las reclamaciones
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	mySecret := "secret-secret"
	signedToken, err := token.SignedString([]byte(mySecret))
	if err != nil {
		msg = "Error al generar el token"
		http.Error(w, "Error al generar el token", http.StatusInternalServerError)
		return
	} else {
		fmt.Println("signedToken :" + signedToken)
		//fmt.Println("Token: ", token)
	}

	responseData := map[string]interface{}{

		"status": status,
		"msg":    msg,
		"token":  signedToken, // Envía el token firmado en la respuesta
	}

	// Convertir el mapa a formato JSON
	jsonResponse, err := json.Marshal(responseData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		msg = "Error al generar respuesta JSON"
		http.Error(w, "Error al generar respuesta JSON", http.StatusInternalServerError)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println("aca claims: ", claims["email"], claims["exp"])
	}

	// Establecer la cabecera Content-Type y enviar la respuesta JSON al cliente
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func userLogin(response http.ResponseWriter, request *http.Request) {

	var status bool
	var msg string
	var nombre string

	response.Header().Set("Content-Type", "application/json")
	var user User
	var dbuser User

	json.NewDecoder(request.Body).Decode(&user)

	fmt.Println("")
	fmt.Println("\n -------------- Aca estamos en el Login. ---------------- ")
	//fmt.Println("------------mail: ", user.Email)

	collection := client.Database("geochat").Collection("user")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := collection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&dbuser)
	cancel()

	fmt.Println(dbuser.FirstName)
	nombre = dbuser.FirstName

	responseData := make(map[string]interface{})

	if err == nil {

		status = true
		fmt.Println("Login Email Existente...")
		msg = "Login Email Existente..."
		//response.Write([]byte(`{"message": Email Existente......"` + `"}`))

		userPass := []byte(user.Password)
		dbPass := []byte(dbuser.Password)

		passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)

		if passErr != nil {
			log.Println("passErr: ", passErr)
			msg = "error con el password...."
			//response.Write([]byte(`{false}`))
			return
		}
		jwtToken, err := GenerateJWT()
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			//response.Write([]byte(`{"message":"` + err.Error() + `"}`))
			msg = "error con el password...."
			response.Write([]byte(msg))

			return
		}

		log.Println("mail: ", user.Email)
		log.Println("token: ", jwtToken)
		log.Println("status: ", status)
		log.Println("msg: ", msg)

		//log.Println("-------------------------------------------------------------")

		//response.Write([]byte(`{"Usuario":"` + user.Email + `"}`))
		//response.Write([]byte(`{"token":"` + jwtToken + `"}`))
		//response.Write([]byte(`{"true"}`))

		responseData["status"] = status
		responseData["msg"] = msg
		responseData["mail"] = user.Email
		responseData["token"] = jwtToken
		responseData["nombre"] = nombre

		// Convertir el mapa a formato JSON
		jsonResponse, err := json.Marshal(responseData)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{"message":"Error al generar respuesta JSON"}`))
			return
		}

		// Enviar la respuesta JSON al cliente
		response.Header().Set("Content-Type", "application/json")
		response.Write(jsonResponse)

		return
	} else {
		status = false
		fmt.Println("Login Email Inexistente: ", err)
		msg = "Login Email Inexistente..."
		//response.Write([]byte(`{false}`))
		log.Println("status: ", status)
		log.Println("msg: ", status)

		responseData["status"] = status
		responseData["msg"] = msg

		jsonResponse, err := json.Marshal(responseData)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			response.Write([]byte(`{"message":"Error al generar respuesta JSON"}`))
			return
		}

		// Enviar la respuesta JSON al cliente
		response.Header().Set("Content-Type", "application/json")
		response.Write(jsonResponse)

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
		fmt.Println("Sign-up Email Existente: ", err)
		response.Write([]byte(`{"message": Email Existente"` + `"}`))
		return
	} else {

		user.Password = getHash([]byte(user.Password))

		collection := client.Database("geochat").Collection("user")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		result, _ := collection.InsertOne(ctx, user)
		json.NewEncoder(response).Encode(result)
		cancel()
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

//---------------------------------------------------------------------------------------------------

func getTasksHandler(w http.ResponseWriter, r *http.Request) {
	// Convertir el slice de tareas a JSON
	jsonData, err := json.Marshal(tasks)
	fmt.Println("Get Tareas---> ")
	if err != nil {
		log.Println("Error al convertir a JSON:", err)
		http.Error(w, "Error al convertir a JSON", http.StatusInternalServerError)
		return
	}

	// Establecer la cabecera del tipo de contenido a JSON
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func addTaskHandler(w http.ResponseWriter, r *http.Request) {
	var task Task
	err := json.NewDecoder(r.Body).Decode(&task)
	if err != nil {
		log.Println("Error al decodificar la tarea:", err)
		http.Error(w, "Error al decodificar la tarea", http.StatusBadRequest)
		return
	}

	// Asignar un ID único a la tarea (puedes usar un UUID u otra estrategia)
	task.ID = "ID_" + task.Name

	// Agregar la tarea al slice de tareas
	tasks = append(tasks, task)

	// Responder con la tarea agregada
	jsonData, err := json.Marshal(task)
	if err != nil {
		log.Println("Error al convertir a JSON:", err)
		http.Error(w, "Error al convertir a JSON", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonData)
	fmt.Println("Tarea Nueva asignada...")

}

//-------------------------------------------------------------------------------------------

func backgroundTask() {
	for {
		fmt.Println("Haciendo tarea....")
		time.Sleep(time.Minute) // Cambia esto al intervalo de tiempo deseado
	}
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	fmt.Println("--------------------------------- Aca la verificacion del token de rutas-----------------")
	mySecret := "secret-secret"

	// Analiza el token con la clave secreta
	token, err := jwt.Parse(tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				fmt.Println("método de firma inesperado")
				return nil, fmt.Errorf("método de firma inesperado: %v", token.Header["bearer "])

			}

			return []byte(mySecret), nil
		})

	if err != nil {
		fmt.Println("Error: ", err)
		return nil, err
	}

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println("Token de Ruta ok !!!......")
		return token, nil
	} else {
		fmt.Println("Token de Ruta INVALIDO ...")
		return nil, fmt.Errorf("token inválido")
	}
}

func protectedEndpoint(response http.ResponseWriter, request *http.Request) {

	/* 	var formData User
	   	if err := json.NewDecoder(request.Body).Decode(&formData); err != nil {
	   		http.Error(response, "Bad request", http.StatusBadRequest)
	   		return
	   	}

	   	fmt.Println("token:", formData)
	*/
	// Obtener el token del encabezado de la solicitud

	tokenHeader := request.Header.Get("Authorization")
	//fmt.Println("tokenHeader  ------> : ", tokenHeader)
	if tokenHeader == "" {
		http.Error(response, "Token no proporcionado", http.StatusUnauthorized)
		return
	}

	// Elimina la palabra "Bearer " del tokenString si está presente
	if strings.HasPrefix(tokenHeader, "Bearer ") {
		tokenHeader = strings.TrimPrefix(tokenHeader, "Bearer ")
	}

	// Verificar el token
	token, err := VerifyToken(tokenHeader)
	if err != nil {
		fmt.Println("Token Valido....")
		http.Error(response, "Token inválido", http.StatusUnauthorized)
		return
	} else {
		fmt.Println("Token Valido", token)
	}

	// Devolver una respuesta exitosa al cliente
	responseData := map[string]interface{}{
		"message": "Solicitud exitosa en la ruta protegida",
	}

	// Convertir el mapa a formato JSON
	jsonResponse, err := json.Marshal(responseData)
	if err != nil {
		http.Error(response, "Error al generar respuesta JSON", http.StatusInternalServerError)
		return
	} else {
		fmt.Println("Solicitud exitosa en la ruta protegida")
	}

	// Enviar la respuesta JSON al cliente
	response.Header().Set("Content-Type", "application/json")
	response.Write(jsonResponse)
}

var client *mongo.Client
var tasks []Task

func main() {

	c := cors.New(cors.Options{
		//AllowedOrigins:   []string{"http://localhost:3000"}, // Cambia esto según las URL de origen que deseas permitir
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowCredentials: true,
		AllowedOrigins:   []string{"*"}, // All origins
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	client, _ = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	//client, _ = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://181.191.65.250:27017"))
	cancel()

	router := mux.NewRouter()
	//router.HandleFunc("/api/user/login", userLogin).Methods("GET")
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Bienvenidos a Geochat Backend")
	})
	http.Handle("/", router)

	router.HandleFunc("/api/user/login", userLogin).Methods("POST")
	router.HandleFunc("/api/user/signup", userSignup).Methods("POST")
	router.HandleFunc("/api/user/mail", userEmail).Methods("POST")

	//router.HandleFunc("/api/tasks", getTasksHandler)    // Get Tarea
	//router.HandleFunc("/api/tasks/add", addTaskHandler) // ADD Tarea de fondo....

	//------------------------------------------------------------------------------

	router.HandleFunc("/api/user/native/login", userLoginNative).Methods("POST")
	router.HandleFunc("/api/some/protected/endpoint", protectedEndpoint).Methods("POST")

	pool := websocket.NewPool()
	go pool.Start()

	go backgroundTask()

	router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(pool, w, r)
	})

	port := "8080"
	log.Println("Aplication Comenzo en: " + port)
	log.Fatal(http.ListenAndServe(":8080", c.Handler(router)))

}
