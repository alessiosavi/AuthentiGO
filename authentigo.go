package main

import (
	//Golang import
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	// Internal import
	authutils "authentigo/auth"
	basiccrypt "authentigo/crypt"
	basicredis "authentigo/database/redis"
	utils "gologviewer/utils/core"

	// External import
	"github.com/onrik/logrus/filename"
	log "github.com/sirupsen/logrus" // Pretty log library, not the fastest (zerolog/zap)
	"github.com/valyala/fasthttp"
)

// configuration is the structure for handle the configuration data
type configuration struct {
	Port int    // Port to bind the service
	Host string // Hostname to bind the service
}

// status Structure used for populate the json response for the RESTfull HTTP API
type status struct {
	Status      bool        `json:"Status"`      // Status of response [true,false] OK, KO
	ErrorCode   string      `json:"ErrorCode"`   // Code linked to the error (KO)
	Description string      `json:"Description"` // Description linked to the error (KO)
	Data        interface{} `json:"Data"`        // Generic data to return in the response
}

// middlewareRequest Structure used for manage the request among the user and the external service
type middlewareRequest struct {
	Username string `json:"user"`   // Username of the customer that require the service
	Token    string `json:"token"`  // Token related to the user for consume the service
	Method   string `json:"method"` // Is the external service that you want to call
	Data     string `json:"data"`   // Is the arguments that you want to encode in your request
}

func main() {
	Formatter := new(log.TextFormatter) //#TODO: Formatter have to be inserted in `configuration` in order to dinamically change debug level [at runtime?]
	Formatter.TimestampFormat = "15-01-2018 15:04:05.000000"
	Formatter.FullTimestamp = true
	Formatter.ForceColors = true
	log.AddHook(filename.NewHook()) // Print filename + line at every log
	log.SetFormatter(Formatter)
	log.SetLevel(log.DebugLevel)
	var cfg configuration
	cfg = configuration{Port: 8090, Host: "localhost"}
	handleRequests(cfg)
}

// handleRequests Handler of the HTTP API
func handleRequests(cfg configuration) {
	m := func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("AuthentiGo", "v0.1.0$/alpha")
		log.Info("REQUEST --> ", ctx, " | Headers: ", ctx.Request.Header.String(), " | Body: ", ctx.PostBody())
		switch string(ctx.Path()) {
		case "/send":
			//ctx.Write(sendGet(nil))
		case "/middleware":
			middleware(ctx)
		case "/benchmark":
			fastBenchmarkHTTP(ctx) // Benchmark API
		case "/auth/login":
			ctx.Request.Header.Set("WWW-Authenticate", "Basic realm=\"Restricted\"")
			AuthLoginWrapper(ctx) // Login functionality [Test purpouse]
		case "/auth/register":
			ctx.Request.Header.Set("WWW-Authenticate", "Basic realm=\"Restricted\"")
			AuthRegisterWrapper(ctx) // Register an user into the DB [Test purpouse]
		case "/auth/verify":
			VerifyCookieFromRedisHTTP(ctx) // Verify if an user is authorized to use the services
		default:
			ctx.Response.SetStatusCode(404)
			ctx.WriteString("The url " + string(ctx.URI().RequestURI()) + string(ctx.QueryArgs().QueryString()) + " does not exist :(\n")
			fastBenchmarkHTTP(ctx)
		}
	}
	// The gzipHandler will serve a compress request only if the client request it with headers (Content-Type: gzip, deflate)
	gzipHandler := fasthttp.CompressHandlerLevel(m, fasthttp.CompressBestCompression) // Compress data before sending (if requested by the client)
	err := fasthttp.ListenAndServe(cfg.Host+":"+strconv.Itoa(cfg.Port), gzipHandler)  // Try to start the server with input "host:port" received in input
	if err != nil {                                                                   // No luck, connection not succesfully. Probably port used ...
		log.Warn("Port ", cfg.Port, " seems used :/")
		for i := 0; i < 10; i++ {
			port := strconv.Itoa(utils.Random(8081, 8090)) // Generate a new port to use
			log.Info("Round ", strconv.Itoa(i), "]No luck! Connecting to anotother random port [@", port, "] ...")
			cfg.Port, _ = strconv.Atoi(port)                               // Updating the configuration with the new port used
			err := fasthttp.ListenAndServe(cfg.Host+":"+port, gzipHandler) // Trying with the random port generate few step above
			if err == nil {                                                // Connection estabileshed!
				log.Info("HandleRequests | Connection estabilished @[", cfg.Host, ":", cfg.Port) // Not reached
				break
			}
		}
	}
	log.Trace("HandleRequests | STOP")
}

//AuthLoginWrapper is the authentication wrapper for login functionality. It allow the customers that have completed the registration phase to login into the services.
// In order to be compliant with as many protocol as possibile, the method try find the two parameter needed (user,pass) sequentially from:
// BasicAuth headers; query args; GET args; POST args. It manage few error cause just for debug purpouse
func AuthLoginWrapper(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	username, password := ParseAuthenticationCoreHTTP(ctx) // Retrieve the username and password encoded in the request
	if authutils.ValidateCredentials(username, password) { // Verify if the input parameter respect the rules ...
		check := authutils.LoginUserCoreHTTP(username, password) // Login phase
		if strings.Compare(check, "OK") == 0 {                   // Login Succeed
			token := basiccrypt.GenerateToken(username, password)             // Generate a simple md5 hashed token
			ctx.Response.Header.SetCookie(CreateCookie("GoLog-Token", token)) // Set the token into the cookie headers
			log.Warn("AuthLoginWrapper | Client logged in succesfully!! | ", username, ":", password, " | Token: ", token)
			log.Info("AuthLoginWrapper | Inserting token into Redis ", token)

			redisClient, err := basicredis.ConnectToDb("", "") // Connect to the default redis instance
			if err != nil {
				log.Error("AuthLoginWrapper | Impossible to connect to Redis for store the token | CLIENT: ", redisClient, " | ERR: ", err)
				json.NewEncoder(ctx).Encode(status{Status: false, Description: "Unable to connect to RedisDB", ErrorCode: check, Data: redisClient})
				return
			} // Store the token for future auth check
			basicredis.InsertIntoClient(redisClient, username, token) // insert the token into the DB
			log.Info("AuthLoginWrapper | Token inserted! All operation finished correctly!")

			json.NewEncoder(ctx).Encode(status{Status: true, Description: "User logged in!", ErrorCode: username + ":" + password, Data: token})
		} else if strings.Compare(check, "NOT_VALID") == 0 { // Input does not match with rules
			log.Error("AuthLoginWrapper | Input does not respect the rules :/! | ", username, ":", password)
			ctx.Response.Header.DelCookie("GoLog-Token")
			json.NewEncoder(ctx).Encode(status{Status: false, Description: "Wrong input!", ErrorCode: username, Data: nil})
		} else if strings.Compare(check, "USR") == 0 { //User does not exist in DB
			log.Error("AuthLoginWrapper | Client does not exists! | ", username, ":", password)
			ctx.Response.Header.DelCookie("GoLog-Token")
			json.NewEncoder(ctx).Encode(status{Status: false, Description: "User does not exists!", ErrorCode: "USER_NOT_REGISTERED", Data: nil})
		} else if strings.Compare(check, "PSW") == 0 { //Password mismatch
			log.Error("AuthLoginWrapper | Password does not match! | ", username, ":", password)
			ctx.Response.Header.DelCookie("GoLog-Token")
			json.NewEncoder(ctx).Encode(status{Status: false, Description: "Password don't match!", ErrorCode: username, Data: nil})
		} else { // General error cause
			json.NewEncoder(ctx).Encode(status{Status: false, Description: "Unable to connect to MongoDB", ErrorCode: check, Data: nil})
		}
	} else { // error parsing credential
		log.Info("AuthLoginWrapper | Error parsing credential!! |", username+":"+password)
		ctx.Response.Header.DelCookie("GoLog-Token")
		json.NewEncoder(ctx).Encode(status{Status: false, Description: "Error parsing credential", ErrorCode: "Missing or manipulated input", Data: nil})
	}
}

//AuthRegisterWrapper is the authentication wrapper for register the client into the service.
//It have to parse the credentials of the customers and register the username and the password into the DB.
func AuthRegisterWrapper(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	username, password := ParseAuthenticationCoreHTTP(ctx) // Retrieve the username and password encoded in the request
	if authutils.ValidateCredentials(username, password) {
		check := authutils.RegisterUserCoreHTTP(username, password) // Registration phase, connect to MongoDB
		if strings.Compare(check, "OK") == 0 {                      // Registration Succeed
			log.Warn("AuthRegisterWrapper | Registering new client! | ", username, ":", password)
			json.NewEncoder(ctx).Encode(status{Status: true, Description: "User inserted!", ErrorCode: username + ":" + password, Data: nil})
		} else if strings.Compare(check, "NOT_VALID") == 0 { // Input don't match with rules
			log.Error("AuthRegisterWrapper | Input does not respect the rules :/! | ", username, ":", password)
			ctx.Response.Header.DelCookie("GoLog-Token")
			json.NewEncoder(ctx).Encode(status{Status: false, Description: "Wrong input!", ErrorCode: username, Data: nil})
		} else if strings.Compare(check, "ALREDY_EXIST") == 0 { //User alredy present in DB
			log.Error("AuthRegisterWrapper | User alredy exists! | ", username, ":", password)
			json.NewEncoder(ctx).Encode(status{Status: false, Description: "User alredy exists!", ErrorCode: username, Data: nil})
		} else { // General error cause
			json.NewEncoder(ctx).Encode(status{Status: false, Description: "Unable to connect to DB", ErrorCode: check, Data: nil})
		}

	} else { // error parsing credential
		log.Info("AuthRegisterWrapper | Error parsing credential!! | ", username, ":", password)
		json.NewEncoder(ctx).Encode(status{Status: false, Description: "Error parsing credential", ErrorCode: "Wrong input or fatal error", Data: nil})
	}
}

// ParseAuthenticationCoreHTTP The purpouse of this method is to decode the username and the password encoded in the request.
// It have to recognize if the parameters are sent in the body of the request OR in the payload of the BasicAuth Header.
// In first instance he try if the prefix of the BasicAuth is present in the headers. If found will delegate to extract the data to
// another function specialized to extract the data from the BasicAuth header.
// If the BasicAuth header is not provided, then the method will delegate the request to a function specialized for parse the data
// from the body of the request
func ParseAuthenticationCoreHTTP(ctx *fasthttp.RequestCtx) (string, string) {
	log.Trace("ParseAuthenticationHTTP | START")
	basicAuthPrefix := []byte("Basic ")              // BasicAuth template prefix
	auth := ctx.Request.Header.Peek("Authorization") // Get the Basic Authentication credentials from headers
	log.Info("ParseAuthenticationHTTP | Auth Headers: [", string(auth), "]")
	if bytes.HasPrefix(auth, basicAuthPrefix) { // Check if the login is executed using the BasicAuth headers
		return authutils.ParseAuthCredentialFromHeaders(auth) // Call the delegated method for extract the credentials from the Header
	} // In other case call the delegated method for extract the credentials from the body of the Request
	log.Info("ParseAuthenticationCoreHTTP | Credentials not in Headers, analyzing the body of the request ...")
	user, pass := ParseAuthCredentialsFromRequestBody(ctx) // Used for extract user and password from the request
	return user, pass
}

// VerifyCookieFromRedisHTTP wrapper for verify if the user is logged
func VerifyCookieFromRedisHTTP(ctx *fasthttp.RequestCtx) {
	user, _ := ParseAuthenticationCoreHTTP(ctx)
	token := ParseTokenFromRequest(ctx)
	auth := authutils.VerifyCookieFromRedisCoreHTTP(user, token) // Call the core function for recognize if the user have the token
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	if strings.Compare(auth, "AUTHORIZED") == 0 {
		json.NewEncoder(ctx).Encode(status{Status: true, Description: "Logged in!", ErrorCode: auth, Data: nil})
	} else {
		json.NewEncoder(ctx).Encode(status{Status: false, Description: "Not logged in!", ErrorCode: auth, Data: nil})
	}
}

//CreateCookie Method that return a cookie valorized as input (GoLog-Token as key)
func CreateCookie(key string, value string) *fasthttp.Cookie {
	authCookie := fasthttp.Cookie{}
	if strings.Compare(key, "") == 0 {
		authCookie.SetKey("GoLog-Token")
	} else {
		authCookie.SetKey(key)
	}
	authCookie.SetValue(value)
	authCookie.SetMaxAge(30) // Set 30 seconds expiration
	return &authCookie
}

// RedirectCookie return the cookie by the parameter in input and reassing to the response
func RedirectCookie(ctx *fasthttp.RequestCtx) string {
	var cookie string
	cookie = string(ctx.Request.Header.Cookie("GoLog-Token"))
	if strings.Compare(cookie, "") == 0 {
		cookie = "USER_NOT_LOGGED_IN"
	}
	ctx.Response.Header.SetCookie(CreateCookie("GoLog-Token", cookie))
	return cookie
}

// ParseAuthCredentialsFromRequestBody is delegated to extract the username and the password from the request body
func ParseAuthCredentialsFromRequestBody(ctx *fasthttp.RequestCtx) (string, string) {
	log.Debug("ParseAuthCredentialsFromRequestBody | START")
	user := string(ctx.FormValue("user")) // Extracting data from request
	pass := string(ctx.FormValue("pass"))
	return user, pass
}

// ParseTokenFromRequest is delegated to retrieved the token encoded in the request. The token can be sent in two different way.
// In first instance the method will try to find the token in the cookie. If the cookie is not provided in the cookie,
// then the research will continue analayzing the body of the request (URL ARGS,GET,POST).
// In case of token not found, an empty string will be returned
func ParseTokenFromRequest(ctx *fasthttp.RequestCtx) string {
	token := string(ctx.Request.Header.Cookie("GoLog-Token")) // GoLog-Token is the hardcoded name of the cookie
	log.Info("ParseTokenFromRequest | Checking if token is in the cookie ...")
	if strings.Compare(token, "") == 0 { // No cookie provided :/ Checking in the request
		log.Warn("ParseTokenFromRequest | Token is not in the cookie, retrieving from the request ...")
		token = string(ctx.FormValue("token")) // Extracting the token from the request (ARGS,GET,POST)
		if strings.Compare(token, "") == 0 {   // No token provided in the request
			log.Warn("ParseTokenFromRequest | Can not find the token! ...")
			return "" // "COOKIE_NOT_PRESENT"
		}
		log.Info("ParseTokenFromRequest | Token found in request! ... | ", token)
	} else {
		log.Info("ParseTokenFromRequest | Token found in cookie! ... | ", token)
	}
	return token
}

// fastBenchmarkHTTP return the number of line printed
func fastBenchmarkHTTP(ctx *fasthttp.RequestCtx) {
	ctx.Write([]byte("Retry !"))
}

//middleware is the function delegated to take in charge the request of the customer, be sure that is logged in, then call
// the external service that the user want to contat. If the customers is authorized (token proved in request match with the one retrieved)
// from Redis), the query will be executed and the result will be showed back as a response.
func middleware(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	log.Info("CTX: ", string(ctx.PostBody())) // Logging the arguments of the request
	var req middlewareRequest
	json.Unmarshal(ctx.PostBody(), &req) // Populate the structure from the json
	log.Info("Req: ", req)
	log.Debug("Validating request ...")
	if validateMiddlewareRequest(req) { // Verify it the json is valid
		log.Info("Request valid! Verifying token from Redis ...")
		auth := authutils.VerifyCookieFromRedisCoreHTTP(req.Username, req.Token) // Call the core function for recognize if the user have the token
		if strings.Compare(auth, "AUTHORIZED") == 0 {                            // Token in redis, call the external service..
			log.Info("REQUEST OK> ", req)
			log.Warn("Using service ", req.Method, " | ARGS: ", req.Data, " | Token: ", req.Token, " | USR: ", req.Username)
			ctx.Write(sendGet(req))
			return
		}
		json.NewEncoder(ctx).Encode(status{Status: false, Description: "NOT AUTHORIZED!!", ErrorCode: "YOU_SHALL_NOT_PASS", Data: nil})
		return
	}
	json.NewEncoder(ctx).Encode(status{Status: false, Description: "Not Valid Json!", ErrorCode: "", Data: req})
}

// validateMiddlewareRequest is developed in order to verify it the request from the customer is valid. Can be view as a "filter"
func validateMiddlewareRequest(request middlewareRequest) bool {
	if authutils.UsernameValidation(request.Username) { // Validate the username
		if authutils.TokenValidation(request.Token) { // Validate the token
			if strings.Compare(request.Method, "") != 0 { // Verify if the request is not empty
				return true
			}
		}
	}
	return false
}

// sendGet is developed in order to forward the input request to the service and return the response
func sendGet(request middlewareRequest) []byte {
	//url := "https://ground0.hackx.com/log-analyzer-prod/auth/" + method + "?" + data
	url := "https://ground0.hackx.com/log-analyzer-prod/" + request.Method + "?" + request.Data
	log.Info("URL:>", url)
	//	data = []byte(`{"title":"Buy cheese and bread for breakfast."}`)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte("")))
	req.Header.Set("X-Custom-Header", "login_test")
	req.Header.Set("Content-Type", "text/plain")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	log.Info("response Status:", resp.Status)
	log.Info("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	log.Info("response Body:", string(body))

	return body
}
