package main

import (
	"flag"
	"github.com/globalsign/mgo"
	"github.com/go-redis/redis"
	"github.ibm.com/Alessio-Savi/AuthentiGo/database/mongo"
	"github.ibm.com/Alessio-Savi/AuthentiGo/datastructures"
	"github.ibm.com/Alessio-Savi/AuthentiGo/utils"
	"os"

	//Golang import
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	// Internal import
	utils "github.com/alessiosavi/GoUtils"
	authutils "github.ibm.com/Alessio-Savi/AuthentiGo/auth"
	basiccrypt "github.ibm.com/Alessio-Savi/AuthentiGo/crypt"
	basicredis "github.ibm.com/Alessio-Savi/AuthentiGo/database/redis"

	// External import
	"github.com/onrik/logrus/filename"
	log "github.com/sirupsen/logrus" // Pretty log library, not the fastest (zerolog/zap)
	"github.com/valyala/fasthttp"
)

func main() {

	// ==== SET LOGGING
	Formatter := new(log.TextFormatter) //#TODO: Formatter have to be inserted in `configuration` in order to dinamically change debug level [at runtime?]
	Formatter.TimestampFormat = "15-01-2018 15:04:05.000000"
	Formatter.FullTimestamp = true
	Formatter.ForceColors = true
	log.AddHook(filename.NewHook()) // Print filename + line at every log
	log.SetFormatter(Formatter)

	// ==== LOAD JSON CONF FILE
	cfg := verifyCommandLineInput()
	log.SetLevel(utils.SetDebugLevel(cfg.Log.Level))

	// ==== CONNECT TO MONGO ====
	mongoClient := basicmongo.InitMongoDBConnection(cfg.Mongo.Host, cfg.Mongo.Port, "", true)
	defer mongoClient.Close()

	// ==== CONNECT TO REDIS ====
	redisClient := basicredis.ConnectToDb(cfg.Redis.Host, cfg.Redis.Port)
	defer redisClient.Close()

	log.Info("main | Spawing API services")
	handleRequests(cfg, mongoClient, redisClient)
}

// handleRequests Is delegated to map (BIND) the API methods to the HTTP URL
// It use a gzip handler that is usefull for reduce bandwitch usage while interacting with the middleware function
func handleRequests(cfg datastructures.Configuration, mgoClient *mgo.Session, redisClient *redis.Client) {
	m := func(ctx *fasthttp.RequestCtx) {
		if cfg.SSL.Enabled {
			httputils.SecureRequest(ctx, true)
		} else {
			httputils.SecureRequest(ctx, false)
		}

		ctx.Response.Header.Set("AuthentiGo", "$v0.1.2")
		log.Info("REQUEST --> ", ctx, " | Headers: ", ctx.Request.Header.String(), " | Body: ", ctx.PostBody())
		switch string(ctx.Path()) {
		case "/middleware":
			middleware(ctx, redisClient)
		case "/benchmark":
			fastBenchmarkHTTP(ctx) // Benchmark API
		case "/auth/login":
			ctx.Request.Header.Set("WWW-Authenticate", "Basic realm=\"Restricted\"")
			AuthLoginWrapper(ctx, mgoClient, redisClient) // Login functionality [Test purpouse]
		case "/auth/register":
			ctx.Request.Header.Set("WWW-Authenticate", "Basic realm=\"Restricted\"")
			AuthRegisterWrapper(ctx, mgoClient) // Register an user into the DB [Test purpouse]
		case "/auth/verify":
			VerifyCookieFromRedisHTTP(ctx, redisClient) // Verify if an user is authorized to use the service
		case "/test/crypt":
			CryptDataHTTPWrapper(ctx)
		case "/test/decrypt":
			DecryptDataHTTPWrapper(ctx)
		default:
			ctx.Response.SetStatusCode(404)
			ctx.WriteString("The url " + string(ctx.URI().RequestURI()) + string(ctx.QueryArgs().QueryString()) + " does not exist :(\n")
			fastBenchmarkHTTP(ctx)
		}
	}
	// ==== GZIP HANDLER ====
	// The gzipHandler will serve a compress request only if the client request it with headers (Content-Type: gzip, deflate)
	gzipHandler := fasthttp.CompressHandlerLevel(m, fasthttp.CompressBestSpeed) // Compress data before sending (if requested by the client)
	log.Info("HandleRequests | Binding services to @[", cfg.Host, ":", cfg.Port)

	// ==== SSL HANDLER + GZIP if requested ====
	if cfg.SSL.Enabled {
		httputils.ListAndServerSSL(cfg.Host, cfg.SSL.Path, cfg.SSL.Cert, cfg.SSL.Key, cfg.Port, gzipHandler)
	}
	// ==== Simple GZIP HANDLER ====
	httputils.ListAndServerGZIP(cfg.Host, cfg.Port, gzipHandler)

	log.Trace("HandleRequests | STOP")
}

//AuthLoginWrapper is the authentication wrapper for login functionality. It allow the customers that have completed the registration phase to login and receive the mandatory
// token for interact with the services
// In order to be compliant with as many protocol as possibile, the method try find the two parameter needed (user,pass) sequentially from:
// BasicAuth headers; query args; GET args; POST args. It manage few error cause just for debug purpouse
// The login functionality can be accomplished using different methods:
// BasichAuth headers: example ->from browser username:password@$URL/auth/login| curl -vL --user "username:password $URL/auth/login"
// GET Request: example -> from browser $URL/auth/login?user=username&pass=password | curl -vL $URL/auth/login?user=username&pass=password
// POST Request: example -> curl -vL $URL/auth/login -d 'user=username&pass=password'
func AuthLoginWrapper(ctx *fasthttp.RequestCtx, mgoClient *mgo.Session, redisClient *redis.Client) {
	log.Info("AuthLoginWrapper | Starting authentication | Parsing authentication credentials")
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	username, password := ParseAuthenticationCoreHTTP(ctx) // Retrieve the username and password encoded in the request from BasicAuth headers, GET & POST
	if authutils.ValidateCredentials(username, password) { // Verify if the input parameter respect the rules ...
		log.Debug("AuthLoginWrapper | Input validated | User: ", username, " | Pass: ", password, " | Calling core functionalities ...")
		check := authutils.LoginUserCoreHTTP(username, password, mgoClient) // Login phase
		if strings.Compare(check, "OK") == 0 {                              // Login Succeed
			log.Debug("AuthLoginWrapper | Login succesfully! Generating token!")
			token := basiccrypt.GenerateToken(username, password) // Generate a simple md5 hashed token
			log.Info("AuthLoginWrapper | Inserting token into Redis ", token)
			basicredis.InsertIntoClient(redisClient, username, token) // insert the token into the DB
			log.Info("AuthLoginWrapper | Token inserted! All operation finished correctly! | Setting token into response")
			authcookie := CreateCookie("GoLog-Token", token)
			ctx.Response.Header.SetCookie(authcookie)     // Set the token into the cookie headers
			ctx.Response.Header.Set("GoLog-Token", token) // Set the token into a custom headers for future security improvments
			log.Warn("AuthLoginWrapper | Client logged in succesfully!! | ", username, ":", password, " | Token: ", token)
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: true, Description: "User logged in!", ErrorCode: username + ":" + password, Data: token})
		} else if strings.Compare(check, "NOT_VALID") == 0 { // Input does not match with rules
			log.Error("AuthLoginWrapper | Input does not respect the rules :/! | ", username, ":", password)
			ctx.Response.Header.DelCookie("GoLog-Token")
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Wrong input!", ErrorCode: username, Data: nil})
		} else if strings.Compare(check, "USR") == 0 { //User does not exist in DB
			log.Error("AuthLoginWrapper | Client does not exists! | ", username, ":", password)
			ctx.Response.Header.DelCookie("GoLog-Token")
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "User does not exists!", ErrorCode: "USER_NOT_REGISTERED", Data: nil})
		} else if strings.Compare(check, "PSW") == 0 { //Password mismatch
			log.Error("AuthLoginWrapper | Password does not match! | ", username, ":", password)
			ctx.Response.Header.DelCookie("GoLog-Token")
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Password don't match!", ErrorCode: username, Data: nil})
		} else { // General error cause
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Unable to connect to MongoDB", ErrorCode: check, Data: nil})
		}
	} else { // error parsing credential
		log.Info("AuthLoginWrapper | Error parsing credential!! |", username+":"+password)
		ctx.Response.Header.DelCookie("GoLog-Token")
		json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Error parsing credential", ErrorCode: "Missing or manipulated input", Data: nil})
	}
}

//AuthRegisterWrapper is the authentication wrapper for register the client into the service.
//It have to parse the credentials of the customers and register the username and the password into the DB.
func AuthRegisterWrapper(ctx *fasthttp.RequestCtx, mgoClient *mgo.Session) {
	log.Debug("AuthRegisterWrapper | Starting register functionalities! | Parsing username and password ...")
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	username, password := ParseAuthenticationCoreHTTP(ctx) // Retrieve the username and password encoded in the request
	if authutils.ValidateCredentials(username, password) {
		log.Debug("AuthRegisterWrapper | Input validated | User: ", username, " | Pass: ", password, " | Calling core functionalities ...")
		check := authutils.RegisterUserCoreHTTP(username, password, mgoClient) // Registration phase, connect to MongoDB
		if strings.Compare(check, "OK") == 0 {                                 // Registration Succeed
			log.Warn("AuthRegisterWrapper | Registering new client! | ", username, ":", password)
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: true, Description: "User inserted!", ErrorCode: username + ":" + password, Data: nil})
		} else if strings.Compare(check, "NOT_VALID") == 0 { // Input don't match with rules
			log.Error("AuthRegisterWrapper | Input does not respect the rules :/! | ", username, ":", password)
			ctx.Response.Header.DelCookie("GoLog-Token")
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Wrong input!", ErrorCode: username, Data: nil})
		} else if strings.Compare(check, "ALREDY_EXIST") == 0 { //User alredy present in DB
			log.Error("AuthRegisterWrapper | User alredy exists! | ", username, ":", password)
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "User alredy exists!", ErrorCode: username, Data: nil})
		} else { // General error cause
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Unable to connect to DB", ErrorCode: check, Data: nil})
		}

	} else { // error parsing credential
		log.Info("AuthRegisterWrapper | Error parsing credential!! | ", username, ":", password)
		json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Error parsing credential", ErrorCode: "Wrong input or fatal error", Data: nil})
	}
}

// ParseAuthenticationCoreHTTP The purpouse of this method is to decode the username and the password encoded in the request.
// It have to recognize if the parameters are sent in the body of the request OR in the payload of the BasicAuth Header.
// In first instance he try if the prefix of the BasicAuth is present in the headers. If found will delegate to extract the data to
// another function specialized to extract the data from the BasicAuth header.
// If the BasicAuth header is not provided, then the method will delegate the request to a function specialized for parse the data
// from the body of the request
func ParseAuthenticationCoreHTTP(ctx *fasthttp.RequestCtx) (string, string) {
	log.Debug("ParseAuthenticationHTTP | START")
	basicAuthPrefix := []byte("Basic ")              // BasicAuth template prefix
	auth := ctx.Request.Header.Peek("Authorization") // Get the Basic Authentication credentials from headers
	log.Info("ParseAuthenticationHTTP | Auth Headers: [", string(auth), "]")
	if bytes.HasPrefix(auth, basicAuthPrefix) { // Check if the login is executed using the BasicAuth headers
		log.Debug("ParseAuthenticationHTTP | Loggin-in from BasicAuth headers ...")
		return authutils.ParseAuthCredentialFromHeaders(auth) // Call the delegated method for extract the credentials from the Header
	} // In other case call the delegated method for extract the credentials from the body of the Request
	log.Info("ParseAuthenticationCoreHTTP | Credentials not in Headers, analyzing the body of the request ...")
	user, pass := ParseAuthCredentialsFromRequestBody(ctx) // Used for extract user and password from the request
	return user, pass
}

// VerifyCookieFromRedisHTTP wrapper for verify if the user is logged
func VerifyCookieFromRedisHTTP(ctx *fasthttp.RequestCtx, redisClient *redis.Client) {
	go ctx.Response.Header.SetContentType("application/json; charset=utf-8") // Why not ? (:
	log.Debug("VerifyCookieFromRedisHTTP | Retrieving username ...")
	user, _ := ParseAuthenticationCoreHTTP(ctx)
	log.Debug("VerifyCookieFromRedisHTTP | Retrieving token ...")
	token := ParseTokenFromRequest(ctx)
	log.Debug("VerifyCookieFromRedisHTTP | Retrieving cookie from redis ...")
	auth := authutils.VerifyCookieFromRedisCoreHTTP(user, token, redisClient) // Call the core function for recognize if the user have the token
	if strings.Compare(auth, "AUTHORIZED") == 0 {
		json.NewEncoder(ctx).Encode(datastructures.Response{Status: true, Description: "Logged in!", ErrorCode: auth, Data: nil})
	} else {
		json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Not logged in!", ErrorCode: auth, Data: nil})
	}
}

//CreateCookie Method that return a cookie valorized as input (GoLog-Token as key)
func CreateCookie(key string, value string) *fasthttp.Cookie {
	if strings.Compare(key, "") == 0 {
		key = "GoLog-Token"
	}
	log.Debug("CreateCookie | Creating Cookie | Key: ", key, " | Val: ", value)
	authCookie := fasthttp.Cookie{}
	authCookie.SetKey(key)
	authCookie.SetValue(value)
	authCookie.SetMaxAge(30) // Set 30 seconds expiration
	authCookie.SetHTTPOnly(true)
	authCookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
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
func middleware(ctx *fasthttp.RequestCtx, redisClient *redis.Client) {
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	log.Info("CTX: ", string(ctx.PostBody())) // Logging the arguments of the request
	var req datastructures.MiddlewareRequest
	json.Unmarshal(ctx.PostBody(), &req) // Populate the structure from the json
	log.Info("Req: ", req)
	log.Debug("Validating request ...")
	if validateMiddlewareRequest(req) { // Verify it the json is valid
		log.Info("Request valid! Verifying token from Redis ...")
		auth := authutils.VerifyCookieFromRedisCoreHTTP(req.Username, req.Token, redisClient) // Call the core function for recognize if the user have the token
		if strings.Compare(auth, "AUTHORIZED") == 0 {                                         // Token in redis, call the external service..
			log.Info("REQUEST OK> ", req)
			log.Warn("Using service ", req.Method, " | ARGS: ", req.Data, " | Token: ", req.Token, " | USR: ", req.Username)
			ctx.Write(sendGet(req))
			return
		}
		json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "NOT AUTHORIZED!!", ErrorCode: "YOU_SHALL_NOT_PASS", Data: nil})
		return
	}
	json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Not Valid Json!", ErrorCode: "", Data: req})
}

// validateMiddlewareRequest is developed in order to verify it the request from the customer is valid. Can be view as a "filter"
func validateMiddlewareRequest(request datastructures.MiddlewareRequest) bool {
	if authutils.ValidateUsername(request.Username) { // Validate the username
		if authutils.ValidateToken(request.Token) { // Validate the token
			if strings.Compare(request.Method, "") != 0 { // Verify if the request is not empty
				return true
			}
		}
	}
	return false
}

func CryptDataHTTPWrapper(ctx *fasthttp.RequestCtx) {
	log.Debug("CryptDataHTTPWrapper | Retrieving username and password ...")
	user, psw := ParseAuthenticationCoreHTTP(ctx)
	log.Debug("CryptDataHTTPWrapper | Retrieving token ...")
	token := ParseTokenFromRequest(ctx)

	log.Debug("CryptDataHTTPWrapper | Validating credentials ... ")
	if authutils.ValidateCredentials(user, psw) {
		log.Debug("CryptDataHTTPWrapper | Validating token ... ")
		if authutils.ValidateToken(token) {
			chiper_text := basiccrypt.Encrypt([]byte(user+":"+psw), psw)
			log.Debug("Chiper: " + chiper_text)
		}
	}

	// if strings.Compare(auth, "AUTHORIZED") == 0 {
	// 	json.NewEncoder(ctx).Encode(status{Status: true, Description: "Logged in!", ErrorCode: auth, Data: nil})
	// } else {
	// 	json.NewEncoder(ctx).Encode(status{Status: false, Description: "Not logged in!", ErrorCode: auth, Data: nil})
	// }

}

func DecryptDataHTTPWrapper(ctx *fasthttp.RequestCtx) {
	log.Debug("DecryptDataHTTPWrapper | Retrieving username and password ...")
	user, psw := ParseAuthenticationCoreHTTP(ctx)
	log.Debug("DecryptDataHTTPWrapper | Retrieving token ...")
	token := ParseTokenFromRequest(ctx)

	log.Debug("DecryptDataHTTPWrapper | Validating credentials ... ")
	if authutils.ValidateCredentials(user, psw) {
		log.Debug("DecryptDataHTTPWrapper | Validating token ... ")
		if authutils.ValidateToken(token) {
			plain := basiccrypt.Decrypt(token, psw)
			log.Debug("Plain: " + plain)
		}
	}
}

// sendGet is developed in order to forward the input request to the service and return the response
func sendGet(request datastructures.MiddlewareRequest) []byte {
	//url := "https://ground0.hackx.com/log-analyzer-prod/auth/" + method + "?" + data
	url := "https://ground0.hackx.com/log-analyzer-prod/" + request.Method + "?" + request.Data
	log.Info("URL:>", url)
	//	data = []byte(`{"title":"Buy cheese and bread for breakfast."}`)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte("")))
	if err != nil {
		log.Error("sendGet | Ouch! Seems that we POST an error | ERR: ", err)
	}
	req.Header.Set("X-Custom-Header", "login_test")
	req.Header.Set("Content-Type", "text/plain")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		// Raise os.Exit
		panic(err)
	}
	defer resp.Body.Close()

	log.Info("response Status:", resp.Status)
	log.Info("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	log.Info("response Body:", string(body))

	return body
}

// VerifyCommandLineInput is delegated to manage the inputer parameter provide with the input flag from command line
func verifyCommandLineInput() datastructures.Configuration {
	log.Debug("verifyCommandLineInput | Init a new configuration from the conf file")
	c := flag.String("config", "./conf/test.json", "Specify the configuration file.")
	flag.Parse()
	if strings.Compare(*c, "") == 0 {
		log.Fatal("verifyCommandLineInput | Call the tool using --config conf/config.json")
	}
	file, err := os.Open(*c)
	if err != nil {
		log.Fatal("can't open config file: ", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	cfg := datastructures.Configuration{}
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatal("can't decode config JSON: ", err)
	}
	log.Debug("Conf loaded -> ", cfg)

	return cfg
}
