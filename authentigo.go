package main

import (
	//Golang import
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	// == Internal import ==
	// General purpose library

	// Provide methods for manage authentication phase
	authutils "alessiosavi/AuthentiGo/auth"
	// Provide method for crypt and decrypt data
	basiccrypt "alessiosavi/AuthentiGo/crypt"
	// Wrap redis methods
	basicredis "alessiosavi/AuthentiGo/database/redis"
	// Wrap mgo methods
	basicmongo "alessiosavi/AuthentiGo/database/mongo"
	// Common utils
	commonutils "alessiosavi/AuthentiGo/utils/common"
	// Provide exportable datastructure
	datastructures "alessiosavi/AuthentiGo/datastructures"
	// HTTP utils
	httputils "alessiosavi/AuthentiGo/utils/http"

	// == External dependencies ==

	// Manage mongo connection
	mgo "github.com/globalsign/mgo"
	// Manage redis connection
	redis "github.com/go-redis/redis"
	// Print filename on log
	filename "github.com/onrik/logrus/filename"
	// Very nice log library
	log "github.com/sirupsen/logrus"
	// Screaming fast HTTP server
	fasthttp "github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/expvarhandler"
)

func main() {

	// ==== SET LOGGING
	Formatter := new(log.TextFormatter) //#TODO: Formatter have to be inserted in `configuration` in order to dinamically change debug level [at runtime?]
	Formatter.TimestampFormat = "Jan _2 15:04:05.000000000"
	Formatter.FullTimestamp = true
	Formatter.ForceColors = true
	log.AddHook(filename.NewHook()) // Print filename + line at every log
	log.SetFormatter(Formatter)

	// ==== LOAD JSON CONF FILE
	cfg := commonutils.VerifyCommandLineInput()
	log.SetLevel(commonutils.SetDebugLevel(cfg.Log.Level))

	// ==== CONNECT TO MONGO ====
	mongoClient := basicmongo.InitMongoDBConnection(cfg.Mongo.Host, cfg.Mongo.Port, "", true)
	if mongoClient == nil {
		log.Fatal("Unable to connect to mongo!")
	}
	defer mongoClient.Close()

	// ==== CONNECT TO REDIS ====
	redisClient := basicredis.ConnectToDb(cfg.Redis.Host, cfg.Redis.Port, cfg.Redis.Token.DB)
	if redisClient == nil {
		log.Fatal("Unable to connect to redis!")
	}
	defer redisClient.Close()

	log.Info("main | Spawing API services")
	handleRequests(cfg, mongoClient, redisClient)
}

// handleRequests Is delegated to map (BIND) the API methods to the HTTP URL
// It use a gzip handler that is usefull for reduce bandwitch usage while interacting with the middleware function
func handleRequests(cfg datastructures.Configuration, mgoClient *mgo.Session, redisClient *redis.Client) {
	m := func(ctx *fasthttp.RequestCtx) {
		if cfg.SSL.Enabled {
			log.Debug("handleRequests | SSL is enabled!")
		}
		httputils.SecureRequest(ctx, cfg.SSL.Enabled)
		ctx.Response.Header.Set("AuthentiGo", "$v0.2.1")

		// Avoid to print stats for the expvar handler
		if strings.Compare(string(ctx.Path()), "/stats") != 0 {
			log.Info("\n|REQUEST --> ", ctx, " \n|Headers: ", ctx.Request.Header.String(), "| Body: ", string(ctx.PostBody()))
		}

		switch string(ctx.Path()) {
		case "/middleware":
			middleware(ctx, redisClient)
		case "/benchmark":
			fastBenchmarkHTTP(ctx) // Benchmark API
		case "/auth/login":
			AuthLoginWrapper(ctx, mgoClient, redisClient, cfg) // Login functionality [Test purpouse]
		case "/auth/register":
			AuthRegisterWrapper(ctx, mgoClient, cfg) // Register an user into the DB [Test purpouse]
		case "/auth/delete":
			DeleteCustomerHTTP(ctx, cfg.Mongo.Users.DB, cfg.Mongo.Users.Collection, redisClient, mgoClient)
		case "/auth/verify":
			VerifyCookieFromRedisHTTP(ctx, redisClient) // Verify if an user is authorized to use the service
		case "/test/crypt":
			CryptDataHTTPWrapper(ctx)
		case "/test/decrypt":
			DecryptDataHTTPWrapper(ctx)
		case "/stats":
			expvarhandler.ExpvarHandler(ctx)
		default:
			_, err := ctx.WriteString("The url " + string(ctx.URI().RequestURI()) + string(ctx.QueryArgs().QueryString()) + " does not exist :(\n")
			commonutils.Check(err, "handleRequests")
			ctx.Response.SetStatusCode(404)
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
func AuthLoginWrapper(ctx *fasthttp.RequestCtx, mgoClient *mgo.Session, redisClient *redis.Client, cfg datastructures.Configuration) {
	log.Info("AuthLoginWrapper | Starting authentication | Parsing authentication credentials")
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	username, password := ParseAuthenticationCoreHTTP(ctx) // Retrieve the username and password encoded in the request from BasicAuth headers, GET & POST
	if authutils.ValidateCredentials(username, password) { // Verify if the input parameter respect the rules ...
		log.Debug("AuthLoginWrapper | Input validated | User: ", username, " | Pass: ", password, " | Calling core functionalities ...")
		check := authutils.LoginUserHTTPCore(username, password, mgoClient, cfg.Mongo.Users.DB, cfg.Mongo.Users.Collection) // Login phase
		if strings.Compare(check, "OK") == 0 {                                                                              // Login Succeed
			log.Debug("AuthLoginWrapper | Login succesfully! Generating token!")
			token := basiccrypt.GenerateToken(username, password) // Generate a simple md5 hashed token
			log.Info("AuthLoginWrapper | Inserting token into Redis ", token)
			basicredis.InsertIntoClient(redisClient, username, token, cfg.Redis.Token.Expire) // insert the token into the DB
			log.Info("AuthLoginWrapper | Token inserted! All operation finished correctly! | Setting token into response")
			authcookie := authutils.CreateCookie("GoLog-Token", token, cfg.Redis.Token.Expire)
			ctx.Response.Header.SetCookie(authcookie)     // Set the token into the cookie headers
			ctx.Response.Header.Set("GoLog-Token", token) // Set the token into a custom headers for future security improvments
			log.Warn("AuthLoginWrapper | Client logged in succesfully!! | ", username, ":", password, " | Token: ", token)
			err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: true, Description: "User logged in!", ErrorCode: username + ":" + password, Data: token})
			commonutils.Check(err, "AuthLoginWrapper")
		} else {
			commonutils.AuthLoginWrapperErrorHelper(ctx, check, username, password)
		}
	} else { // error parsing credential
		log.Info("AuthLoginWrapper | Error parsing credential!! |", username+":"+password)
		ctx.Response.Header.DelCookie("GoLog-Token")
		ctx.Error(fasthttp.StatusMessage(fasthttp.StatusUnauthorized), fasthttp.StatusUnauthorized)
		ctx.Response.Header.Set("WWW-Authenticate", "Basic realm=Restricted")
		//err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Error parsing credential", ErrorCode: "Missing or manipulated input", Data: nil})
		//commonutils.Check(err, "AuthLoginWrapper")
	}
}

//AuthRegisterWrapper is the authentication wrapper for register the client into the service.
//It have to parse the credentials of the customers and register the username and the password into the DB.
func AuthRegisterWrapper(ctx *fasthttp.RequestCtx, mgoClient *mgo.Session, cfg datastructures.Configuration) {
	log.Debug("AuthRegisterWrapper | Starting register functionalities! | Parsing username and password ...")
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	ctx.Request.Header.Set("WWW-Authenticate", `Basic realm="Restricted"`)
	username, password := ParseAuthenticationCoreHTTP(ctx) // Retrieve the username and password encoded in the request
	if authutils.ValidateCredentials(username, password) {
		log.Debug("AuthRegisterWrapper | Input validated | User: ", username, " | Pass: ", password, " | Calling core functionalities ...")
		check := authutils.RegisterUserHTTPCore(username, password, mgoClient, cfg.Mongo.Users.DB, cfg.Mongo.Users.Collection) // Registration phase, connect to MongoDB
		if strings.Compare(check, "OK") == 0 {                                                                                 // Registration Succeed
			log.Warn("AuthRegisterWrapper | Customer insert with success! | ", username, ":", password)
			err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: true, Description: "User inserted!", ErrorCode: username + ":" + password, Data: nil})
			commonutils.Check(err, "AuthRegisterWrapper")
		} else {
			commonutils.AuthRegisterErrorHelper(ctx, check, username, password)
		}
	} else { // error parsing credential
		log.Info("AuthRegisterWrapper | Error parsing credential!! | ", username, ":", password)
		err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Error parsing credential", ErrorCode: "Wrong input or fatal error", Data: nil})
		commonutils.Check(err, "AuthRegisterWrapper")
	}
}

// ParseAuthenticationCoreHTTP The purpouse of this method is to decode the username and the password encoded in the request.
// It have to recognize if the parameters are sent in the body of the request OR in the payload of the BasicAuth Header.
// In first instance he try if the prefix of the BasicAuth is present in the headers. If found will delegate to extract the data to
// another function specialized to extract the data from the BasicAuth header.
// If the BasicAuth header is not provided, then the method will delegate the request to a function specialized for parse the data
// from the body of the request
func ParseAuthenticationCoreHTTP(ctx *fasthttp.RequestCtx) (string, string) {
	basicAuthPrefix := []byte("Basic ")              // BasicAuth template prefix
	auth := ctx.Request.Header.Peek("Authorization") // Get the Basic Authentication credentials from headers
	log.Info("ParseAuthenticationHTTP | Auth Headers: [", string(auth), "]")
	if bytes.HasPrefix(auth, basicAuthPrefix) { // Check if the login is executed using the BasicAuth headers
		log.Debug("ParseAuthenticationHTTP | Loggin-in from BasicAuth headers ...")
		return authutils.ParseAuthCredentialFromHeaders(auth) // Call the delegated method for extract the credentials from the Header
	} // In other case call the delegated method for extract the credentials from the body of the Request
	log.Info("ParseAuthenticationCoreHTTP | Credentials not in Headers, retrieving from body ...")
	user, pass := authutils.ParseAuthCredentialsFromRequestBody(ctx) // Used for extract user and password from the request
	return user, pass
}

// VerifyCookieFromRedisHTTP wrapper for verify if the user is logged
func VerifyCookieFromRedisHTTP(ctx *fasthttp.RequestCtx, redisClient *redis.Client) {
	var err error
	ctx.Response.Header.SetContentType("application/json; charset=utf-8") // Why not ? (:
	log.Debug("VerifyCookieFromRedisHTTP | Retrieving username ...")
	user, _ := ParseAuthenticationCoreHTTP(ctx)
	log.Debug("VerifyCookieFromRedisHTTP | Retrieving token ...")
	token := ParseTokenFromRequest(ctx)
	log.Debug("VerifyCookieFromRedisHTTP | Retrieving cookie from redis ...")
	auth := authutils.VerifyCookieFromRedisHTTPCore(user, token, redisClient) // Call the core function for recognize if the user have the token
	if strings.Compare(auth, "AUTHORIZED") == 0 {
		err = json.NewEncoder(ctx).Encode(datastructures.Response{Status: true, Description: "Logged in!", ErrorCode: auth, Data: nil})
		commonutils.Check(err, "VerifyCookieFromRedisHTTP")
	} else {
		err = json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Not logged in!", ErrorCode: auth, Data: nil})
		commonutils.Check(err, "VerifyCookieFromRedisHTTP")
	}
}

// DeleteCustomerHTTP wrapper for verify if the user is logged
func DeleteCustomerHTTP(ctx *fasthttp.RequestCtx, db string, coll string, redisClient *redis.Client, mgoClient *mgo.Session) {
	var err error
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	log.Debug("DeleteCustomerHTTP | Retrieving username ...")
	user, psw := ParseAuthenticationCoreHTTP(ctx)
	log.Debug("DeleteCustomerHTTP | Retrieving token ...")
	token := ParseTokenFromRequest(ctx)
	log.Debug("DeleteCustomerHTTP | Retrieving cookie from redis ...")
	status := authutils.DeleteCustomerHTTPCore(user, psw, token, db, coll, redisClient, mgoClient)
	if strings.Compare(status, "OK") == 0 {
		err = json.NewEncoder(ctx).Encode(datastructures.Response{Status: true, Description: "User " + user + " removed!", ErrorCode: status, Data: nil})
		commonutils.Check(err, "DeleteCustomerHTTP")
	} else {
		err = json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "User " + user + " NOT removed!", ErrorCode: status, Data: nil})
		commonutils.Check(err, "DeleteCustomerHTTP")
	}
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
	_, err := ctx.Write([]byte("Retry !"))
	commonutils.Check(err, "fastBenchmarkHTTP")
}

// middleware is the function delegated to take in charge the request of the customer, be sure that is logged in, then call
// the external service that the user want to contact. If the customers is authorized (the token proved in the request match with the one retrieved
// from Redis), the query will be executed and the result will be showed back as a response.
func middleware(ctx *fasthttp.RequestCtx, redisClient *redis.Client) {
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	log.Info("CTX: ", string(ctx.PostBody())) // Logging the arguments of the request
	var req datastructures.MiddlewareRequest
	err := json.Unmarshal(ctx.PostBody(), &req) // Populate the structure from the json
	commonutils.Check(err, "middleware")
	log.Info("Request unmarshalled: ", req)
	log.Debug("Validating request ...")
	if authutils.ValidateMiddlewareRequest(req) { // Verify it the json is valid
		log.Info("Request valid! Verifying token from Redis ...")
		auth := authutils.VerifyCookieFromRedisHTTPCore(req.Username, req.Token, redisClient) // Call the core function for recognize if the user have the token
		if strings.Compare(auth, "AUTHORIZED") == 0 {                                         // Token in redis, call the external service..
			log.Info("REQUEST OK> ", req)
			log.Warn("Using service ", req.Method, " | ARGS: ", req.Data, " | Token: ", req.Token, " | USR: ", req.Username)
			_, err := ctx.Write(sendGet(req))
			commonutils.Check(err, "middleware")
			return
		}
		err = json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "NOT AUTHORIZED!!", ErrorCode: "YOU_SHALL_NOT_PASS", Data: nil})
		commonutils.Check(err, "middleware")
		return
	}
	err = json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Not Valid Json!", ErrorCode: "", Data: req})
	commonutils.Check(err, "middleware")
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

	// TODO: Create class for manage response
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
