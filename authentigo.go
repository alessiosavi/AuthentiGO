package authentigo

import (
	"bytes"
	"encoding/base64"
	basicmongo "gologviewer/utils/database/mongo"
	basicredis "gologviewer/utils/database/redis"
	"regexp"
	"strings"
	"time"

	"github.com/globalsign/mgo/bson"
	log "github.com/sirupsen/logrus" // Pretty log library, not the fastest (zerolog/zap)
	"github.com/valyala/fasthttp"
)

// Person structure of a customer for save it into the DB during registration phase.
type Person struct {
	ID        bson.ObjectId `bson:"_id,omitempty" json:"_id,omitempty"`
	Username  string        `bson:"Username,omitempty" json:"Username,omitempty"`
	Password  string        `bson:"Password,omitempty" json:"Password,omitempty"`
	Name      string        `bson:"Name,omitempty" json:"Name,omitempty"`
	Surname   string        `bson:"Surname,omitempty"`
	Birthday  time.Time     `bson:"Birthday,omitempty"` // time.Date(2014, time.November, 5, 0, 0, 0, 0, time.UTC)
	Cellphone string        `bson:"Cellphone,omitempty"`
	Phone     string        `bson:"Phone,omitempty"`
	Addresses []Info        `bson:"Addresses,omitempty"`
	Mail      string        `bson:"Mail,omitempty" json:"Mail,omitempty"`
	WorkMail  string        `bson:"WorkMail,omitempty"`
}

// Info Used for track user skill/experience/role
type Info struct {
	Type   string   `bson:"Type,omitempty"`   // IT Specialist
	Skills []string `bson:"Skills,omitempty"` // Java, Spring, Golang
	Years  int      `bson:"Years,omitempty"`
	City   City     `bson:"City,omitempty"`
}

// City save the location status of the customer
type City struct {
	Name    string `bson:"Name,omitempty"` // Bergamo
	Town    string `bson:"Town,omitempty"` // Verdello
	ZipCode int    `bson:"ZipCode,omitempty"`
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
	log.Info("ParseAuthenticationHTTP | Auth Headers: ", string(auth))
	if bytes.HasPrefix(auth, basicAuthPrefix) { // Check if the login is executed using the BasicAuth headers
		return ParseAuthCredentialFromHeaders(ctx, auth) // Call the delegated method for extract the credentials from the Header
	} // In other case call the delegated method for extract the credentials from the body of the Request
	log.Info("ParseAuthenticationCoreHTTP | Credentials not in Headers, analyzing the body of the request ...")
	user, pass := ParseAuthCredentialsFromRequestBody(ctx) // Used for extract user and password from the request
	return user, pass
}

// LoginUserCoreHTTP is delegated to manage the "core process" of authentication. It use the username in input for retrieve the customer
// data from MongoDB. If the data is found, then the password in input will be compared with the one retrieved from the database
func LoginUserCoreHTTP(username, password string) string {
	log.Debug("LoginUserHTTP | Verify if user [", username, "] is registered ...")
	mongoClient := basicmongo.InitMongoDBConnection(nil) // Connect to the default (nil) database
	if mongoClient == nil {                              // 10 seconds wait
		log.Error("RegisterUserCoreHTTP | Impossible to connect to DB | ", mongoClient)
		return "DB_UNAVAIBLE"
	}
	defer mongoClient.Close() // TODO: Possibile to do better ?
	log.Info("LoginUserHTTP | Getting value from DB ...")
	var User Person                                                                                     // Allocate a Person for store the DB result of next instruction
	err := mongoClient.DB("GoLog-Customer").C("Customer").Find(bson.M{"Username": username}).One(&User) // Searching the user and assign the result (&) to User
	log.Warn("LoginUserHTTP | Dumping result from DB: ", User, " | ERROR: ", err)
	if err == nil { // User found... Let's now compare the password ..
		log.Debug("LoginUserHTTP | Comparing password ...")
		if strings.Compare(User.Password, password) == 0 { // Comparing password of the user from DB with the one in input
			log.Warn("LoginUserHTTP | Client credential authorizated !!! | User: ", User)
			return "OK"
		}
		log.Error("LoginUserHTTP | Passwords does not match!!")
		return "PSW"
	}
	log.Error("LoginUserHTTP | User is not registered!")
	return "USR"
}

// InsertTokenIntoRedis is delegated to store the token of the customer into Redis. After that a customer have logged in, the token
// assigned as a cookie is stored into Redis (used as a Cache), in order to validate every request without query MongoDB.
func InsertTokenIntoRedis(User Person, token string) string {
	log.Info("LoginUserHTTP | Inserting token into Redis for user ", User)
	redisClient, err := basicredis.ConnectToDb("", "") // Connect to the default redis instance
	if err != nil {
		log.Error("RegisterUserCoreHTTP | Impossible to connect to Redis for store the token | CLIENT: ", redisClient, " | ERR: ", err)
		return "REDIS_DB_UNAVAIBLE"
	} // Store the token for future auth check
	basicredis.InsertIntoClient(redisClient, User.Username, token) // insert the token into the DB
	log.Info("LoginUserHTTP | Token inserted! All operation finished correctly!")
	return "OK"
}

// RegisterUserCoreHTTP is delegated to register the credential of the user into the Redis database.
// It estabilish the connection to MongoDB with a specialized function, then it create an user with the input data.
// After that, it ask to a delegated function to insert the data into Redis.
func RegisterUserCoreHTTP(username, password string) string {
	log.Debug("RegisterUserCoreHTTP | Registering [", username, ":", password, "]")
	mongoClient := basicmongo.InitMongoDBConnection(nil) // Enstabilish the connection to the default DB
	if mongoClient == nil {
		log.Error("RegisterUserCoreHTTP | Impossible to connect to DB | ", mongoClient)
		return "DB_UNAVAIBLE"
	}
	defer mongoClient.Close()
	User := Person{Username: username, Password: password, Birthday: time.Now()}            // Create the user
	return basicmongo.InsertData(User, mongoClient, "GoLog-Customer", "Customer", username) // Ask to a delegated function to insert the data
}

// VerifyCookieFromRedisCoreHTTP is delegated to verify if the cookie of the customer is present on the DB (aka is logged).
// This method have only to verify if the token provided by the customer that use the API is present on RedisDB.
// In first instance it try to validate the input data. Then will continue connecting to Redis in order to retrieve the token of
// the customer. If the token is found, the customer is authorized to continue.
func VerifyCookieFromRedisCoreHTTP(user, token string) string {
	if UsernameValidation(user) { // Verify that the credentials respect the rules
		if TokenValidation(token) { // Verify that the token respect the rules
			redisClient, err := basicredis.ConnectToDb("", "") // Connect to the default redis instance
			if err != nil {
				log.Error("VerifyCookieFromRedisCoreHTTP | Impossible to connect to Redis for store the token | CLIENT: ", redisClient, " | ERR: ", err)
				return "REDIS_DB_UNAVAIBLE"
			} // Retrieve the token for compare
			check, dbToken := basicredis.GetValueFromDB(redisClient, user)
			if check == true {
				if strings.Compare(dbToken, token) == 0 {
					log.Info("VerifyCookieFromRedisCoreHTTP | Token MATCH!! User is logged! | ", user, " | ", token)
					return "AUTHORIZED"
				}
				log.Error("VerifyCookieFromRedisCoreHTTP | Token MISMATCH!! User is NOT logged! | ", user, " | TK: ", token, " | DB: ", dbToken)
				return "NOT_AUTHORIZED"
			}
			log.Error("VerifyCookieFromRedisCoreHTTP | Token not present in DB")
			return "USER_NOT_LOGGED"
		}
		log.Error("VerifyCookieFromRedisCoreHTTP | Token not valid :/ | Token: ", token)
		return "COOKIE_NOT_VALID"
	}
	log.Error("VerifyCookieFromRedisCoreHTTP | Username or password mispelled")
	return "USERNAME_NOT_VALID"
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

// ParseAuthCredentialFromHeaders is delegated to extract the username and the password from the BasicAuth header provided by the request
// In case of error will return two emtpy string; in case of success will return (username,password)
func ParseAuthCredentialFromHeaders(ctx *fasthttp.RequestCtx, auth []byte) (string, string) {
	basicAuthPrefix := []byte("Basic ")
	payload, err := base64.StdEncoding.DecodeString(string(auth[len(basicAuthPrefix):])) // Extract only the string after the "Basic "
	log.Info("parseAuthCredentialFromHeaders | Payload extracted: ", payload)
	if err != nil {
		log.Error("parseAuthCredentialFromHeaders | STOP | KO | ", err)
		return "", "" // error cause
	}
	pair := bytes.SplitN(payload, []byte(":"), 2) // Extract the username [0] and password [1] separated by the ':'
	if len(pair) == 2 {                           // Only "username:password" admitted!
		log.Info("parseAuthCredentialFromHeaders | Payload splitted: ", string(pair[0]), " | ", string(pair[1]))
		return string(pair[0]), string(pair[1])
	}
	log.Error("parseAuthCredentialFromHeaders | Impossible to split the payload :/ | Payload: ", payload, " | Basic: ", string(auth))
	return "", "" // error cause
}

// ValidateCredentials is wrapper for the multiple method for validate the input parameters
func ValidateCredentials(user string, pass string) bool {
	if UsernameValidation(user) && PasswordValidation(pass) {
		return true
	}
	return false
}

// PasswordValidation execute few check on the password in input
func PasswordValidation(password string) bool {
	if strings.Compare(password, "") == 0 {
		log.Warn("PasswordValidation | Password is empty :/")
		return false
	}
	if len(password) < 4 || len(password) > 32 {
		log.Warn("PasswordValidation | Password len not valid")
		return false
	}
	myReg := regexp.MustCompile("^[a-zA-Z0-9]{4,32}$") // Only letter + number
	if !myReg.MatchString(password) {                  // If the input don't match the regexp
		log.Warn("PasswordValidation | Password have strange character :/ [", password, "]")
		return false
	}
	log.Info("PasswordValidation | Password [", password, "] VALIDATED!")
	return true
}

// UsernameValidation execute few check on the username in input
func UsernameValidation(username string) bool {
	if strings.Compare(username, "") == 0 {
		log.Warn("UsernameValidation | Username is empty :/")
		return false
	}
	if len(username) < 4 || len(username) > 32 {
		log.Warn("UsernameValidation | Username len not valid")
		return false
	}
	myReg := regexp.MustCompile("^[a-zA-Z0-9]{4,32}$") // The string have to contains ONLY (letter OR number)
	if !myReg.MatchString(username) {                  // the input doesn't match the regexp
		log.Warn("UsernameValidation | Username have strange character :/ [", username, "]")
		return false
	}
	log.Info("UsernameValidation | Username [", username, "] VALIDATED!")
	return true
}

// TokenValidation execute few check on the token in input
func TokenValidation(token string) bool {
	log.Debug("Validating [", token, "] ...")
	if strings.Compare(token, "") == 0 {
		log.Warn("TokenValidation | Token is empty :/")
		return false
	}
	if len(token) != 32 { // md5 32 char
		log.Warn("TokenValidation | Token len != 32 :/")
		return false
	}
	log.Info("TokenValidation | Token [", token, "] VALIDATED!")
	return true
}
