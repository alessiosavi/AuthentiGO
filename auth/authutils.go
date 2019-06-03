package authutils

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/valyala/fasthttp"
	basicmongo "github.ibm.com/Alessio-Savi/AuthentiGo/database/mongo"
	basicredis "github.ibm.com/Alessio-Savi/AuthentiGo/database/redis"
	"github.ibm.com/Alessio-Savi/AuthentiGo/datastructures"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	log "github.com/sirupsen/logrus"
)

// ====== HTTP CORE METHODS ======

// LoginUserHTTPCore is delegated to manage the "core process" of authentication. It use the username in input for retrieve the customer
// data from MongoDB. If the data is found, then the password in input will be compared with the one retrieved from the database
func LoginUserHTTPCore(username, password string, mongoClient *mgo.Session, db, coll string) string {
	log.Debug("LoginUserHTTPCore | Verify if user [", username, "] is registered ...")
	if mongoClient == nil { // 10 seconds wait
		log.Error("LoginUserHTTPCore | Impossible to connect to DB | ", mongoClient)
		return "DB_UNAVAIBLE"
	}
	log.Info("LoginUserHTTPCore | Getting value from DB ...")
	var User datastructures.Person                                                  // Allocate a Person for store the DB result of next instruction
	err := mongoClient.DB(db).C(coll).Find(bson.M{"Username": username}).One(&User) // Searching the user and assign the result (&) to User
	log.Warn("LoginUserHTTPCore | Dumping result from DB: ", User, " | ERROR: ", err)
	if err == nil { // User found... Let's now compare the password ..
		log.Debug("LoginUserHTTPCore | Comparing password ...")
		if strings.Compare(User.Password, password) == 0 { // Comparing password of the user from DB with the one in input
			log.Warn("LoginUserHTTPCore | Client credential authorizated !!! | User: ", User)
			return "OK"
		}
		log.Error("LoginUserHTTPCore | Passwords does not match!!")
		return "PSW"
	}
	log.Error("LoginUserHTTPCore | User is not registered!")
	return "USR"
}

// InsertTokenIntoRedis is delegated to store the token of the customer into Redis. After that a customer have logged in, the token
// assigned as a cookie is stored into Redis (used as a Cache), in order to validate every request without query MongoDB.
func InsertTokenIntoRedis(User datastructures.Person, token string, redisClient *redis.Client, expire int) string {
	log.Info("InsertTokenIntoRedis | Inserting token into Redis for user ", User)
	//redisClient, err := basicredis.ConnectToDb("", "") // Connect to the default redis instance
	if redisClient == nil {
		log.Error("InsertTokenIntoRedis | Impossible to connect to Redis for store the token | CLIENT: ", redisClient) //, " | ERR: ", err)
		return "REDIS_DB_UNAVAIBLE"
	} // Store the token for future auth check
	if basicredis.InsertIntoClient(redisClient, User.Username, token, expire) { // insert the token into the DB
		log.Info("InsertTokenIntoRedis | Token inserted! All operation finished correctly!")
		return "OK"
	}
	return "KO"
}

// RegisterUserHTTPCore is delegated to register the credential of the user into the Redis database.
// It estabilish the connection to MongoDB with a specialized function, then it create an user with the input data.
// After that, it ask to a delegated function to insert the data into Redis.
func RegisterUserHTTPCore(username, password string, mongoClient *mgo.Session, db, coll string) string {
	log.Debug("RegisterUserHTTPCore | Registering [", username, ":", password, "]")
	if mongoClient == nil {
		log.Error("RegisterUserHTTPCore | Impossible to connect to DB | ", mongoClient)
		return "DB_UNAVAIBLE"
	}
	log.Debug("RegisterUserHTTPCore | Verifying if connection is available ...")
	err := mongoClient.Ping()
	if err != nil {
		log.Error("MongoPing: ", err)
		return err.Error()
	}
	log.Debug("RegisterUserHTTPCore | Connection enstabilished! Inserting data ...")
	User := datastructures.Person{Username: username, Password: password, Birthday: time.Now()} // Create the user
	return basicmongo.InsertData(User, mongoClient, db, coll, username)                         // Ask to a delegated function to insert the data
}

// VerifyCookieFromRedisHTTPCore is delegated to verify if the cookie of the customer is present on the DB (aka is logged).
// This method have only to verify if the token provided by the customer that use the API is present on RedisDB.
// In first instance it try to validate the input data. Then will continue connecting to Redis in order to retrieve the token of
// the customer. If the token is found, the customer is authorized to continue.
func VerifyCookieFromRedisHTTPCore(user, token string, redisClient *redis.Client) string {
	log.Debug("VerifyCookieFromRedisHTTPCore | START | User: ", user, " | Token: ", token)
	if ValidateUsername(user) { // Verify that the credentials respect the rules
		if ValidateToken(token) { // Verify that the token respect the rules
			log.Debug("VerifyCookieFromRedisHTTPCore | Credential validated, retrieving token value from Redis ...")
			check, dbToken := basicredis.GetValueFromDB(redisClient, user)
			if check {
				log.Trace("VerifyCookieFromRedisHTTPCore | Data retrieved!")
				if strings.Compare(dbToken, token) == 0 {
					log.Info("VerifyCookieFromRedisHTTPCore | Token MATCH!! User is logged! | ", user, " | ", token)
					return "AUTHORIZED"
				}
				log.Error("VerifyCookieFromRedisHTTPCore | Token MISMATCH!! User is NOT logged! | ", user, " | TK: ", token, " | DB: ", dbToken)
				return "NOT_AUTHORIZED"
			}
			log.Error("VerifyCookieFromRedisHTTPCore | Token not present in DB")
			return "USER_NOT_LOGGED"
		}
		log.Error("VerifyCookieFromRedisHTTPCore | Token not valid :/ | Token: ", token)
		return "COOKIE_NOT_VALID"
	}
	log.Error("VerifyCookieFromRedisHTTPCore | Username or password mispelled")
	return "USERNAME_NOT_VALID"
}

func DeleteCustomerHTTPCore(user, password, token, db, coll string, redisClient *redis.Client, mgoClient *mgo.Session) string {
	log.Info("DeleteCustomerHTTPCore | Removing -> User: ", user, " | Psw: ", password, " | Token: ", token)
	log.Debug("DeleteCustomerHTTPCore | Validating username and password ...")
	if ValidateCredentials(user, password) {
		log.Debug("DeleteCustomerHTTPCore | Validating token ...")
		if ValidateToken(token) {
			log.Debug("DeleteCustomerHTTPCore | Input validated! | Retrieving data from DB ...")
			var User datastructures.Person                                            // Allocate a Person for store the DB result of next instruction
			err := mgoClient.DB(db).C(coll).Find(bson.M{"Username": user}).One(&User) // Searching the user and assign the result (&) to User
			if err == nil {                                                           // User found... Let's now compare the password ..
				log.Debug("DeleteCustomerHTTPCore | Comparing password ...")
				if strings.Compare(User.Password, password) == 0 { // Comparing password of the user from DB with the one in input
					log.Warn("DeleteCustomerHTTPCore | Password match !! | Retrieving token from Redis ...")
					check, dbToken := basicredis.GetValueFromDB(redisClient, user)
					if check {
						log.Debug("DeleteCustomerHTTPCore | Data retrieved [", dbToken, "]! | Comparing token ...")
						if strings.Compare(token, dbToken) == 0 {
							log.Info("DeleteCustomerHTTPCore | Token match!! | Deleting customer [", user, "] from MongoDB ..")
							err = basicmongo.RemoveUser(mgoClient, db, coll, user)
							if err != nil {
								log.Error("DeleteCustomerHTTPCore | Error during delete of user :( | User: ", user, " | Session: ", mgoClient, " | Error: ", err)
								return "KO_DELETE_MONGO"
							}
							log.Info("DeleteCustomerHTTPCore | Customer [", user, "] deleted!! | Removing token")
							if basicredis.RemoveValueFromDB(redisClient, user) {
								log.Info("DeleteCustomerHTTPCore | Token removed from Redis | Bye bye [", User, "]")
								return "OK"
							}
						}
						log.Error("DeleteCustomerHTTPCore | User [", user, "] have tried to delete the account with a valid password but with an invalid token!!")
						log.Error("DeleteCustomerHTTPCore | TokenDB: ", token, " | Customer: ", User)
						return "TOKEN_MANIPULATED"
					}
					log.Error("DeleteCustomerHTTPCore | User [", user, "] not logged in!!")
					return "NOT_LOGGED"

				}
				log.Error("DeleteCustomerHTTPCore | Passwords does not match!!")
				return "PSW"
			}
			log.Error("DeleteCustomerHTTPCore | User [", user, "] is not registered yet!!")
			return "NOT_REGISTER"

		}
		log.Error("DeleteCustomerHTTPCore | Token [", token, "] is not valid!")
		return "TOKEN"

	}
	log.Error("DeleteCustomerHTTPCore | Credentials [Usr: ", user, " | Psw: ", password, "] not valid!!")
	return "NOT_REGISTER"
}

// ====== HTTP UTILS METHODS ======

// ParseAuthCredentialFromHeaders is delegated to extract the username and the password from the BasicAuth header provided by the request
// In case of error will return two emtpy string; in case of success will return (username,password)
func ParseAuthCredentialFromHeaders(auth []byte) (string, string) {
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
	if ValidateUsername(user) && PasswordValidation(pass) {
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

// ValidateUsername execute few check on the username in input
func ValidateUsername(username string) bool {
	if strings.Compare(username, "") == 0 {
		log.Warn("ValidateUsername | Username is empty :/")
		return false
	}
	if len(username) < 4 || len(username) > 32 {
		log.Warn("ValidateUsername | Username len not valid")
		return false
	}
	myReg := regexp.MustCompile("^[a-zA-Z0-9]{4,32}$") // The string have to contains ONLY (letter OR number)
	if !myReg.MatchString(username) {                  // the input doesn't match the regexp
		log.Warn("ValidateUsername | Username have strange character :/ [", username, "]")
		return false
	}
	log.Info("ValidateUsername | Username [", username, "] VALIDATED!")
	return true
}

// ValidateToken execute few check on the token in input
func ValidateToken(token string) bool {
	log.Debug("ValidateToken | Validating [", token, "] ...")
	if strings.Compare(token, "") == 0 {
		log.Warn("ValidateToken | Token is empty :/")
		return false
	}
	if !(len(token) > 0 && len(token) < 100) {
		log.Warn("ValidateToken | Token len not in 0<token<100 :/ [found ", len(token), "]")
		return false
	}
	log.Info("ValidateToken | Token [", token, "] VALIDATED!")
	return true
}

// RedirectCookie return the cookie by the parameter in input and reassing to the response
func RedirectCookie(ctx *fasthttp.RequestCtx, expire int) string {
	var cookie string
	cookie = string(ctx.Request.Header.Cookie("GoLog-Token"))
	if strings.Compare(cookie, "") == 0 {
		cookie = "USER_NOT_LOGGED_IN"
	}
	ctx.Response.Header.SetCookie(CreateCookie("GoLog-Token", cookie, expire))
	return cookie
}

// ParseAuthCredentialsFromRequestBody is delegated to extract the username and the password from the request body
func ParseAuthCredentialsFromRequestBody(ctx *fasthttp.RequestCtx) (string, string) {
	user := string(ctx.FormValue("user")) // Extracting data from request
	pass := string(ctx.FormValue("pass"))
	return user, pass
}

//CreateCookie Method that return a cookie valorized as input (GoLog-Token as key)
func CreateCookie(key string, value string, expire int) *fasthttp.Cookie {
	if strings.Compare(key, "") == 0 {
		key = "GoLog-Token"
	}
	log.Debug("CreateCookie | Creating Cookie | Key: ", key, " | Val: ", value)
	authCookie := fasthttp.Cookie{}
	authCookie.SetKey(key)
	authCookie.SetValue(value)
	authCookie.SetMaxAge(expire)
	authCookie.SetHTTPOnly(true)
	authCookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	return &authCookie
}

// ValidateMiddlewareRequest is developed in order to verify it the request from the customer is valid. Can be view as a "filter"
func ValidateMiddlewareRequest(request datastructures.MiddlewareRequest) bool {
	if ValidateUsername(request.Username) { // Validate the username
		if ValidateToken(request.Token) { // Validate the token
			if strings.Compare(request.Method, "") != 0 { // Verify if the request is not empty
				return true
			}
		}
	}
	return false
}
