package authutils

import (
	"bytes"
	"encoding/base64"
	"github.com/go-redis/redis"
	basicmongo "github.ibm.com/Alessio-Savi/AuthentiGo/database/mongo"
	basicredis "github.ibm.com/Alessio-Savi/AuthentiGo/database/redis"
	"github.ibm.com/Alessio-Savi/AuthentiGo/datastructures"
	"regexp"
	"strings"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	log "github.com/sirupsen/logrus"
)

// LoginUserCoreHTTP is delegated to manage the "core process" of authentication. It use the username in input for retrieve the customer
// data from MongoDB. If the data is found, then the password in input will be compared with the one retrieved from the database
func LoginUserCoreHTTP(username, password string, mongoClient *mgo.Session, db, coll string) string {
	log.Debug("LoginUserHTTP | Verify if user [", username, "] is registered ...")
	if mongoClient == nil { // 10 seconds wait
		log.Error("RegisterUserCoreHTTP | Impossible to connect to DB | ", mongoClient)
		return "DB_UNAVAIBLE"
	}
	log.Info("LoginUserHTTP | Getting value from DB ...")
	var User datastructures.Person                                                  // Allocate a Person for store the DB result of next instruction
	err := mongoClient.DB(db).C(coll).Find(bson.M{"Username": username}).One(&User) // Searching the user and assign the result (&) to User
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
func InsertTokenIntoRedis(User datastructures.Person, token string, redisClient *redis.Client) string {
	log.Info("LoginUserHTTP | Inserting token into Redis for user ", User)
	//redisClient, err := basicredis.ConnectToDb("", "") // Connect to the default redis instance
	if redisClient == nil {
		log.Error("RegisterUserCoreHTTP | Impossible to connect to Redis for store the token | CLIENT: ", redisClient) //, " | ERR: ", err)
		return "REDIS_DB_UNAVAIBLE"
	} // Store the token for future auth check
	if basicredis.InsertIntoClient(redisClient, User.Username, token) { // insert the token into the DB
		log.Info("LoginUserHTTP | Token inserted! All operation finished correctly!")
		return "OK"
	}
	return "KO"
}

// RegisterUserCoreHTTP is delegated to register the credential of the user into the Redis database.
// It estabilish the connection to MongoDB with a specialized function, then it create an user with the input data.
// After that, it ask to a delegated function to insert the data into Redis.
func RegisterUserCoreHTTP(username, password string, mongoClient *mgo.Session, db, coll string) string {
	log.Debug("RegisterUserCoreHTTP | Registering [", username, ":", password, "]")
	//mongoClient := basicmongo.InitMongoDBConnection(nil) // Enstabilish the connection to the default DB
	if mongoClient == nil {
		log.Error("RegisterUserCoreHTTP | Impossible to connect to DB | ", mongoClient)
		return "DB_UNAVAIBLE"
	}
	User := datastructures.Person{Username: username, Password: password, Birthday: time.Now()} // Create the user
	return basicmongo.InsertData(User, mongoClient, db, coll, username)                         // Ask to a delegated function to insert the data
}

// VerifyCookieFromRedisCoreHTTP is delegated to verify if the cookie of the customer is present on the DB (aka is logged).
// This method have only to verify if the token provided by the customer that use the API is present on RedisDB.
// In first instance it try to validate the input data. Then will continue connecting to Redis in order to retrieve the token of
// the customer. If the token is found, the customer is authorized to continue.
func VerifyCookieFromRedisCoreHTTP(user, token string, redisClient *redis.Client) string {
	log.Debug("VerifyCookieFromRedisCoreHTTP | START | User: ", user, " | Token: ", token)
	if ValidateUsername(user) { // Verify that the credentials respect the rules
		if ValidateToken(token) { // Verify that the token respect the rules
			log.Debug("VerifyCookieFromRedisCoreHTTP | Credential validated, retrieving token value from Redis ...")
			check, dbToken := basicredis.GetValueFromDB(redisClient, user)
			log.Trace("VerifyCookieFromRedisCoreHTTP | Data retrieved!")
			if check {
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
	if len(token) != 52 {
		log.Warn("ValidateToken | Token len != 52 :/ [found ", len(token), "]")
		return false
	}
	log.Info("ValidateToken | Token [", token, "] VALIDATED!")
	return true
}
