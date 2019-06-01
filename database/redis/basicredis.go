package basicredis

import (
	"strings"

	"github.com/go-redis/redis"
	log "github.com/sirupsen/logrus"
)

// ConnectToDb use emtpy string for hardcoded port
func ConnectToDb(addr string, port string) *redis.Client {
	if strings.Compare(addr, port) == 0 {
		addr = "localhost"
		port = "6379"
	}
	client := redis.NewClient(&redis.Options{
		Addr:     addr + ":" + port,
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	log.Info("Connecting to -> ", client)
	err := client.Ping().Err()
	if err != nil {
		log.Fatal("Impossibile to connecto to DB ....| CLIENT: ", addr, ":", port, " | ERR: ", err)
		return nil
	}
	return client
}

// GetValueFromDB is delegated to check if a key is alredy inserted and return the value
func GetValueFromDB(client *redis.Client, key string) (bool, string) {
	tmp, err := client.Get(key).Result()
	if err == nil {
		log.Debug("GetValueFromDB | SUCCESS | Key: ", key, " | Value: ", tmp)
		return true, tmp
	} else if err == redis.Nil {
		log.Warn("GetValueFromDB | Key -> ", key, " does not exist")
		return false, tmp
	}
	log.Error("GetValueFromDB | Fatal exception during retrieving of data [", key, "] | Redis: ", client)
	panic(err)

}

// InsertIntoClient set the two value into the Databased pointed from the client
func InsertIntoClient(client *redis.Client, key string, value string) bool {
	log.Info("InsertIntoClient | Inserting -> (", key, ":", value, ")")
	err := client.Set(key, value, 0).Err() // Inserting the values into the DB
	if err != nil {
		panic(err) //return false
	}
	log.Info("InsertIntoClient | INSERTED SUCCESFULLY!! | (", key, ":", value, ")")
	return true
}
