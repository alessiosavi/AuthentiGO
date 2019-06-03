package basicmongo

import (
	"strings"

	"github.ibm.com/Alessio-Savi/AuthentiGo/datastructures"

	log "github.com/sirupsen/logrus"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

// InitMongoDBConnection return a session to the Mongo instances configured in input.
// If input is null connect to the default instances
func InitMongoDBConnection(host string, port int, connectionMode string, refreshMode bool) *mgo.Session {
	log.Warn("InitMongoDBConnection | Connecting to MongoDB using: ", host)
	session, err := mgo.Dial(host) // Connection to MongoDB
	if err != nil {
		log.Error("InitMongoDBConnection | Error! MongoDB does not reply! :/", session)
		return nil
	}
	log.Warn("InitMongoDBConnection | Connection init finished succesfully! | ", session)
	log.Info("InitMongoDBConnection | Running in Strong (secure read/write) mode")
	session.SetMode(mgo.Strong, true) // Configuring MongoDB session
	return session
}

// RemoveCollectionFromDB is used for remove the collection in input from the db
func RemoveCollectionFromDB(session *mgo.Session, database string, collection string) error {
	log.Warn("Removing collection: ", collection, " From DB: ", database)
	err := session.DB(database).C(collection).DropCollection()
	if err != nil {
		log.Error("Fatal error :/ ", err)
		return err
	}
	log.Warn("Collection ", collection, " removed succesfully!")
	return nil
}

// InsertData is used for insert a generic data into a collection
// It take in input the session, database and collection where insert the change
func InsertData(User datastructures.Person, session *mgo.Session, database, collection, username string) string {
	log.Info("InsertData | Verify if customer is alredy registered in DB: ", database, " | Collection: ", collection)
	err := session.DB(database).C(collection).Find(bson.M{"Username": username}).Select(bson.M{"Username": 1}).One(nil) // Searching the user
	log.Warn("InsertData | ", err)
	if err != nil { // User is not present into the DB
		log.Debug("InsertData | Registering new client ...")
		err = session.DB(database).C(collection).Insert(User)
		if err != nil {
			log.Error("InsertData | Some error occurs during insert, impossible to register a new Customer :/ | Err: ", err)
			return "KO"
		}
		log.Warning("InsertData | Client registered! | ", User)
		return "OK"
	}
	log.Error("InsertData | Client alredy exists! | ", User, " | ERR: ", err)
	return "ALREDY_EXIST"
}

// RemoveUser Remove a registered user from MongoDB
func RemoveUser(session *mgo.Session, database, collection, username string) error {
	log.Info("RemoveUser | Removing user: ", username, " | From DB: ", database, " | Collection: ", collection)
	err := session.DB(database).C(collection).Remove(bson.M{"Username": username})
	if err != nil {
		log.Error("RemoveUser | Error during delete of user :( | User: ", username, " | Session: ", session, " | Error: ", err)
		return err
	}
	log.Warn("RemoveUser | Correctly deleted | ", username)
	return nil
}

// InitServerData is used for retrieve the list of DBs name from the mongo instance in input.
// It fetch the list of DBs from the Mongo instance.
// Return a pointer to a structure for store and manipulate the data
func InitServerData(session *mgo.Session) *datastructures.ServerData {
	var dbList []string
	var dataServer datastructures.ServerData
	dbList, err := session.DatabaseNames() // Retrieving the list of DB
	if err != nil {
		log.Error("Error! During retrieving of DB Names :/", session)
		return nil
	}
	log.Info("List of DB: ", dbList)
	dataServer = datastructures.ServerData{DatabaseList: make([]datastructures.Database, len(dbList))} // Init the structure for receive the data
	for i := 0; i < len(dbList); i++ {                                                                 // Iterate the list of DB names
		dataServer.DatabaseList[i].Name = dbList[i] // Save the name of DBs in mongo into the structure
	}
	log.Info("DB Saved! ", dataServer, "\n")
	return &dataServer
}

// PopulateCollectionList populate the list of Collections from the database list name in input.
// Populate the structure in input, just for test purpouse
func PopulateCollectionList(session *mgo.Session, dataServer *datastructures.ServerData) error {
	for i := 0; i < len(dataServer.DatabaseList); i++ { // Save the name of collection into the relative structure
		log.Info("Retrieving collections from -> " + dataServer.DatabaseList[i].Name)
		collectionsNames, err := session.DB(dataServer.DatabaseList[i].Name).CollectionNames() // Get the list of collections
		if err != nil {
			log.Error("Error! During retrieving of DB Names :/", session)
			return err
		}
		log.Warn("Retrieved ", collectionsNames, " | ", dataServer.DatabaseList[i])
		dataServer.DatabaseList[i].Collections = make([]datastructures.Collection, len(collectionsNames))
		for j := 0; j < len(collectionsNames); j++ { // Iterating the collections name
			dataServer.DatabaseList[i].Collections[j].Name = collectionsNames[j]
			log.Info("Collection Name -> ", session.DB(dataServer.DatabaseList[i].Name).C(dataServer.DatabaseList[i].Collections[j].Name).Find(bson.M{}))
			// Retrieving collection data
			for k := 0; k < len(dataServer.DatabaseList[i].Collections); k++ {
				err := session.DB(dataServer.DatabaseList[i].Name).C(dataServer.DatabaseList[i].Collections[j].Name).Find(bson.M{}).All(&dataServer.DatabaseList[i].Collections[j].Document)
				if err != nil {
					log.Error("Fatal error :/ ", err)
					log.Error("Collection error -> ", dataServer.DatabaseList[i].Collections[j].Document)
					return err
				}
				log.Warn("Data -> ", dataServer.DatabaseList[i].Collections[j].Document)
			}
		}
	}
	return nil
}

// GetCollectionsData is used for retrieve the list of Collections from the DB in input.
// It return a list of collection containing all the data [Used for test purpouse]
func GetCollectionsData(session *mgo.Session, database string) []datastructures.Collection {
	var collectionsNames []string               //List of collection related to the DB iterated
	var err error                               // General exception
	var collections []datastructures.Collection // List of collection to return

	log.Info("Retrieving collection from -> ", database)
	collectionsNames, err = session.DB(database).CollectionNames() // Get the list of collections related to the DB
	if err != nil {
		log.Error("Error! During retrieving of DB Names :/", session)
		return nil
	}
	log.Warn("Retrieved ", collectionsNames, " | ", database)
	collections = make([]datastructures.Collection, len(collectionsNames))

	for j := 0; j < len(collectionsNames); j++ { // Iterating the collections name
		collections[j].Name = collectionsNames[j]
		log.Info("Collection Name -> ", collections[j].Name)             // Retrieve everything
		if strings.Compare(collections[j].Name, "system.profile") == 0 { // Removing MongoDB profiling collections
			log.Error("Removing ", collections[j].Name, " ...")
			//RemoveCollectionFromDB(session, database, collections[j].Name)
		} else if strings.Contains(collections[j].Name, "icket") || strings.Contains(collections[j].Name, "ava") { // Ignore big ticket DB
			log.Error("Skipping ", collections[j].Name, " ...")
		} else {
			for k := 0; k < len(collections); k++ { // Retrieving collection data
				err := session.DB(database).C(collections[j].Name).Find(bson.M{}).All(&collections[j].Document) // Retrieve & Save the document into address of collections[index].Document
				if err != nil {
					log.Error("Fatal error :/ ", err)
					log.Error("Collection error -> ", collections[j].Document)
					return nil
				}
				log.Warn("Data -> ", collections[j].Document)
			}
		}
	}
	return collections
}
