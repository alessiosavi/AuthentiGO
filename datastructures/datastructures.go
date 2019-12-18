package datastructures

import (
	"github.com/globalsign/mgo/bson"
	"time"
)

// configuration is the structure for handle the configuration data
type Configuration struct {
	Host    string // Hostname to bind the service
	Port    int    // Port to bind the service
	Version string
	SSL     struct {
		Path    string
		Cert    string
		Key     string
		Enabled bool
	}
	Mongo struct {
		Host  string
		Port  int
		Users struct {
			DB         string
			Collection string
		}
	}
	Redis struct {
		Host  string
		Port  string
		Token struct {
			Expire int
			DB     int
		}
	}
	Log struct {
		Level string
		Path  string
		Name  string
	}
}

// status Structure used for populate the json response for the RESTfull HTTP API
type Response struct {
	Status      bool        `json:"Status"`      // Status of response [true,false] OK, KO
	ErrorCode   string      `json:"ErrorCode"`   // Code linked to the error (KO)
	Description string      `json:"Description"` // Description linked to the error (KO)
	Data        interface{} `json:"Data"`        // Generic data to return in the response
}

// middlewareRequest Structure used for manage the request among the user and the external service
type MiddlewareRequest struct {
	Username string   `json:"user"`    // Username of the customer that require the service
	Token    string   `json:"token"`   // Token related to the user for consume the service
	Service  string   `json:"service"` // Is the external service that you want to call
	Method   string   `json:"method"`  // POST-GET-HEAD etc etc
	Headers  []string `json:"headers"` // Headers to send in the request
	Data     string   `json:"data"`    // Is the arguments that you want to encode in your request
}

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

// Database struct for DB
type Database struct {
	Name        string
	Collections []Collection
}

// Collection struct for DB
type Collection struct {
	Name     string
	Document []interface{}
}

// ServerData struct for manage DB
type ServerData struct {
	DatabaseList []Database
}
