package commonutils

import (
	"encoding/json"
	"flag"
	"math/rand"
	"os"
	"strings"
	"time"

	"alessiosavi/AuthentiGo/datastructures"

	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func Check(err error, method string) bool {
	if err != nil {
		log.Error("Error on method {" + method + "}! [" + err.Error() + "]")
		return false
	}
	return true
}

// VerifyCommandLineInput is delegated to manage the inputer parameter provide with the input flag from command line
func VerifyCommandLineInput() datastructures.Configuration {
	log.Debug("VerifyCommandLineInput | Init a new configuration from the conf file")
	c := flag.String("config", "./conf/test.json", "Specify the configuration file.")
	flag.Parse()
	if strings.Compare(*c, "") == 0 {
		log.Fatal("VerifyCommandLineInput | Call the tool using --config conf/config.json")
	}
	file, err := os.Open(*c)
	if err != nil {
		log.Fatal("VerifyCommandLineInput | can't open config file: ", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	cfg := datastructures.Configuration{}
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatal("VerifyCommandLineInput | can't decode config JSON: ", err)
	}
	log.Debug("VerifyCommandLineInput | Conf loaded -> ", cfg)

	return cfg
}

func AuthLoginWrapperErrorHelper(ctx *fasthttp.RequestCtx, err, username, password string) {
	if strings.Compare(err, "NOT_VALID") == 0 { // Input does not match with rules
		log.Error("AuthLoginWrapper | Input does not respect the rules :/! | ", username, ":", password)
		ctx.Response.Header.DelCookie("GoLog-Token")
		err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Wrong input!", ErrorCode: username, Data: nil})
		Check(err, "AuthLoginWrapperErrorHelper")
	} else if strings.Compare(err, "USR") == 0 { //User does not exist in DB
		log.Error("AuthLoginWrapper | Client does not exists! | ", username, ":", password)
		ctx.Response.Header.DelCookie("GoLog-Token")
		err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "User does not exists!", ErrorCode: "USER_NOT_REGISTERED", Data: nil})
		Check(err, "AuthLoginWrapperErrorHelper")
	} else if strings.Compare(err, "PSW") == 0 { //Password mismatch
		log.Error("AuthLoginWrapper | Password does not match! | ", username, ":", password)
		ctx.Response.Header.DelCookie("GoLog-Token")
		err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Password don't match!", ErrorCode: username, Data: nil})
		Check(err, "AuthLoginWrapperErrorHelper")
	} else { // General error cause
		err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Unable to connect to MongoDB", ErrorCode: err, Data: nil})
		Check(err, "AuthLoginWrapperErrorHelper")
	}

}

func AuthRegisterErrorHelper(ctx *fasthttp.RequestCtx, check, username, password string) {
	if strings.Compare(check, "NOT_VALID") == 0 { // Input don't match with rules
		log.Error("AuthRegisterWrapper | Input does not respect the rules :/! | ", username, ":", password)
		ctx.Response.Header.DelCookie("GoLog-Token")
		err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Wrong input!", ErrorCode: username, Data: nil})
		Check(err, "AuthRegisterErrorHelper")
	} else if strings.Compare(check, "ALREDY_EXIST") == 0 { //User alredy present in DB
		log.Error("AuthRegisterWrapper | User alredy exists! | ", username, ":", password)
		err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "User alredy exists!", ErrorCode: username, Data: nil})
		Check(err, "AuthRegisterErrorHelper")
	} else { // General error cause
		err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Unable to connect to DB", ErrorCode: check, Data: nil})
		Check(err, "AuthRegisterErrorHelper")
	}

}

// SetDebugLevel return the LogRus object by the given string
func SetDebugLevel(level string) log.Level {
	if strings.Compare(strings.ToLower(level), "debug") == 0 {
		return log.DebugLevel
	} else if strings.Compare(strings.ToLower(level), "trace") == 0 {
		return log.TraceLevel
	} else if strings.Compare(strings.ToLower(level), "info") == 0 {
		return log.InfoLevel
	} else if strings.Compare(strings.ToLower(level), "error") == 0 {
		return log.ErrorLevel
	} else if strings.Compare(strings.ToLower(level), "fatal") == 0 {
		return log.FatalLevel
	} else if strings.Compare(strings.ToLower(level), "panic") == 0 {
		return log.PanicLevel
	} else if strings.Contains(strings.ToLower(level), "warn") {
		return log.WarnLevel
	}
	return log.DebugLevel
}

// Random initalizate a new seed using the UNIX Nano time and return an integer between the 2 input value
func Random(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}
