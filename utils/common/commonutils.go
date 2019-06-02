package commonutils

import (
	"encoding/json"
	"flag"
	log "github.com/sirupsen/logrus"
	"github.ibm.com/Alessio-Savi/AuthentiGo/datastructures"
	"os"
	"strings"
)

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
