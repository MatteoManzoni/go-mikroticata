package main

import (
	"encoding/json"
	"flag"
	log "github.com/sirupsen/logrus"
	"gitlab.com/MatteoManzoni/go-mikroticata/libs"
)

func main() {

	configPath := flag.String("config", "/etc/mikroticata.yaml", "Path of the mikroticata confg file")
	flag.Parse()

	mikroticataConfig, err := libs.ParseConfig(*configPath)
	if err != nil {
		libs.Log(log.PanicLevel, "Something went wrong loading mikroticata config: " + err.Error())
	}

	b, err := json.Marshal(mikroticataConfig)
	if err != nil {
		libs.Log(log.PanicLevel, "Something went wrong loading mikroticata config: " + err.Error())
	}

	libs.Log(log.InfoLevel, "Loaded mikroticata config: " + string(b))

	err = libs.NewMikroticataLoop(mikroticataConfig)
	if err != nil {
		libs.Log(log.PanicLevel, "Event loop exited with error: " + err.Error())
	}
}