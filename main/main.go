package main

import (
	"encoding/json"
	"flag"
	log "github.com/sirupsen/logrus"
	"gitlab.com/MatteoManzoni/go-mikroticata/core"
	"gitlab.com/MatteoManzoni/go-mikroticata/handlers"
	"os"
	"os/signal"
	"runtime"
)

func main() {

	configPath := flag.String("config", "/etc/mikroticata.yaml", "(Optional, default to /etc/mikroticata.yaml) Path of the mikroticata confg file")
	logPath := flag.String("logFile", "", "(Optional, default to stdout only) Path of the file to log to")
	flag.Parse()

	err := handlers.SetupLogging(*logPath, *logPath == "")

	mikroticataConfig, err := core.ParseConfig(*configPath)
	if err != nil {
		handlers.Log(log.PanicLevel, "Something went wrong loading mikroticata config: " + err.Error())
	}

	b, err := json.Marshal(mikroticataConfig)
	if err != nil {
		handlers.Log(log.PanicLevel, "Something went wrong loading mikroticata config: " + err.Error())
	}

	handlers.Log(log.InfoLevel, "Loaded mikroticata config: " + string(b))

	runtime.GOMAXPROCS(runtime.NumCPU() + 1)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func(){
		<-c
		handlers.Log(log.InfoLevel, "Bye Bye")
		os.Exit(0)
	}()

	err = core.NewMikroticataLoop(mikroticataConfig)
	if err != nil {
		handlers.Log(log.PanicLevel, "Event loop exited with error: " + err.Error())
	}
}