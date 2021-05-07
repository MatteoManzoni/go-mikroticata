package handlers

import (
	log "github.com/sirupsen/logrus"
	"gitlab.com/MatteoManzoni/go-mikroticata/core"
	"os"
	"path/filepath"
	"runtime"
)

const LOG_PATH = "/tmp/mikroticata.log"

func Log(level log.Level, mgs string) {
	_, file, line, _ := runtime.Caller(1)
	logField := log.Fields{
		"agent_version": core.MIKROTICATA_VERSION,
		"executable":   filepath.Base(os.Args[0]),
		"calling_line": line,
		"calling_file": file,
	}
	switch level {
	case log.ErrorLevel:
		log.WithFields(logField).Error(mgs)
		break
	case log.WarnLevel:
		log.WithFields(logField).Warning(mgs)
		break
	case log.InfoLevel:
		log.WithFields(logField).Info(mgs)
		break
	case log.PanicLevel:
		log.WithFields(logField).Panic(mgs)
		break
	}

}