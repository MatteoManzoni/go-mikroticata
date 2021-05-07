package handlers

import (
	log "github.com/sirupsen/logrus"
	"gitlab.com/MatteoManzoni/go-mikroticata/core"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func SetupLogging(logPath string, fileLogging bool) error {

	customFormatter := new(log.JSONFormatter)
	customFormatter.TimestampFormat = time.RFC1123
	log.SetFormatter(customFormatter)

	if fileLogging {
		err := os.MkdirAll(logPath, os.ModePerm)
		if err != nil {
			return err
		}

		output := &lumberjack.Logger{
			Filename:   logPath + filepath.Base(os.Args[0]) + ".log",
			MaxSize:    2,
			MaxBackups: 1,
			MaxAge:     5,
			Compress:   true,
		}

		ioMW := io.MultiWriter(output, os.Stdout)

		log.SetOutput(ioMW)
	} else {
		log.SetOutput(os.Stdout)
	}

	log.SetLevel(log.InfoLevel)

	return nil
}

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