package libs

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"gopkg.in/yaml.v2"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
	"github.com/go-redis/redis/v8"
	"golang.org/x/net/context"
)

const LOG_PATH = "/tmp/mikroticata.log"
const MIKROTICATA_LIBS_VERSION = "{MIKROTICATA_VERSION}"

type MikroticataConfig struct {
	BlacklistDuration  		string    `yaml:"blacklistDuration"`
	WhitelistSources   		[]string  `yaml:"whitelistSources"`
	WhitelistDests     		[]string  `yaml:"whitelistDests"`
	WAN_IP             		string    `yaml:"WAN_IP"`
	EventPeriodMilliSeconds uint      `yaml:"eventPeriodMilliSeconds"`
	RedisPassword      		string    `yaml:"redisPassword"`
	RedisHost         		string    `yaml:"redisHost"`
	RedisPort         		int       `yaml:"redisPort"`
	RedisDB           		int       `yaml:"redisDB"`
	AlertsRedisKey     		string    `yaml:"redisAlertKey"`
}

type MikroticataLoopControl struct {
	ticker   *time.Ticker
	config   MikroticataConfig
	err      chan error
	rdb      *redis.Client
	ctx	     context.Context
}

type SuriAlert struct {
	SourceIP string   `json:"src_ip"`
	DestIP   string   `json:"dest_ip"`
}

func init() {
	err := os.MkdirAll(LOG_PATH, os.ModePerm)
	if err != nil {
		panic(err)
	}

	customFormatter := new(log.JSONFormatter)
	customFormatter.TimestampFormat = time.RFC1123
	log.SetFormatter(customFormatter)

	output := &lumberjack.Logger{
		Filename:   LOG_PATH + filepath.Base(os.Args[0]) + ".log",
		MaxSize:    2,
		MaxBackups: 1,
		MaxAge:     5,
		Compress:   true,
	}

	ioMW := io.MultiWriter(output, os.Stdout)

	log.SetOutput(ioMW)

	log.SetLevel(log.InfoLevel)
}

func Log(level log.Level, mgs string) {
	_, file, line, _ := runtime.Caller(1)
	logField := log.Fields{
		"agent_version": MIKROTICATA_LIBS_VERSION,
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

func ParseConfig(path string) (MikroticataConfig, error) {
	mikroticataConfig := MikroticataConfig{}
	timonExtractorConfHandler, err := os.Open(path)
	if err != nil {
		return mikroticataConfig, err
	}

	timonextractorConfbytes, err := ioutil.ReadAll(timonExtractorConfHandler)
	if err != nil {
		return mikroticataConfig, err
	}
	err = yaml.Unmarshal(timonextractorConfbytes, &mikroticataConfig)
	if err != nil {
		return mikroticataConfig, err
	}

	return mikroticataConfig, nil
}

func retriveSuriAlerts(ctx context.Context, client *redis.Client, key string) ([]SuriAlert,error) {
	value := client.Ping(ctx)
	if value.Err() != nil {
		return []SuriAlert{}, value.Err()
	}

	values := client.LRange(ctx, key, 0, -1)
	if values.Err() != nil {
		return []SuriAlert{}, values.Err()
	}

	client.Del(ctx, key)

	var suricataAlerts []SuriAlert
	for _, jsonAlert := range values.Val() {
		var suricataAlert SuriAlert

		err := json.Unmarshal([]byte(jsonAlert), &suricataAlert)
		if err != nil {
			Log(log.ErrorLevel, "Error unmashaling Suricata event into struct: " + err.Error())
			continue
		}

		suricataAlerts = append(suricataAlerts, suricataAlert)
	}

	return suricataAlerts, nil
}

func NewMikroticataLoop(config MikroticataConfig) error {
	ml := &MikroticataLoopControl{
		ticker:     time.NewTicker(time.Millisecond * time.Duration(config.EventPeriodMilliSeconds)),
		config:     config,
		ctx:        context.Background(),
		err:        make(chan error),
		rdb:        redis.NewClient(&redis.Options{
			Addr:     config.RedisHost + ":" + strconv.Itoa(config.RedisPort),
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		}),
	}
	defer func() {
		err := ml.rdb.Close()
		if err != nil {
			Log(log.PanicLevel, "Error closing the connection to redis: " + err.Error())
		}
	}()

	go ml.run()

	return <-ml.err
}

func (l MikroticataLoopControl) run()  {
	for {
		select {
			case <-l.ticker.C:
				suriAlerts, err := retriveSuriAlerts(l.ctx, l.rdb, l.config.AlertsRedisKey)
				if err != nil {
					l.err <- err
				}
				fmt.Println(suriAlerts)
		}
	}
}