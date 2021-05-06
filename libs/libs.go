package libs

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"net"
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
var privateIPBlocks []*net.IPNet

type MikroticataConfig struct {
	BlacklistDuration  		string    				`yaml:"blacklistDuration"`
	WhitelistSources   		[]net.IP 				`yaml:"whitelistSources"`
	WhitelistDests     		[]net.IP  				`yaml:"whitelistDests"`
	WAN_IP             		net.IP    				`yaml:"WAN_IP"`
	DynamicWAN				bool                    `yaml:"dynamicWAN"`
	EventPeriodMilliSeconds uint      				`yaml:"eventPeriodMilliSeconds"`
	SWIUpdPeriodSeconds     uint      				`yaml:"blacklistUpdatePeriodSeconds"`
	WanRefreshPeriodSeconds uint      				`yaml:"dynamicWANRefresh"`
	RedisPassword      		string    				`yaml:"redisPassword"`
	RedisHost         		string    				`yaml:"redisHost"`
	RedisPort         		int      				`yaml:"redisPort"`
	RedisDB           		int       				`yaml:"redisDB"`
	AlertsRedisKey     		string    				`yaml:"redisAlertKey"`
	TikConfig          		MikrotikConfiguration 	`yaml:"mikrotikConfiguration"`
}

type MikrotikConfiguration struct {
	Name		string `yaml:"name"`
	Host		string `yaml:"host"`
	Username	string `yaml:"user"`
	Password	string `yaml:"password"`
}

type MikroticataLoopControl struct {
	redisTicker   			*time.Ticker
	blacklistCleanerTicker 	*time.Ticker
	dynWanRefreshTicker     *time.Ticker
	config   				MikroticataConfig
	err      				chan error
	rdb      				*redis.Client
	ctx	     				context.Context
}

type SuriAlert struct {
	SourceIP 	net.IP   `json:"src_ip"`
	DestIP   	net.IP   `json:"dest_ip"`
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

	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
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

func cleanBlacklistExpired(config MikroticataConfig) error {

	fmt.Println("CLEANING BLACKLIST")

	return nil
}

func ipIsPrivate(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func isIPBlacklisted(ip net.IP, blacklist []net.IP) bool {
	for _, blacklistedIP  := range blacklist {
		if blacklistedIP.Equal(ip) {
			return true
		}
	}
	return false
}

func blacklistSuriAlerts(alerts []SuriAlert, config MikroticataConfig) error {

	for _, suricataAlert := range alerts {
		if ipIsPrivate(suricataAlert.DestIP) && ipIsPrivate(suricataAlert.SourceIP) {
			continue
		}

		if ipIsPrivate(suricataAlert.SourceIP) &&
			!suricataAlert.DestIP.Equal(config.WAN_IP) &&
			! isIPBlacklisted(suricataAlert.SourceIP, config.WhitelistSources) {
				fmt.Println("I'm going to ban this dest IP: " + suricataAlert.DestIP.String())
		}
		if ipIsPrivate(suricataAlert.DestIP) &&
			! suricataAlert.SourceIP.Equal(config.WAN_IP) &&
			! isIPBlacklisted(suricataAlert.DestIP, config.WhitelistDests) {
			fmt.Println("I'm going to ban this source IP: " + suricataAlert.SourceIP.String())
		}
	}

	return nil
}

func NewMikroticataLoop(config MikroticataConfig) error {
	ml := &MikroticataLoopControl{
		redisTicker:    		time.NewTicker(time.Millisecond * time.Duration(config.EventPeriodMilliSeconds)),
		blacklistCleanerTicker:	time.NewTicker(time.Second * time.Duration(config.SWIUpdPeriodSeconds)),
		dynWanRefreshTicker:	time.NewTicker(time.Second * time.Duration(config.SWIUpdPeriodSeconds)),
		config:     			config,
		ctx:        			context.Background(),
		err:        			make(chan error),
		rdb:        			redis.NewClient(&redis.Options{
			Addr:     				config.RedisHost + ":" + strconv.Itoa(config.RedisPort),
			Password: 				config.RedisPassword,
			DB:       				config.RedisDB,
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
			case <-l.redisTicker.C:
				suriAlerts, err := retriveSuriAlerts(l.ctx, l.rdb, l.config.AlertsRedisKey)
				if err != nil {
					l.err <- err
				}
				err = blacklistSuriAlerts(suriAlerts,l.config)
				if err != nil {
					l.err <- err
				}
		    case <-l.blacklistCleanerTicker.C:
			    err := cleanBlacklistExpired(l.config)
				if err != nil {
					l.err <- err
				}
		}
	}
}