package libs

import (
	"crypto/tls"
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
	"strings"
	"time"
	"github.com/go-redis/redis/v8"
	"golang.org/x/net/context"
    "github.com/go-resty/resty/v2"
)

const LOG_PATH = "/tmp/mikroticata.log"
const MIKROTICATA_LIBS_VERSION = "{MIKROTICATA_VERSION}"
var privateIPBlocks []*net.IPNet

type toType int32
const (
	SOURCE   	toType = 0
	DESTINATION toType = 1
)

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
	TikConfig          		[]MikrotikConfiguration `yaml:"mikrotikConfigurations"`
}

type MikrotikConfiguration struct {
	Name		 	 	string `yaml:"name"`
	Host		  		string `yaml:"host"`
	Username	  		string `yaml:"user"`
	Password	  		string `yaml:"password"`
	EnableTLS     		bool   `yaml:"enableTLS"`
	SkipTLSVerify 		bool   `yaml:"TLSskipVerify"`
	MirrorRuleComment 	string `yaml:"swiMirrorRuleComment"`
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

type MikrotikSwitchRuleConfig struct {
	ID 				string `json:".id"`
	TargetChip		string `json:"switch"`
	TargetPorts		string `json:"ports"`
	Comment    		string `json:"comment"`
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

	fmt.Println("Get all switch rules")
	fmt.Println("Check rules comments")
	fmt.Println("Extract last update timestamp from rules")

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
				err := blacklistMikrotik(suricataAlert.DestIP, SOURCE, config.TikConfig, config.BlacklistDuration)
				if err != nil {
					Log(log.ErrorLevel, "Something went wrong trying to blacklist an IP: "+err.Error())
				}
		}
		if ipIsPrivate(suricataAlert.DestIP) &&
			! suricataAlert.SourceIP.Equal(config.WAN_IP) &&
			! isIPBlacklisted(suricataAlert.DestIP, config.WhitelistDests) {
				err := blacklistMikrotik(suricataAlert.SourceIP, DESTINATION, config.TikConfig, config.BlacklistDuration)
				if err != nil {
					Log(log.ErrorLevel, "Something went wrong trying to blacklist an IP: "+err.Error())
				}
		}
	}

	return nil
}

func setupMikrotikRESTClient(config MikrotikConfiguration) *resty.Client {
	client := resty.New()

	client.SetHeader("Accept", "application/json")
	client.SetHeaders(map[string]string{
		"Content-Type": "application/json",
		"User-Agent": "go-mikroticata " + MIKROTICATA_LIBS_VERSION,
	})
	client.SetBasicAuth(config.Username, config.Password)
	client.SetRetryCount(5).
		SetRetryWaitTime(1 * time.Second).
		SetRetryMaxWaitTime(6 * time.Second)
	client.AddRetryCondition(
		func(r *resty.Response, err error) bool {
			return 200 < r.StatusCode() || r.StatusCode() >=300
		},
	)

	return client
}

func blacklistMikrotik(ip net.IP, to toType, switches []MikrotikConfiguration, blacklistDuration string) error {

	var toDirection string
	var toDirectionQuery string
	if to == SOURCE {
		toDirection = "source"
		toDirectionQuery = "src-address"
	} else if to == DESTINATION {
		toDirection = "destination"
		toDirectionQuery = "dst-address"
	}

	for _, mikrotik := range switches {
		var swiHost string
		if mikrotik.EnableTLS {
			swiHost = "https://" + mikrotik.Host
		} else {
			swiHost = "http://" + mikrotik.Host
		}
		swiHost = swiHost + "/rest/"

		restClient := setupMikrotikRESTClient(mikrotik)
		if mikrotik.SkipTLSVerify {
			restClient.SetTLSClientConfig(&tls.Config{ InsecureSkipVerify: true })
		} else {
			restClient.SetTLSClientConfig(&tls.Config{ InsecureSkipVerify: false })
		}

		var mirroredPorts []MikrotikSwitchRuleConfig
		_, err := restClient.R().
			SetResult(&mirroredPorts).
			SetQueryParams(map[string]string{
				"comment": mikrotik.MirrorRuleComment,
				"mirror": "yes",
			}).
			Get(swiHost + "interface/ethernet/switch/rule")
		if err != nil {
			Log(log.ErrorLevel, "Cannot retrive mirror rule from " + mikrotik.Name + " target: " + err.Error())
			continue
		}

		if len(mirroredPorts) != 1 {
			Log(log.ErrorLevel, "Cannot find exactly one mirror rule in " + mikrotik.Name + " target")
			continue
		}

		var ruleExist []MikrotikSwitchRuleConfig
		_, err = restClient.R().
			SetResult(&ruleExist).
			SetQueryParams(map[string]string{
				toDirectionQuery: ip.String(),
				"switch": mirroredPorts[0].TargetChip,
				"ports": mirroredPorts[0].TargetPorts,
			}).
			Get(swiHost + "interface/ethernet/switch/rule")
		if err != nil {
			Log(log.ErrorLevel, "Cannot check for rule existance from " + mikrotik.Name + " target: " + err.Error())
			continue
		}

		if len(ruleExist) == 1 {
			if strings.HasPrefix(ruleExist[0].Comment, "MIKROTICATA_") {
				_, err = restClient.R().
					SetBody(map[string]interface{}{
						"comment": "MIKROTICATA_" + strconv.FormatInt(time.Now().UTC().Unix(), 10),
					}).
					Patch(swiHost + "interface/ethernet/switch/rule/" + ruleExist[0].ID)
				if err != nil {
					Log(log.ErrorLevel, "Cannot patch blacklist update time " + mikrotik.Name + " target: " + err.Error())
					continue
				}
			} else {
				Log(log.WarnLevel, "The matching rules seems to be not MIKROTICATA managed, I'll do nothing ")
			}
		} else if len(ruleExist) == 0 {
			blockRule := make(map[string]string)
			blockRule["switch"] 			= mirroredPorts[0].TargetChip
			blockRule["ports"] 				= mirroredPorts[0].TargetPorts
			blockRule["copy-to-cpu"] 		= "no"
			blockRule["redirect-to-cpu"] 	= "no"
			blockRule["mirror"] 			= "no"
			blockRule["new-dst-ports"] 		= ""
			blockRule["comment"] 			= "MIKROTICATA_" + strconv.FormatInt(time.Now().UTC().Unix(), 10)
			blockRule[toDirectionQuery]		=  ip.String()

			_, err = restClient.R().
				SetBody(blockRule).
				Post(swiHost + "interface/ethernet/switch/rule/")
			if err != nil {
				Log(log.ErrorLevel, "Cannot create new blacklist rule on " + mikrotik.Name + " target: " + err.Error())
				continue
			}
		} else {
			Log(log.WarnLevel, "More or negative rules exist on the switch with the same configuration, I'll do nothing ")
			continue
		}
	}

	Log(log.InfoLevel, "Blacklisted " + toDirection + " IP: "+ip.String())

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