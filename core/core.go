package core

import (
	"encoding/json"
	"errors"
	"github.com/go-redis/redis/v8"
	log "github.com/sirupsen/logrus"
	"gitlab.com/MatteoManzoni/go-mikroticata/handlers"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"strconv"
	"time"
)

const MIKROTICATA_VERSION = "{MIKROTICATA_VERSION}"

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
			handlers.Log(log.ErrorLevel, "Error unmashaling Suricata event into struct: " + err.Error())
			continue
		}

		suricataAlerts = append(suricataAlerts, suricataAlert)
	}

	return suricataAlerts, nil
}

func blacklistSuriAlerts(alerts []SuriAlert, config MikroticataConfig) error {

	for _, suricataAlert := range alerts {
		if handlers.IPisPrivate(suricataAlert.DestIP) && handlers.IPisPrivate(suricataAlert.SourceIP) {
			continue
		}

		if handlers.IPisPrivate(suricataAlert.SourceIP) &&
			!suricataAlert.DestIP.Equal(config.WAN_IP) &&
			! handlers.IsIpBlacklisted(suricataAlert.SourceIP, config.WhitelistSources) {
				err := handlers.CreateBlockRuleMikrotik(suricataAlert.DestIP, SOURCE, config.TikConfigs)
				if err != nil {
					handlers.Log(log.ErrorLevel, "Something went wrong trying to blacklist an IP: "+err.Error())
				}
		}
		if handlers.IPisPrivate(suricataAlert.DestIP) &&
			! suricataAlert.SourceIP.Equal(config.WAN_IP) &&
			! handlers.IsIpBlacklisted(suricataAlert.DestIP, config.WhitelistDests) {
				err := handlers.CreateBlockRuleMikrotik(suricataAlert.SourceIP, DESTINATION, config.TikConfigs)
				if err != nil {
					handlers.Log(log.ErrorLevel, "Something went wrong trying to blacklist an IP: "+err.Error())
				}
		}
	}

	return nil
}

func NewMikroticataLoop(config MikroticataConfig) error {
	ml := &MikroticataLoopControl{
		redisTicker:    		time.NewTicker(time.Millisecond * time.Duration(config.EventPeriodMilliSeconds)),
		blacklistCleanerTicker:	time.NewTicker(time.Second * time.Duration(config.SWIUpdPeriodSeconds)),
		dynWanRefreshTicker:	time.NewTicker(time.Second * time.Duration(config.WanRefreshPeriodSeconds)),
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
			handlers.Log(log.PanicLevel, "Error closing the connection to redis: " + err.Error())
		}
	}()

	go ml.run()

	return <-ml.err
}

func (l MikroticataLoopControl) run()  {

	var err error
	if l.config.DynamicWAN {
		l.config.WAN_IP, err = handlers.RetriveWanIP()
		if err != nil {
			l.err <- err
		}
	}

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
		    err := handlers.CleanExpiredBlockRules(l.config.TikConfigs, l.config.BlacklistDuration)
			if err != nil {
				l.err <- err
			}
		case <-l.dynWanRefreshTicker.C:
			if l.config.DynamicWAN {
				l.config.WAN_IP, err = handlers.RetriveWanIP()
				if err != nil {
					handlers.Log(log.ErrorLevel, "An error occurred during the retrieval of the updated WAN IP: " + err.Error() + ", I'm gonna keep last value")
				}
			}
		case <-l.ctx.Done():
			l.err <- errors.New("context done")
		}
	}
}