package core

import (
	"context"
	"github.com/go-redis/redis/v8"
	"net"
	"time"
)

type ToType int32
const (
	SOURCE   	ToType = 0
	DESTINATION ToType = 1
)

type MikroticataConfig struct {
	BlacklistDuration  		string    				`yaml:"blacklistDuration"`
	WhitelistSources   		[]net.IP 				`yaml:"whitelistSources"`
	WhitelistDests     		[]net.IP  				`yaml:"whitelistDests"`
	WAN_IP             		net.IP    				`yaml:"WAN_IP"`
	DynamicWAN				bool                    `yaml:"dynamicWAN"`
	EventPeriodMilliSeconds uint      				`yaml:"eventPeriodMilliSeconds"`
	SWIUpdPeriodSeconds     uint      				`yaml:"blacklistUpdatePeriodSeconds"`
	WanRefreshPeriodSeconds uint      				`yaml:"dynamicWANRefreshSeconds"`
	RedisPassword      		string    				`yaml:"redisPassword"`
	RedisHost         		string    				`yaml:"redisHost"`
	RedisPort         		int      				`yaml:"redisPort"`
	RedisDB           		int       				`yaml:"redisDB"`
	AlertsRedisKey     		string    				`yaml:"redisAlertKey"`
	TikConfigs         		[]MikrotikConfiguration `yaml:"mikrotikConfigurations"`
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
