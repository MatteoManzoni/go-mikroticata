package handlers

import (
	"crypto/tls"
	"fmt"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"gitlab.com/MatteoManzoni/go-mikroticata/core"
	"net"
	"strconv"
	"strings"
	"time"
)

func setupMikrotikRESTClient(config core.MikrotikConfiguration) *resty.Client {
	client := resty.New()

	client.SetHeader("Accept", "application/json")
	client.SetHeaders(map[string]string{
		"Content-Type": "application/json",
		"User-Agent": "go-mikroticata " + core.MIKROTICATA_VERSION,
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

func CleanExpiredBlockRules(switches []core.MikrotikConfiguration, blacklistDurationString string) error {

	fmt.Println("Get all switch rules")
	fmt.Println("Check rules comments")
	fmt.Println("Extract last update timestamp from rules")

	var blacklistDuration time.Duration
	blacklistDuration, err := time.ParseDuration(blacklistDurationString)
	if err != nil {
		Log(log.ErrorLevel, "Invalid duration string: " + err.Error())
		Log(log.WarnLevel, "Defaulting to 1h blacklist duration")
		blacklistDuration = 1 * time.Hour
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
			restClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		} else {
			restClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: false})
		}

		var switchRules []core.MikrotikSwitchRuleConfig
		resp, err := restClient.R().
			SetResult(&switchRules).
			SetQueryParams(map[string]string{
				"mirror": "no",
			}).
			Get(swiHost + "interface/ethernet/switch/rule")
		if err != nil {
			Log(log.ErrorLevel, "Cannot retrieve non-mirror rules from " + mikrotik.Name + " target, returned an error: " + err.Error())
			continue
		} else if resp.StatusCode() < 200 || resp.StatusCode() >=300 {
			Log(log.ErrorLevel, "Target: " + mikrotik.Name + " returned an invalid code on non-mirror rules retrieval: " + resp.String())
			continue
		}

		for _, rule := range switchRules {
			if strings.HasPrefix(rule.Comment, "MANAGED_BY_MIKROTICATA_") {
				creationUnixTSstring := strings.TrimPrefix(rule.Comment, "MANAGED_BY_MIKROTICATA_")
				creationUnixTS, err := strconv.ParseInt(creationUnixTSstring, 10, 64)
				if err != nil {
					Log(log.ErrorLevel, "Invalid string TS to I64 TS: " + err.Error())
					continue
				}
				creationTime := time.Unix(creationUnixTS, 0)
				deletionTime := creationTime.Add(blacklistDuration)

				if deletionTime.Before(time.Now()) {
					Log(log.InfoLevel, "[" + mikrotik.Name + "] I'm going to remove the rule ID: " + rule.ID + " with comment: " + rule.Comment)

					resp, err := restClient.R().
						SetResult(&switchRules).
						Delete(swiHost + "interface/ethernet/switch/rule/" + rule.ID)
					if err != nil {
						Log(log.ErrorLevel, "Cannot delete expired rule: " + rule.ID + " from " + mikrotik.Name + " target, returned an error: " + err.Error())
					} else if resp.StatusCode() < 200 || resp.StatusCode() >=300 {
						Log(log.ErrorLevel, "Target: " + mikrotik.Name + " returned an invalid code on non-mirror rules retrieval: " + resp.String())
					}

					Log(log.InfoLevel, "[" + mikrotik.Name + "] Removed expired rule: " + rule.ID + " with comment: " + rule.Comment)
				}
			}
		}
	}

	return nil
}

func CreateBlockRuleMikrotik(ip net.IP, to core.ToType, switches []core.MikrotikConfiguration) error {

	var toDirection string
	var toDirectionQuery string
	if to == core.SOURCE {
		toDirection = "source"
		toDirectionQuery = "src-address"
	} else if to == core.DESTINATION {
		toDirection = "destination"
		toDirectionQuery = "dst-address"
	}

	Log(log.InfoLevel, "I'm going to blacklist " + toDirection + " IP: "+ip.String())

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

		var mirroredPorts []core.MikrotikSwitchRuleConfig
		resp, err := restClient.R().
			SetResult(&mirroredPorts).
			SetQueryParams(map[string]string{
				"comment": mikrotik.MirrorRuleComment,
				"mirror": "yes",
			}).
			Get(swiHost + "interface/ethernet/switch/rule")
		if err != nil {
			Log(log.ErrorLevel, "Cannot retrive mirror rule from " + mikrotik.Name + " target, returned an error: " + err.Error())
			continue
		} else if resp.StatusCode() < 200 || resp.StatusCode() >=300 {
			Log(log.ErrorLevel, "Target: " + mikrotik.Name + " returned an invalid code on mirror switch rules retrieval: " + resp.String())
			continue
		}

		if len(mirroredPorts) != 1 {
			Log(log.ErrorLevel, "Cannot find exactly one mirror rule in " + mikrotik.Name + " target")
			continue
		}

		var ruleExist []core.MikrotikSwitchRuleConfig
		resp, err = restClient.R().
			SetResult(&ruleExist).
			SetQueryParams(map[string]string{
				toDirectionQuery: ip.String(),
				"switch": mirroredPorts[0].TargetChip,
				"ports": mirroredPorts[0].TargetPorts,
			}).
			Get(swiHost + "interface/ethernet/switch/rule")
		if err != nil {
			Log(log.ErrorLevel, "Cannot check for rule existence " + mikrotik.Name + " target, returned an error: " + err.Error())
			continue
		} else if resp.StatusCode() < 200 || resp.StatusCode() >=300 {
			Log(log.ErrorLevel, "Target: " + mikrotik.Name + " returned an invalid code on check for switch rules existence: " + resp.String())
			continue
		}

		if len(ruleExist) == 1 {
			if strings.HasPrefix(ruleExist[0].Comment, "MANAGED_BY_MIKROTICATA_") {
				resp, err = restClient.R().
					SetBody(map[string]interface{}{
						"comment": "MANAGED_BY_MIKROTICATA_" + strconv.FormatInt(time.Now().UTC().Unix(), 10),
					}).
					Patch(swiHost + "interface/ethernet/switch/rule/" + ruleExist[0].ID)
				if err != nil {
					Log(log.ErrorLevel, "Cannot update mirror rule to " + mikrotik.Name + " target, returned an error: " + err.Error())
					continue
				} else if resp.StatusCode() < 200 || resp.StatusCode() >=300 {
					Log(log.ErrorLevel, "Target: " + mikrotik.Name + " returned an invalid code on mirror switch rules update: " + resp.String())
					continue
				}
			} else {
				Log(log.WarnLevel, "The matching rules seems to be not MIKROTICATA managed, I'll do nothing on: " + mikrotik.Name)
			}
		} else if len(ruleExist) == 0 {
			blockRule := make(map[string]string)
			blockRule["switch"] 			= mirroredPorts[0].TargetChip
			blockRule["ports"] 				= mirroredPorts[0].TargetPorts
			blockRule["copy-to-cpu"] 		= "no"
			blockRule["redirect-to-cpu"] 	= "no"
			blockRule["mirror"] 			= "no"
			blockRule["new-dst-ports"] 		= ""
			blockRule["comment"] 			= "MANAGED_BY_MIKROTICATA_" + strconv.FormatInt(time.Now().UTC().Unix(), 10)
			blockRule[toDirectionQuery]		=  ip.String()

			resp, err = restClient.R().
				SetBody(blockRule).
				Put(swiHost + "interface/ethernet/switch/rule/")
			if err != nil {
				Log(log.ErrorLevel, "Cannot create block mirror rule to " + mikrotik.Name + " target, returned an error: " + err.Error())
				continue
			} else if resp.StatusCode() < 200 || resp.StatusCode() >=300 {
				Log(log.ErrorLevel, "Target: " + mikrotik.Name + " returned an invalid code on mirror switch rules creation: " + resp.String())
				continue
			}
		} else {
			Log(log.WarnLevel, "More or negative rules exist on the switch with the same configuration, I'll do nothing ")
			continue
		}
		Log(log.InfoLevel, "[" + mikrotik.Name + "] Blacklisted " + toDirection + " IP: "+ip.String())
	}

	Log(log.InfoLevel, "Blacklisted " + toDirection + " IP: "+ip.String() + " on all switch targets")

	return nil
}
