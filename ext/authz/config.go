package authz

import (
	"fmt"
	"github.com/luraproject/lura/v2/config"
	"github.com/nocturna-ta/api-gateway/ext/service"
	"net/url"
)

const (
	namespace = "nocturna/auth"
)

type extraConfig struct {
	AuthService       service.Auth
	ServiceAddress    string
	TargetService     string
	LogRequestOnError bool
}

func configGetter(cfg config.ExtraConfig) *extraConfig {
	v, ok := cfg[namespace]
	if !ok {
		return nil
	}
	tmp, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}

	var conf extraConfig

	if sa, ok := tmp["security_address"].(string); ok {
		conf.ServiceAddress = sa
	} else {
		return nil
	}

	if tsn, ok := tmp["target_service_name"].(string); ok {
		conf.TargetService = tsn
	}

	if val, ok := tmp["log_request_on_error"].(bool); ok {
		conf.LogRequestOnError = val
	}

	_, err := url.Parse(conf.ServiceAddress)
	if err != nil {
		fmt.Println("Error parsing service url ", err)
		return nil
	}

	conf.AuthService = service.NewAuthSvc(conf.ServiceAddress)

	return &conf
}
