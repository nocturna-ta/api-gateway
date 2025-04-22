package authz

import (
	"github.com/luraproject/lura/v2/config"
	"github.com/nocturna-ta/api-gateway/ext/service"
)

const (
	namespace = "nocturna/auth"
)

type extraConfig struct {
	AuthService       service.Auth
	ServiceAddress    string
	TargetService     string
	LogRequestOnError bool
	RequiredRoles     string
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

	if roles, ok := tmp["required_roles"].(string); ok {
		conf.RequiredRoles = roles
	}
	conf.AuthService = service.NewAuthSvc(conf.ServiceAddress)

	return &conf
}
