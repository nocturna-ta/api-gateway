package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	krakendgin "github.com/luraproject/lura/v2/router/gin"
	"github.com/nocturna-ta/api-gateway/ext/service"
	libCtx "github.com/nocturna-ta/golib/context"
	"io"
	"net/http"
	"strings"
)

func HandlerFactory(l logging.Logger, hf krakendgin.HandlerFactory) krakendgin.HandlerFactory {
	return func(config *config.EndpointConfig, proxy proxy.Proxy) gin.HandlerFunc {
		handlerFunc := hf(config, proxy)

		conf := configGetter(config.ExtraConfig)

		if conf == nil {
			return func(ctx *gin.Context) {
				handlerFunc(ctx)
			}
		}

		return func(ctx *gin.Context) {
			res, err := conf.validate(ctx)
			if err != nil {
				l.Error("[Authorization] Error validating authz", err)
				if conf.LogRequestOnError {
					raw, _ := io.ReadAll(ctx.Request.Body)
					msg := "[Authorization] URL --> " + ctx.Request.URL.String()
					h, _ := json.Marshal(ctx.Request.Header)
					msg += " ; Headers --> " + string(h)
					msg += " ; Body --> " + strings.ReplaceAll(string(raw), "\n", " ")
					l.Error(msg)

					ctx.Request.Body = io.NopCloser(bytes.NewReader(raw))
				}
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{"error": err.Error()})
				return
			}

			if !res {
				l.Error("[Authorization] Invalid authorization")
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{"error": "Invalid authorization"})
				return
			}

			handlerFunc(ctx)
		}
	}
}

func (ec *extraConfig) validate(c *gin.Context) (bool, error) {
	targetService := ec.TargetService
	if targetService == "" {
		targetService = c.Request.URL.Path
	}

	requestID := libCtx.ReadRequestId(c)

	// remove external header auth
	c.Request.Header.Del(libCtx.XUserId)
	c.Request.Header.Del(libCtx.XAddressId)
	c.Request.Header.Del(libCtx.XRole)

	ctx := context.WithValue(c, libCtx.RequestContextKey, libCtx.RequestContext{
		RequestId: requestID,
	})

	res, err := ec.AuthService.Validate(ctx, &service.AuthValidateRequest{
		Header:        mapHeader(c.Request.Header),
		Path:          c.Request.URL.Path,
		TargetService: ec.TargetService,
	})
	if err != nil || res == nil || !res.IsValid {
		return false, err
	}

	// injecting headers from security/auth
	for key, val := range res.InjectHeaders {
		c.Request.Header.Set(key, val)
	}

	return true, nil
}

func mapHeader(header http.Header) map[string]string {
	headers := map[string]string{}

	for key, val := range header {
		headers[strings.ToLower(key)] = strings.Join(val, ",")
	}

	return headers
}
