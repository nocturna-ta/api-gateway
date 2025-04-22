package common

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	krakendgin "github.com/luraproject/lura/v2/router/gin"
	libCtx "github.com/nocturna-ta/golib/context"
)

func HandlerFactory(l logging.Logger, hf krakendgin.HandlerFactory) krakendgin.HandlerFactory {
	return func(config *config.EndpointConfig, proxy proxy.Proxy) gin.HandlerFunc {
		return func(ctx *gin.Context) {
			// remove reserved header
			ctx.Request.Header.Del(libCtx.XAddressId)
			ctx.Request.Header.Del(libCtx.XUserId)
			ctx.Request.Header.Del(libCtx.XRole)

			// set request-id header
			ctx.Request.Header.Set(libCtx.XRequestId, uuid.NewString())

			hf(config, proxy)(ctx)
		}
	}
}
