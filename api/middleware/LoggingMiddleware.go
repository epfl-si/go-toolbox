package middlewares

import (
	"time"

	"github.com/epfl-si/go-toolbox/log"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func LoggingMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set("uuid", uuid.New())
		// set start time to "now" in ms
		ctx.Set("start", time.Now().UnixMilli())

		ctx.Next()

		// set end time to "now" in ms
		end := time.Now().UnixMilli()
		start := ctx.GetInt64("start")
		ctx.Set("processing_time", end-start)

		log.LogApiInfo(logger, ctx, "")

		ctx.Next()
	}
}
