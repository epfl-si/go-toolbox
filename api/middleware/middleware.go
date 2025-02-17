package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/epfl-si/go-toolbox/api"
	"github.com/epfl-si/go-toolbox/log"
	"github.com/epfl-si/go-toolbox/messages"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func ContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		lang := c.Request.Header.Get("Content-Language")
		if lang == "" {
			lang = "fr"
		}
		c.Set("lang", lang)
		uuid := c.GetHeader("X-Krakend-UUID")
		seeAs := c.GetHeader("X-Krakend-SeeAs")
		userType := c.GetHeader("X-Krakend-UserType")
		userId := c.GetHeader("X-Krakend-UserId")
		scopes := strings.Split(c.GetHeader("X-Krakend-Scopes"), ",")

		// if internal/same namespace call, then pass default system values
		if userId == "" {
			userType = "service"
			userId = "system"
		}

		c.Set("uuid", uuid)
		c.Set("userId", userId)
		c.Set("userType", userType)
		c.Set("scopes", scopes)

		// no authentication on OPTIONS
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// no control for some endpoints
		if strings.Contains(c.FullPath(), "/docs/") || strings.Contains(c.FullPath(), "/healthcheck") || strings.Contains(c.FullPath(), "/liveness") {
			c.Set("userId", "probe")
			c.Set("userType", "service") // probe as service to avoid access control rejection
			c.Next()
			return
		}

		c.Set("isRoot", false)

		// if Entra JWT, then extract claims: uniqueid and groups
		authorizationHeader := c.Request.Header.Get("Authorization")
		rBearerJwt, _ := regexp.Compile(`^Bearer (?:[\w-]*\.){2}[\w-]*$`)
		if rBearerJwt.MatchString(authorizationHeader) {
			authorizationHeader = strings.ReplaceAll(authorizationHeader, "Bearer ", "")

			// get middle part and decode base64
			splits := strings.Split(authorizationHeader, ".")
			if len(splits) != 3 {
				c.JSON(http.StatusBadRequest, gin.H{"error": messages.GetMessage(lang, "InvalidTokenFormat")})
				c.Abort()
				return
			}
			// unmarshal jwtData to json
			var data map[string]interface{}
			// decode splits[1] from base64 to json
			dataPart := splits[1]
			// pad data part if needed
			if len(dataPart)%4 != 0 {
				dataPart += strings.Repeat("=", 4-len(dataPart)%4)
			}
			// decode base64 part 2 and convert to JSON
			jsonData, err := base64.StdEncoding.DecodeString(dataPart)
			if err != nil {
				c.JSON(http.StatusBadRequest, api.MakeError(c, "", http.StatusBadRequest, messages.GetMessage(lang, "UnableToDecodeBase64"), err.Error(), "", nil))
				c.Abort()
				return
			}

			err = json.Unmarshal([]byte(jsonData), &data)
			if err != nil {
				c.JSON(http.StatusBadRequest, api.MakeError(c, "", http.StatusBadRequest, messages.GetMessage(lang, "UnableToParseToken"), err.Error(), "", nil))
				c.Abort()
				return
			}

			// if there's an employee ID claim, it means we're dealing with a person/sciper
			if data["uniqueid"] != nil {
				uniqueid := data["uniqueid"].(string)
				if uniqueid != "" {
					c.Set("userType", "person")
				}
			}

			// set root
			isRoot := false
			if data["groups"] != nil {
				groups := data["groups"].([]interface{})
				for _, group := range groups {
					if group == os.Getenv("ROOT_GROUP") {
						isRoot = true
						break
					}
				}
			}
			c.Set("isRoot", isRoot)

			// set seeAs only if root
			if isRoot {
				seeAsPattern := regexp.MustCompile(`^\d{6}$`)
				if seeAs != "" && seeAsPattern.MatchString(seeAs) {
					c.Set("seeAs", seeAs)
					c.Set("userId", seeAs)
					c.Set("userIdOverrided", userId)
				}
			}

			c.Next()
			return
		}
	}
}

func CorsMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "*")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "*")

		ctx.Next()
	}
}

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
