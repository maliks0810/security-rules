package middleware

import (
	"strings"
	"time"

	"github.com/gofiber/contrib/otelfiber"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"securityrules/security-rules/configs"
)

func FiberMiddleware(application *fiber.App) {
	// otelfiber and compress drain streaming response bodies (they read
	// ctx.Response().Body() to record size / compress), which deadlocks SSE.
	// Skip both for the events path.
	otel := otelfiber.Middleware()
	compressMW := compress.New(compressionConfig())
	skipForEvents := func(next fiber.Handler) fiber.Handler {
		return func(c *fiber.Ctx) error {
			if strings.HasSuffix(c.Path(), "/v1/api/events") {
				return c.Next()
			}
			return next(c)
		}
	}

	application.Use(
		skipForEvents(otel),
		skipForEvents(compressMW),
		cors.New(corsConfig()),
		limiter.New(limiterConfig()),
		logger.New(loggerConfig()),
		recover.New(recoverConfig()),
	)
}

func compressionConfig() compress.Config {
	return compress.Config{
		Level: compress.LevelBestSpeed,
		Next: func(ctx *fiber.Ctx) bool {
			return strings.HasSuffix(ctx.Path(), "/v1/api/events")
		},
	}
}

func corsConfig() cors.Config {
	return cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "OPTIONS,GET,POST,HEAD,PUT,DELETE,PATCH",
	}
}

func limiterConfig() limiter.Config {
	return limiter.Config{
		Max: 				120,
		Expiration: 		1 * time.Minute,
		LimiterMiddleware: 	limiter.FixedWindow{},
		LimitReached: func(ctx *fiber.Ctx) error {
			ctx.Context().Logger().Printf("Rate Limit has been reached!")
			return ctx.SendStatus(fiber.StatusTooManyRequests)
		},
	}
}

func loggerConfig() logger.Config {
	return logger.Config{
		Format:     "[${time}] ${status} - ${latency} ${method} ${path}\n",
		TimeFormat: "15:04:05", // https://programming.guide/go/format-parse-string-time-date-example.html
		TimeZone:   "Local",
		// LOG_HTTP_SUCCESS (env) toggles Fiber's per-request access log
		// entirely. Default false — ALL access-log lines (2xx, 3xx,
		// 4xx, 5xx) are skipped so the console shows only the zap-level
		// app messages. Flip LOG_HTTP_SUCCESS=true in an env file to
		// log every request (useful when tracing a specific call
		// end-to-end); failures are always visible via zap.Error in
		// the handlers themselves.
		Next: func(c *fiber.Ctx) bool {
			if configs.EnvConfigs == nil || !configs.EnvConfigs.LogHttpSuccess {
				return true
			}
			return false
		},
	}
}

func recoverConfig() recover.Config {
	return recover.Config{
		EnableStackTrace: true,
	}
}
