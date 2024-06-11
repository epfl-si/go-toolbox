package database

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// GetGormDB returns a Gorm database connection.
//
// Parameters:
// - log *zap.Logger: a logger instance
// - host string: the database host
// - name string: the database name
// - user string: the database user
// - pass string: the database password
// - port string: the database port
// - param string: the specific database parameters
// - maxIdle int: the maximum number of idle connections
// - maxOpen int: the maximum number of open connections
//
// Return type(s):
// - *gorm.DB: the Gorm database connection
// - error: an error, if any, encountered during the connection
func GetGormDB(log *zap.Logger, host, name, user, pass, port, param string, maxIdle int, maxOpen int) (*gorm.DB, error) {
	//log.Infof("[GetGormDB] Connecting to 'database' %s on host %s as user '%s' (%s)", name, host, user, param)
	logLevel := logger.Silent

	if os.Getenv("LOG_LEVEL") == "info" || os.Getenv("LOG_LEVEL") == "debug" {
		logLevel = logger.Info
	}
	db, err := gorm.Open(mysql.Open(getConnectString(host, name, user, pass, port, param)), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		log.Error(fmt.Sprintf("GetGormDB:%s", err))
		return db, err
	}

	log.Info(fmt.Sprintf("GetGormDB:successfully connected on host '%s' to database '%s' as user '%s' (%s)", host, name, user, param))

	sqlDB, err := db.DB()
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(2 * time.Minute)

	return db, nil
}

func getConnectString(dbHost, dbName, dbUser, dbPassword, dbPort, dbParam string) string {
	var dsn string
	if dbParam != "" {
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?%s", dbUser, dbPassword, dbHost, dbPort, dbName, dbParam)
	} else {
		dsn = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)
	}

	return dsn
}
