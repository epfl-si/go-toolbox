package database

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

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
	if os.Getenv("LOG_DB_SILENT") == "1" {
		logLevel = logger.Silent
	}
	db, err := gorm.Open(mysql.Open(getConnectString(host, name, user, pass, port, param)), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		log.Error(fmt.Sprintf("GetGormDB:Hostname:'%s': %s", host, err))
		return nil, err
	}

	// log.Info(fmt.Sprintf("GetGormDB:successfully connected on host '%s' to database '%s' as user '%s' (%s)", host, name, user, param))

	sqlDB, err := db.DB()
	if err != nil {
		log.Error(fmt.Sprintf("GetGormDB:Hostname:'%s': %s", host, err))
		return nil, err
	}
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(2 * time.Minute)

	return db, nil
}

// GetOracleDB returns an Oracle database connection.
func GetOracleDB(log *zap.Logger, host, name, user, pass, port, service string) (*sql.DB, error) {
	iPort, _ := strconv.Atoi(port)
	connStr := go_ora.BuildUrl(host, iPort, service, user, pass, nil)
	conn, err := sql.Open("oracle", connStr)
	if err != nil {
		return nil, err
	}
	// check for error
	err = conn.Ping()
	if err != nil {
		return nil, err
	}

	log.Info(fmt.Sprintf("GetOracleDB:successfully connected on Oracle host '%s' to database '%s' as user '%s'", host, name, user))

	return conn, nil
}

type viaSSHDialer struct {
	client *ssh.Client
}

func (self *viaSSHDialer) Dial(addr string) (net.Conn, error) {
	return self.client.Dial("tcp", addr)
}

func getSSHDialer(sshHost string, sshPort int, sshUser string, sshPass string) (viaSSHDialer, error) {
	var agentClient agent.Agent

	// Estabilish a connection to the local ssh-agent
	if conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		//nolint:errcheck
		defer conn.Close()

		agentClient = agent.NewClient(conn)
	}

	sshConfig := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{},
	}

	if agentClient != nil {
		sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeysCallback(agentClient.Signers))
	}

	if sshPass != "" {
		sshConfig.Auth = append(sshConfig.Auth, ssh.PasswordCallback(func() (string, error) {
			return sshPass, nil
		}))
	}

	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", sshHost, sshPort), sshConfig)
	if err != nil {
		return viaSSHDialer{}, fmt.Errorf("getSSHDialer: %w", err)
	}

	return viaSSHDialer{client: sshClient}, nil
}

//nolint:revive
func GetOracleDBViaSSH(dbHost, dbUser, dbPass, dbService string, dbPort int, sshHost string, sshPort int, sshUser string, sshPass string) (*sql.DB, error) {
	sshDialer, err := getSSHDialer(sshHost, sshPort, sshUser, sshPass)
	if err != nil {
		return nil, fmt.Errorf("GetOracleDBViaSSH: %w", err)
	}

	dsn := go_ora.BuildUrl(dbHost, dbPort, dbService, dbUser, dbPass, nil)

	config, err := go_ora.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("GetOracleDBViaSSH: %w", err)
	}

	config.RegisterDial(sshDialer.client.DialContext)
	go_ora.RegisterConnConfig(config)
	db, err := sql.Open("oracle", "")
	if err != nil {
		return nil, fmt.Errorf("GetOracleDBViaSSH: %w", err)
	}

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
