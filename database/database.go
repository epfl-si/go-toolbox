package database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	go_ora "github.com/sijms/go-ora/v2"
	"golang.org/x/crypto/ssh"

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
	gormDB, err := gorm.Open(mysql.Open(getConnectString(host, name, user, pass, port, param)), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		log.Error(fmt.Sprintf("GetGormDB:Hostname:'%s': %s", host, err))

		return nil, fmt.Errorf("GetGormDB: %w", err)
	}

	// log.Info(fmt.Sprintf("GetGormDB:successfully connected on host '%s' to database '%s' as user '%s' (%s)", host, name, user, param))

	sqlDB, err := gormDB.DB()
	if err != nil {
		log.Error(fmt.Sprintf("GetGormDB:Hostname:'%s': %s", host, err))

		return nil, fmt.Errorf("GetGormDB: %w", err)
	}
	sqlDB.SetMaxIdleConns(maxIdle)
	sqlDB.SetMaxOpenConns(maxOpen)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(2 * time.Minute)

	return gormDB, nil
}

// GetOracleDB returns an Oracle database connection.
func GetOracleDB(log *zap.Logger, host, name, user, pass, port, service string) (*sql.DB, error) {
	iPort, _ := strconv.Atoi(port)
	connStr := go_ora.BuildUrl(host, iPort, service, user, pass, nil)
	conn, err := sql.Open("oracle", connStr)
	if err != nil {
		return nil, fmt.Errorf("GetOracleDB: %w", err)
	}
	// check for error
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = conn.PingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("GetOracleDB: %w", err)
	}

	log.Info(fmt.Sprintf("GetOracleDB:successfully connected on Oracle host '%s' to database '%s' as user '%s'", host, name, user))

	return conn, nil
}

type SSHDialerForDB struct {
	client *ssh.Client
}

// Dial dials the given address to create a connection to the desired destination
func (v *SSHDialerForDB) Dial(ctx context.Context, n string, addr string) (net.Conn, error) {
	conn, err := v.client.DialContext(ctx, n, addr)
	if err != nil {
		err = fmt.Errorf("ViaSSHDialer.Dial: %w", err)
	}

	return &sshConnForDB{conn}, err
}

type sshConnForDB struct {
	net.Conn
}

// SetDeadline masks deadline requests as SSH tunnel has a global timeout
func (*sshConnForDB) SetDeadline(_ time.Time) error {
	return nil
}

// SetReadDeadline masks deadline requests as SSH tunnel has a global timeout
func (*sshConnForDB) SetReadDeadline(_ time.Time) error {
	return nil
}

// SetWriteDeadline masks deadline requests as SSH tunnel has a global timeout
func (*sshConnForDB) SetWriteDeadline(_ time.Time) error {
	return nil
}

// GetSSHDialer creates an instance of ViaSSHDialer that uses Public key authentication
func GetSSHDialer(sshHost string, sshPort int, sshUser string, keyPath string, hostKey ssh.PublicKey, passphrase string) (SSHDialerForDB, error) {
	// get signer from privatekey, optionally encrypted with a passphrase
	keyBytes, err := os.ReadFile(keyPath) //nolint:gosec
	if err != nil {
		return SSHDialerForDB{}, fmt.Errorf("database.GetSSHDialer: %w", err)
	}

	var signer ssh.Signer
	if passphrase == "" {
		signer, err = ssh.ParsePrivateKey(keyBytes)
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
	}
	if err != nil {
		return SSHDialerForDB{}, fmt.Errorf("database.GetSSHDialer: %w", err)
	}

	// create SSH config
	sshConfig := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         30 * time.Second,
	}

	// estabilish connection and return the dialer
	sshClient, err := ssh.Dial("tcp", net.JoinHostPort(sshHost, strconv.Itoa(sshPort)), sshConfig)
	if err != nil {
		return SSHDialerForDB{}, fmt.Errorf("database.GetSSHDialer: %w", err)
	}

	return SSHDialerForDB{client: sshClient}, nil
}

// GetOracleDBViaSSH connects to an Oracle server using an SSH tunnel
func GetOracleDBViaSSH(dbHost, dbUser, dbPass, dbService string, dbPort int, dbOptions map[string]string, sshDialer SSHDialerForDB) (*sql.DB, error) {
	// create db url, register the ssh dial to the config, and use the config to create a db connection
	dsn := go_ora.BuildUrl(dbHost, dbPort, dbService, dbUser, dbPass, dbOptions)

	config, err := go_ora.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("database.GetOracleDBViaSSH: %w", err)
	}

	config.RegisterDial(sshDialer.Dial)
	go_ora.RegisterConnConfig(config)
	dbConn, err := sql.Open("oracle", "")
	if err != nil {
		return nil, fmt.Errorf("database.GetOracleDBViaSSH: %w", err)
	}

	// test connection using a ping
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = dbConn.PingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("database.GetOracleDBViaSSH: %w", err)
	}

	// return db connection
	return dbConn, nil
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
