package batch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/epfl-si/go-toolbox/database"
	"github.com/gofrs/uuid"
	"go.uber.org/zap"

	batch "github.com/epfl-si/go-toolbox/batch/models"
	log "github.com/epfl-si/go-toolbox/log"
)

func getBatchLogger(logLevel string) *zap.Logger {
	return zap.Must(log.GetLoggerConfig(logLevel, []string{"stdout", "/tmp/stdout"}, []string{"stderr", "/tmp/stderr"}).Build())
}

func Log(logger *zap.Logger, priority, message string) {
	if strings.ToUpper(priority) == "INFO" {
		logger.Info(message)
	} else if strings.ToUpper(priority) == "WARN" {
		logger.Warn(message)
	} else if strings.ToUpper(priority) == "ERROR" {
		logger.Error(message)
	} else if strings.ToUpper(priority) == "FATAL" {
		logger.Fatal(message)
	} else if strings.ToUpper(priority) == "DEBUG" {
		logger.Debug(message)
	}
}

func InitBatch() (batch.BatchConfig, error) {
	// generate a UUID
	uuid, _ := uuid.NewV4()
	uuidStr := fmt.Sprintf("%v", uuid)

	// get command and args
	args := os.Args

	ex, err := os.Executable()
	if err != nil {
		return batch.BatchConfig{}, err
	}
	exPath := filepath.Dir(ex)

	logger := getBatchLogger("info")

	db, err := database.GetGormDB(logger, os.Getenv("DBHOST"), os.Getenv("DBNAME"), os.Getenv("DBUSER"), os.Getenv("DBPASS"), os.Getenv("DBPORT"), os.Getenv("DBPARAMS"), 1, 1)
	if err != nil {
		return batch.BatchConfig{}, err
	}

	config := batch.BatchConfig{
		Uuid:        uuidStr,
		Name:        ex,
		Args:        strings.Join(args, " "),
		Stdout:      "",
		Stderr:      "",
		Status:      "RUNNING",
		Path:        exPath,
		OutputPath:  "",
		FilePattern: "",
		Logger:      logger,
		Db:          db,
	}

	return config, nil
}

func SendStatus(config batch.BatchConfig, status string) error {
	// read stdout from /tmp/stdout file
	stdout, err := os.ReadFile("/tmp/stdout")
	if err != nil {
		return err
	}
	stderr, err := os.ReadFile("/tmp/stderr")
	if err != nil {
		return err
	}
	stdoutStr := string(stdout)
	stderrStr := string(stderr)

	batchLog := batch.BatchLog{
		Id:           config.Uuid,
		Date:         time.Now(),
		Name:         config.Name,
		Args:         config.Args,
		Stdout:       stdoutStr,
		Stderr:       stderrStr,
		StdoutLength: len(stdoutStr),
		StderrLength: len(stderrStr),
		Status:       strings.ToUpper(status),
		Path:         config.Path,
		OutputPath:   "",
		FilePattern:  "",
	}
	err = config.Db.Save(&batchLog).Error
	if err != nil {
		return err
	}

	return nil
}
