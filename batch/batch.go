package batch

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/epfl-si/go-toolbox/database"
	"github.com/gofrs/uuid"
	"github.com/joho/godotenv"
	"go.uber.org/zap"

	batch "github.com/epfl-si/go-toolbox/batch/models"
	log "github.com/epfl-si/go-toolbox/log"
)

const maxStdoutSize = 100000

func getBatchLogger(logLevel, uuid string) *zap.Logger {
	return zap.Must(log.GetLoggerConfig(logLevel, []string{"stdout", "/tmp/stdout_" + uuid}, []string{"stderr", "/tmp/stderr_" + uuid}, "json").Build())
}

func Log(logger *zap.Logger, priority, message string) {
	if strings.ToUpper(priority) == "INFO" {
		logger.Info(message)
	} else if strings.ToUpper(priority) == "WARN" {
		logger.Warn(message)
	} else if strings.ToUpper(priority) == "ERROR" {
		logger.Error(message)
	} else if strings.ToUpper(priority) == "FATAL" {
		logger.Error(message) // user .Error, otherwise the process is stopped before we can send the status
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

	exFullPath, err := os.Executable()
	if err != nil {
		return batch.BatchConfig{}, err
	}
	ex := filepath.Base(exFullPath)

	// find first space in args
	allArgs := strings.Join(args, " ")
	// if some args passed
	if strings.Contains(allArgs, " ") {
		allArgs = allArgs[strings.Index(allArgs, " ")+1:]
	} else {
		allArgs = ""
	}

	logger := getBatchLogger("info", uuidStr)

	// load env
	err = godotenv.Load("/home/dinfo/conf/.env")
	if err != nil {
		logger.Info(fmt.Sprintf("Unable to load /home/dinfo/conf/.env file: %s", err))
	}

	db, err := database.GetGormDB(logger, os.Getenv("CADI_DB_HOST"), os.Getenv("CADI_DB_NAME"), os.Getenv("CADI_DB_USER"), os.Getenv("CADI_DB_PWD"), os.Getenv("CADI_DB_PORT"), os.Getenv("CADI_DB_PARAMS"), 1, 1)
	if err != nil {
		return batch.BatchConfig{Logger: logger}, err
	}

	config := batch.BatchConfig{
		Uuid:        uuidStr,
		Name:        ex,
		Args:        allArgs,
		Stdout:      "",
		Stderr:      "",
		Status:      "RUNNING",
		Path:        exFullPath, // /home/dinfo/emails
		OutputPath:  "",
		FilePattern: "",
		Logger:      logger,
		Db:          db,
	}

	return config, nil
}

func SendStatus(config batch.BatchConfig, status string) error {
	// read stdout from /tmp/stdout file
	stdout, _ := os.ReadFile("/tmp/stdout_" + config.Uuid)
	stderr, _ := os.ReadFile("/tmp/stderr_" + config.Uuid)
	stdoutStr := string(stdout)
	stderrStr := string(stderr)
	if len(stdoutStr) > maxStdoutSize {
		stdoutStr = stdoutStr[:maxStdoutSize]
	}
	if len(stderrStr) > maxStdoutSize {
		stderrStr = stderrStr[:maxStdoutSize]
	}

	if status == "success" {
		status = "s"
	} else if status == "failed" {
		status = "f"
	} else {
		status = "f"
	}

	tx := config.Db.Begin()

	batchLog := batch.BatchLog{
		Id:           config.Uuid,
		Date:         time.Now(),
		Name:         config.Name,
		Args:         config.Args,
		Stdout:       stdoutStr,
		Stderr:       stderrStr,
		StdoutLength: len(stdoutStr),
		StderrLength: len(stderrStr),
		Status:       strings.ToLower(status),
		Path:         config.Path,
		LastChange:   time.Now(),
		OutputPath:   "",
		FilePattern:  "",
	}
	err := tx.Create(&batchLog).Error
	if err != nil {
		tx.Rollback()
		return err
	}

	// process stdout and stderr
	files := []string{"/tmp/stdout_" + config.Uuid, "/tmp/stderr_" + config.Uuid}
	for _, file := range files {
		// compress files and insert them in DB
		inputFile, err := os.Open(file)
		if err != nil {
			tx.Rollback()
			return err
		}
		defer inputFile.Close()
		// create a new gzip writer
		gzipWriter, err := os.Create(file + ".gz")
		if err != nil {
			tx.Rollback()
			return err
		}
		defer gzipWriter.Close()
		zipWriter := gzip.NewWriter(gzipWriter)
		defer zipWriter.Close()
		_, err = io.Copy(zipWriter, inputFile)
		if err != nil {
			tx.Rollback()
			return err
		}
		zipWriter.Close()

		// now read the file as bytes
		fileBytes, err := os.ReadFile(file + ".gz")
		if err != nil {
			tx.Rollback()
			return err
		}
		logFile := &batch.BatchLogFile{
			Name: file + ".gz",
			Data: fileBytes,
		}
		err = tx.Create(&logFile).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}

	tx.Commit()

	// stop the process
	os.Exit(1)

	return nil
}
