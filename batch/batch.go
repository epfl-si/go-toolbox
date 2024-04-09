package batch

import (
	"fmt"
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

func getBatchLogger(logLevel string) *zap.Logger {
	return zap.Must(log.GetLoggerConfig(logLevel, []string{"stdout", "/tmp/stdout"}, []string{"stderr", "/tmp/stderr"}, "json").Build())
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

	// load env
	err = godotenv.Load("/home/dinfo/conf/.env")
	if err != nil {
		logger.Info(fmt.Sprintf("Unable to load /home/dinfo/conf/.env file: %s", err))
	}

	//readFile, err := os.Open("/home/dinfo/conf/.env")
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fileScanner := bufio.NewScanner(readFile)
	//fileScanner.Split(bufio.ScanLines)

	//for fileScanner.Scan() {
	//	// Should check if contains PASS and not display
	//	logger.Info(fileScanner.Text())
	//}
	//readFile.Close()

	db, err := database.GetGormDB(logger, os.Getenv("CADI_DB_HOST"), os.Getenv("CADI_DB_NAME"), os.Getenv("CADI_DB_USER"), os.Getenv("CADI_DB_PWD"), os.Getenv("CADI_DB_PORT"), os.Getenv("CADI_DB_PARAMS"), 1, 1)
	if err != nil {
		return batch.BatchConfig{Logger: logger}, err
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
