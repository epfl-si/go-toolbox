// Package opdo handles OPDo logging
package opdo

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
)

var logFile = "/logs/OPDo.log"

func init() {
	// Check if the env variable OPDO_LOGFILE exists, and if it does, set logFile to the value of the env variable
	if os.Getenv("OPDO_LOGFILE") != "" {
		logFile = os.Getenv("OPDO_LOGFILE")
	}
	id := uuid.New() // Generates a random UUID (v4)
	logFile += id.String()
}

// LogOPDo logs the operation of the user identified by handler_id on the data of the user identified by handled_id in the file /logs/OPDo.log
// Parameters:
// - log: a log.Logger object
// - handlerID: the id of the user who performed the operation
// - handledID: the id of the user whose data was operated on
// - crudt: the type of operation performed
//   - C - Creation
//   - R - Read access
//   - U - Modification access
//   - D - Delete
//   - T - Transmission/Export of Data
//
// - source: the source of the operation (e.g. the name of the application/IP address)
// - payload: DPO readable description of the access
// - caller: caller information, used to produced technical logging if not empty
func LogOPDo(log *log.Logger, handlerID string, handledID string, crudt string, source string, payload string, caller string) {
	// Technical logging
	if caller != "" {
		log.Printf("OPDo: In %s (%s), %s accessed %s data in %s mode: %s", caller, source, handlerID, handledID, crudt, payload)
	}

	// Open the file for writing
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed creating file: %s", err)
		return
	}
	// Ensure the file is closed even if an error occurs
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("failed closing file: %s", err)
		}
	}()

	// Create a new writer
	writer := bufio.NewWriter(file)

	// Write the log
	_, err = fmt.Fprintf(writer, "\"%s\";\"%s\";\"%s\";\"%s\";\"%s\";\"%s\"\n", time.Now().UTC().Format(time.RFC3339), handlerID, handledID, crudt, source, payload)
	if err != nil {
		log.Printf("failed writing to file: %s", err)
		return
	}

	// Flush the writer
	if err := writer.Flush(); err != nil {
		log.Printf("failed flushing writer: %s", err)
		return
	}
}
