package opdo

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

// LogOPDo(handler_id, handled_id, crudt, source, payload)
// LogOPDo logs the operation of the user identified by handler_id on the data of the user identified by handled_id in the file /logs/OPDo.log
// Parameters:
// - log: a log.Logger object
// - handler_id: the id of the user who performed the operation
// - handled_id: the id of the user whose data was operated on
// - crudt: the type of operation performed
//   - C - Creation
//   - R - Read access
//   - U - Modification access
//   - D - Delete
//   - T - Transmission/Export of Data
//
// - source: the source of the operation (e.g. the name of the application/IP address)
// - payload: DPO readable description of the access
// TODO: Should maybe take a logger parameter to log errors ?
func LogOPDo(log *log.Logger, handler_id string, handled_id string, crudt string, source string, payload string) {

	// Open the file for writing
	file, err := os.OpenFile("/logs/OPDo.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed creating file: %s", err)
	}

	// Defer closing the file
	defer file.Close()

	// Create a new writer
	writer := bufio.NewWriter(file)

	// Write the log
	_, err = fmt.Fprintf(writer, "\"%s\";\"%s\";\"%s\";\"%s\";\"%s\"\n", handler_id, handled_id, crudt, source, payload)
	if err != nil {
		log.Printf("failed writing to file: %s", err)
	}

	// Flush the writer
	writer.Flush()
}
