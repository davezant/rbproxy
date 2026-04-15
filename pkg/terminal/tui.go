package terminal

import (
	"fmt"
	"log"
)

const (
	Version = "0.1.0v"
)

// Terminal prints

func PrintLog(verbose bool, e string){
	if verbose {
		fmt.Println("[rbproxy]", e)
	}
}

func RaiseError(e error){
	log.Println("[rbproxy] ERR", e.Error())
}

func RaiseFatal(e error){
	log.Fatal("[rbproxy] FATAL", e.Error())
}

// TUI
