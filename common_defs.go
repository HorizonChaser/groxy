package main

import (
	"fmt"
	"github.com/logrusorgru/aurora/v4"
	"regexp"
	"runtime"
	"strings"
)

type LogLevel int
type ServerMode int
type ClientMode int

const (
	Dynamic = iota
	Legacy
)

const (
	Raw = iota
	Socks55
	HTTP
)

const (
	Silent = iota
	Info
	Debug
)

var ipReg = `^((0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.){3}(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$`
var r, _ = regexp.Compile(ipReg)

func IsValidIPv4Address(s string) bool {
	//fi, fu, l := GetCurrFuncFileAndLine()
	//fmt.Printf("curr in func %s in %s:%d\n", fu, fi, l)
	return r.MatchString(s)
}

func GetCurrFuncFileAndLine() (fileName string, funcName string, lineNo int) {
	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	fmt.Printf("%s:%d %s\n", frame.File, frame.Line, frame.Function)

	fileNameSplits := strings.Split(frame.File, "\\")
	fileName = fileNameSplits[len(fileNameSplits)-1]
	funcName = frame.Function
	lineNo = frame.Line

	return
}

func PrintServerWelcomeMsg(msg string, version string) {
	fmt.Print(aurora.Cyan(msg))
	fmt.Println(aurora.Sprintf(aurora.Magenta(" version %s\n"), aurora.Magenta(version)))
}

type ServerConfig struct {
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
	CertFile   string
	KeyFile    string

	LogLevel   LogLevel
	IsMTLS     bool
	CACert     string
	ServerMode ServerMode
}

type ClientConfig struct {
	LocalAddr               string
	LocalPort               int
	RemoteAddr              string
	RemotePort              int
	AllowInsecureServerCert bool
	CertFile                string
	KeyFile                 string

	LogLevel   LogLevel
	IsMTLS     bool
	CACert     string
	ClientMode ClientMode
}
