package common_def

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

// for ServerMode enum val
const (
	Dynamic = iota
	Legacy
	Realtime
)

// for ClientMode enum val
const (
	Raw = iota
	Socks55
	HTTP
)

// for LogLevel enum val
const (
	Silent = iota
	Info
	Debug
)

// reg expression for IPv4 addr validation
var ipReg = `^((0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.){3}(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$`
var r, _ = regexp.Compile(ipReg)

// IsValidIPv4Address checks whether input str is a valid IPv4 addr
func IsValidIPv4Address(s string) bool {
	//fi, fu, l := GetCurrFuncFileAndLine()
	//fmt.Printf("curr in func %s in %s:%d\n", fu, fi, l)
	return r.MatchString(s)
}

// GetCurrFuncFileAndLine returns fileName, funcName and lineNo which correspond to the line where this func is called, for logging purpose
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
	LocalAddr  string // Addr that this groxy server will listen TLS connections at
	LocalPort  int    // Port that this groxy server will listen TLS connections at
	RemoteAddr string // Addr that this groxy server will forward payload of TLS traffic to, ONLY affects in Dynamic Mode
	RemotePort int    // Port that this groxy server will forward payload of TLS traffic to, ONLY affects in Dynamic Mode
	CertFile   string // Path to certificate file that this server use for TLS connection
	KeyFile    string // Path to key of the certificate that this server use for TLS connection

	LogLevel   LogLevel
	IsMTLS     bool   // Is mTLS enabled in TLS handshake
	CACert     string // Path to certificate that CA holds, who assigns the client side cert, ONLY affects when mTLS is enabled
	ServerMode ServerMode

	//ONLY FOR AUDIT SCENARIO
	IsKeyLogged bool   // Whether key logging enabled, which will exports results of handshake and key calc to decrypt TLS1.3 traffics
	KeyLogger   string // Path to output file of KeyLogger
}

type ClientConfig struct {
	LocalAddr               string // Addr that this groxy client will listen client side apps at
	LocalPort               int    // port that this groxy client will listen client side apps at
	RemoteAddr              string // Addr of the groxy server that this groxy client will forward traffic to
	RemotePort              int    // Port of the groxy server that this groxy client will forward traffic to
	AllowInsecureServerCert bool   // Whether to trust insecure server-side cert, usually true when using self-signed certs
	CertFile                string // Path to certificate that client used in mTLS
	KeyFile                 string // Path to key of certificate that client used in mTLS

	LogLevel   LogLevel
	IsMTLS     bool   // Is mTLS allowed when client handshakes with server
	CACert     string // Path to certificate that CA holds, who assigns the client side cert, ONLY affects when mTLS is enabled
	ClientMode ClientMode
}
