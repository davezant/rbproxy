package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"rbproxy/pkg/terminal"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type MissingPermissionsForPortForwarding string
func (e MissingPermissionsForPortForwarding) Error() string {
	return "[rbproxy] ERR: Hosting for the current port needs superuser permissions " + string(e)
}

type InvalidAddressForProxyAccess string
func (e InvalidAddressForProxyAccess) Error() string {
	return "[rbproxy] ERR : Invalid address!  " + string(e)
}

type PortIsAlreadyBeingUsed string
func (e PortIsAlreadyBeingUsed) Error() string {
	return "[rbproxy] ERR: Current port is already being used " + string(e)
}

type Relatory struct {
	StrangeInputs int
	MaliciousAttempts int
}

type PortConfig struct {
//	Info
	Network string
	Protected bool
	ProxyAddress string
	TargetAddress string

//	Limiters
	SpecificLimitBytes int
	GeneralRateLimiter int // ALL
	ExclusiveRateLimiter int // IP Based
// 	Functions 
//	OnRequest(b *buffer) returns 
	ClientFunctions []func(*[]byte) ([]byte, []byte, bool)
	ServerFunctions []func(*[]byte) ([]byte, []byte, bool)
	OnRequest func(*[]byte) ([]byte, []byte, bool)
	OnResponse func(*[]byte) ([]byte, []byte, bool)
	OnClose func(c net.Conn) []byte
}

type Proxy struct {
	Configs *ProxyConfig

//	Environment
	ListenedPorts []PortConfig
	TLSConfig tls.Config
	netListeners []*net.Listener
}

type ProxyConfig struct {
	GeneralLimitBytes int
	
	Verbose bool
}

type RequestPacket struct {
	URLPath string
	Method string
	HTTPVersion string

	Headers map[string]string
	Body map[string]any
	
}

type ResponsePacket struct {
    Protocol   string            
    StatusCode int                
	StatusText string            
    Headers    map[string]string 
    Body       []byte            
}

// Packets & Bytes

const (
	regexHeaders = `(?m)^([^:\r\n]+):\s*([^\r\n]+)`
	regexRequestTopQuery = `^(GET|POST|PUT|DELETE|OPTIONS|HEAD|PATCH)\s+([^\s]+)\s+(HTTP\/[0-9.]+)`
	regexResponseTopQuery = `^(HTTP\/[0-9.]+)\s+([0-9]{3})\s+(.*)$`
)

var (
	reHeaders     = regexp.MustCompile(regexHeaders)
	reRequestTop  = regexp.MustCompile(regexRequestTopQuery)
	reResponseTop = regexp.MustCompile(regexResponseTopQuery)
)

// Passível de mudança

func ParseRequest(buffer *[]byte) RequestPacket {
	req := RequestPacket{Headers: make(map[string]string)}
	parts := bytes.SplitN(*buffer, []byte("\r\n\r\n"), 2)
	headerPart := string(parts[0])

	topMatch := reRequestTop.FindStringSubmatch(headerPart)
	if len(topMatch) > 3 {
		req.Method = topMatch[1]
		req.URLPath = topMatch[2]
		req.HTTPVersion = topMatch[3]
	}

	headerLines := reHeaders.FindAllStringSubmatch(headerPart, -1)
	for _, m := range headerLines {
		req.Headers[m[1]] = m[2]
	}
	
	if len(parts) > 1 && len(parts[1]) > 0 {
		json.Unmarshal(parts[1], &req.Body)
	}

	return req
}

func SerializeRequest(request RequestPacket) []byte {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s %s %s\r\n", request.Method, request.URLPath, request.HTTPVersion))
	for k, v := range request.Headers {
		b.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	b.WriteString("\r\n")

	bodyBytes, _ := json.Marshal(request.Body)
	return append([]byte(b.String()), bodyBytes...)
}

func ParseResponse(buffer *[]byte) ResponsePacket {
	res := ResponsePacket{Headers: make(map[string]string)}
	parts := bytes.SplitN(*buffer, []byte("\r\n\r\n"), 2)
	headerPart := string(parts[0])
	
	topMatch := reResponseTop.FindStringSubmatch(regexResponseTopQuery)

	if len(topMatch) > 3 {
		res.Protocol = topMatch[1]
		res.StatusCode, _ = strconv.Atoi(topMatch[2])
		res.StatusText = topMatch[3]
	}

	headerLines := reHeaders.FindAllStringSubmatch(headerPart, -1)
	for _, m := range headerLines {
		res.Headers[m[1]] = m[2]
	}

	if len(parts) > 1 {
		res.Body = parts[1]
	}

	return res
}

func SerializeResponse(response ResponsePacket) []byte {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s %d %s\r\n", response.Protocol, response.StatusCode, response.StatusText))
	for k, v := range response.Headers {
		b.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	b.WriteString("\r\n")

	return append([]byte(b.String()), response.Body...)
}

// Proxy

func NewProxy(cfg *ProxyConfig, ports []PortConfig) Proxy {
    return Proxy{
		Configs: cfg,
        ListenedPorts:   ports,
    }
}

func (p *Proxy) SetCertificateHTTPS(certFile, keyFile string) {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
		terminal.RaiseError(err)
    }

    p.TLSConfig = tls.Config{
        Certificates:       []tls.Certificate{cert},
        InsecureSkipVerify: true,
        MinVersion:         tls.VersionTLS12, 
    }
}

func (p *Proxy) Start(){
	fmt.Printf("[rbproxy] Starting proxy service - %s\n",terminal.Version)
	for n := range p.ListenedPorts{
		go p.ListenAndRedirect(p.ListenedPorts[n])
	}
	select {}
}

func (p *Proxy) ListenAndRedirect(port PortConfig){
	var listener net.Listener
	var err error
	CallTillPing(p, port)
	fmt.Printf("[rbproxy] Listening for %s to %s\n",port.TargetAddress, port.ProxyAddress)
	
	if !port.Protected {
		listener, err = net.Listen(port.Network, port.ProxyAddress)
	} else {
		listener, err = tls.Listen(port.Network, port.ProxyAddress, &p.TLSConfig)
	}
	
	if err != nil {
		log.Fatal(err)
	}

	go func(){
		for {
    		conn, err := listener.Accept()
    		if err != nil {
				terminal.RaiseFatal(err)
        		continue
    		}
 
		go func(c net.Conn) {
	        defer c.Close()

	        var isRedirectNeeded bool
	        var redirectBuffer []byte
    	
			requestBuffer := p.CaptureClientRequest(c, port)
        
	        if port.OnRequest != nil {
	            requestBuffer, redirectBuffer, isRedirectNeeded = port.OnRequest(&requestBuffer)

				if len(port.ClientFunctions) >= 1 {
					for _, fn := range port.ClientFunctions{
						requestBuffer, redirectBuffer, isRedirectNeeded = fn(&requestBuffer)
						if isRedirectNeeded {
							break
						}
					}
				}
	        }
	
	        var responseBuffer []byte
	        
	        if !isRedirectNeeded {
	            responseBuffer = p.ForwardToTarget(requestBuffer, port)
	            if port.OnResponse != nil {
	                var isResponseRedirectNeeded bool
	                var resBuffer []byte
	                responseBuffer, resBuffer, isResponseRedirectNeeded = port.OnResponse(&responseBuffer)
                
					if len(port.ServerFunctions) >= 1 {
						for _, fn := range port.ClientFunctions{
							responseBuffer, resBuffer, isResponseRedirectNeeded = fn(&requestBuffer)
							if isResponseRedirectNeeded {
								break
							}
						}
					}
	                if isResponseRedirectNeeded {
	                    isRedirectNeeded = true
	                    redirectBuffer = resBuffer
	                }
	            }
	        }
	
	        if isRedirectNeeded {
				if p.Configs.Verbose{
					fmt.Println("[rbproxy] Handling Redirection to ", c.RemoteAddr().String())
				}
				c.Write(redirectBuffer)
	        } else {
	            c.Write(responseBuffer)
	        }
	
	        if port.OnClose != nil {
	            port.OnClose(c)
		    }
		}(conn)
		}
	}()
	p.netListeners = append(p.netListeners, &listener)
}

func (p *Proxy) CaptureClientRequest(conn net.Conn, port PortConfig) []byte {
	var requestBuffer []byte

	if port.SpecificLimitBytes >= 128 {
		requestBuffer = make([]byte, port.SpecificLimitBytes)
	} else if p.Configs.GeneralLimitBytes >= 128 {
 	  	requestBuffer = make([]byte, p.Configs.GeneralLimitBytes)
	} else {
		requestBuffer = make([]byte, 1024)
	}
	n, _ := conn.Read(requestBuffer)

	if p.Configs.Verbose {
		rq := string(requestBuffer)
		fmt.Println("[rbproxy]",rq)
	}

	return requestBuffer[:n]
}

func (p *Proxy) ForwardToTarget(requestPacket []byte, port PortConfig) []byte {
    c, err := net.Dial(port.Network, port.TargetAddress)
    
	if err != nil {
        log.Println(err)
        return nil
    }
    
	defer c.Close()
    c.Write(requestPacket)

    var responseBuffer bytes.Buffer

    _, err = io.Copy(&responseBuffer, c)
    if err != nil && err != io.EOF {
		log.Println("[rbproxy] ERR:",err)
    }

	if p.Configs.Verbose {
		rp := responseBuffer.String()
		fmt.Println("[rbproxy]",rp)
	}
	
	return responseBuffer.Bytes()
}

func CallTillPing(proxy *Proxy, port PortConfig) bool {
    repetitions := 0
    timeout := 5 * time.Second

    for repetitions <= 9 {
        fmt.Printf("[rbproxy] Attempt %d: Waiting for %s...\n", repetitions+1, port.TargetAddress)

        var c net.Conn
        var err error

        dialer := net.Dialer{Timeout: timeout}
        if !port.Protected {
            c, err = dialer.Dial(port.Network, port.TargetAddress)
        } else {
            c, err = tls.Dial(port.Network, port.TargetAddress, &proxy.TLSConfig)
        }

        if err != nil {
            fmt.Println("[rbproxy] Target not reachable:", err)
        } else {
            c.Close()
            fmt.Println("[rbproxy] Found Server:", port.TargetAddress)
            return true
        }

        time.Sleep(2 * time.Second)  
		repetitions++
    }

	terminal.PrintLog("Failed to reach target after max attempts.")
    return false
}
