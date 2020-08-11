package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/elico/dns_resolver"
	glog "github.com/fangdingjun/go-log/v5"
	proxyproto "github.com/pires/go-proxyproto"
	yaml "gopkg.in/yaml.v2"
)

type sockaddr struct {
	family uint16
	data   [14]byte
}

var openDNSResolver *dns_resolver.DnsResolver

const SO_ORIGINAL_DST = 80

// realServerAddress returns an intercepted connection's original destination.
func realServerAddress(conn *net.Conn) (string, error) {
	tcpConn, ok := (*conn).(*net.TCPConn)
	if !ok {
		return "", errors.New("not a TCPConn")
	}

	file, err := tcpConn.File()
	if err != nil {
		return "", err
	}

	// To avoid potential problems from making the socket non-blocking.
	tcpConn.Close()
	*conn, err = net.FileConn(file)
	if err != nil {
		return "", err
	}

	defer file.Close()
	fd := file.Fd()

	var addr sockaddr
	size := uint32(unsafe.Sizeof(addr))
	err = getsockopt(int(fd), syscall.SOL_IP, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr)), &size)
	if err != nil {
		return "", err
	}

	var ip net.IP
	switch addr.family {
	case syscall.AF_INET:
		ip = addr.data[2:6]
	default:
		return "", errors.New("unrecognized address family")
	}

	port := int(addr.data[0])<<8 + int(addr.data[1])

	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

func getsockopt(s int, level int, name int, val uintptr, vallen *uint32) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

func getSNIServerName(buf []byte) string {
	n := len(buf)
	if n <= 5 {
		glog.Error("not tls handshake")
		return ""
	}

	// tls record type
	if recordType(buf[0]) != recordTypeHandshake {
		glog.Error("not tls")
		return ""
	}

	// tls major version
	if buf[1] != 3 {
		glog.Error("TLS version < 3 not supported")
		return ""
	}

	// payload length
	//l := int(buf[3])<<16 + int(buf[4])

	//log.Printf("length: %d, got: %d", l, n)

	// handshake message type
	if uint8(buf[5]) != typeClientHello {
		glog.Error("not client hello")
		return ""
	}

	// parse client hello message

	msg := &clientHelloMsg{}

	// client hello message not include tls header, 5 bytes
	ret := msg.unmarshal(buf[5:n])
	if !ret {
		glog.Error("parse hello message return false")
		return ""
	}
	return msg.serverName
}

func forward(ctx context.Context, c net.Conn, data []byte, dst string) {
	addr := dst
	proxyProto := 0

	ss := strings.Fields(dst)

	var hdr proxyproto.Header

	if len(ss) > 1 {
		addr = ss[0]
		raddr := c.RemoteAddr().(*net.TCPAddr)
		glog.Debugf("connection from %s", raddr)
		hdr = proxyproto.Header{
			Version:            1,
			Command:            proxyproto.PROXY,
			TransportProtocol:  proxyproto.TCPv4,
			SourceAddress:      raddr.IP.To4(),
			DestinationAddress: net.IP{0, 0, 0, 0},
			SourcePort:         uint16(raddr.Port),
			DestinationPort:    0,
		}

		switch strings.ToLower(ss[1]) {
		case "proxy-v1":
			proxyProto = 1
			hdr.Version = 1
		case "proxy-v2":
			proxyProto = 2
			hdr.Version = 2
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	c1, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		glog.Error(err)
		return
	}

	defer c1.Close()

	if proxyProto != 0 {
		glog.Debugf("send proxy proto v%d to %s", proxyProto, addr)
		if _, err = hdr.WriteTo(c1); err != nil {
			glog.Errorln(err)
			return
		}
	}

	if _, err = c1.Write(data); err != nil {
		glog.Error(err)
		return
	}

	ch := make(chan struct{}, 2)

	go func() {
		io.Copy(c1, c)
		ch <- struct{}{}
	}()

	go func() {
		io.Copy(c, c1)
		ch <- struct{}{}
	}()

	select {
	case <-ch:
	case <-ctx.Done():
	}
}

func getDST(c net.Conn, name string) string {
	addr := c.LocalAddr().(*net.TCPAddr)
	dst := cfg.ForwardRules.GetN(name, addr.Port)
	return dst
}

func getDefaultDST() string {
	return cfg.Default
}

func serve(ctx context.Context, c net.Conn) {
	defer c.Close()

	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		glog.Error(err)
		return
	}

	servername := getSNIServerName(buf[:n])
	if servername == "" {
		glog.Debugf("no sni, send to default")
		// Verify that the connection is intercepted
		address, err := realServerAddress(&c)
		// need to verify here that there is no internal loop
		// We should know here what IP addresses present on the Machine/Device
		if err == nil && address != c.LocalAddr().String() {
			if cfg.SpliceNonSni > 0 {
				glog.Debugf("Splicing default dst %s", address)
				forward(ctx, c, buf[:n], address)
				return
			}
		}
		glog.Debugf("Connecting %s->%s to default dst %s", c.LocalAddr(), c.RemoteAddr())
		forward(ctx, c, buf[:n], getDefaultDST())
		return
	}

	blackListed := false

	ips, err := openDNSResolver.LookupHost(servername)
	if err != nil {
		glog.Debugf("Could not get IPs: %v\n", err)
		switch {
		case strings.Contains(err.Error(), "NXDOMAIN"):
			//it's fine and possible
		default:
			glog.Debugf("openDNSResolver Got error on lookup for", servername, "ERROR:", err)
		}
	} else {
		for _, ip := range ips {
			if ip.String() == "146.112.61.104" {
				blackListed = true
				break
			}
		}
	}

	if blackListed {
		glog.Debugf("use dst %s for sni %s", cfg.BlockDestination, servername)
		forward(ctx, c, buf[:n], cfg.BlockDestination)
		return
	}

	dst := getDST(c, servername)
	if dst == "" {
		dst = getDefaultDST()
		glog.Debugf("using default dst %s for sni %s", dst, servername)
	}
	glog.Debugf("using dst %s for sni %s", dst, servername)
	forward(ctx, c, buf[:n], dst)
}

var cfg conf

func main() {
	var cfgfile string
	var logfile string
	var loglevel string
	flag.StringVar(&cfgfile, "c", "config.yaml", "config file")
	flag.StringVar(&logfile, "log_file", "", "log file")
	flag.StringVar(&loglevel, "log_level", "INFO", "log level")
	flag.Parse()

	openDNSResolver = dns_resolver.NewWithPort([]string{"208.67.222.222", "208.67.220.220"}, "53")

	data, err := ioutil.ReadFile(cfgfile)
	if err != nil {
		glog.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		glog.Fatal(err)
	}

	if logfile != "" {
		glog.Default.Out = &glog.FixedSizeFileWriter{
			MaxCount: 4,
			Name:     logfile,
			MaxSize:  10 * 1024 * 1024,
		}
	}

	if lv, err := glog.ParseLevel(loglevel); err == nil {
		glog.Default.Level = lv
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, d := range cfg.Listen {
		glog.Infof("listen on :%d", d)
		lc := &net.ListenConfig{}
		l, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", d))
		if err != nil {
			glog.Fatal(err)
		}
		go func(ctx context.Context, l net.Listener) {
			defer l.Close()
			for {
				c1, err := l.Accept()
				if err != nil {
					glog.Error(err)
					break
				}
				go serve(ctx, c1)
			}
		}(ctx, l)
	}

	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-ch:
		cancel()
		glog.Printf("received signal %s, exit.", s)
	}
}
