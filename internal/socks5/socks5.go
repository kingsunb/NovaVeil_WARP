// Package socks5 实现最小 SOCKS5 服务端, 支持 RFC1929 认证.
// 不依赖外部库, 协议见 RFC 1928. 每个连接用调用方传入的 DialFunc 拨号,
// 连接关闭时由 DialFunc 返回的 net.Conn 的 Close 负责释放底层资源.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// DialFunc 拨号到目标地址, username 为槽位账号.
type DialFunc func(ctx context.Context, network, addr, username string) (net.Conn, error)

// Server 是一个 SOCKS5 服务端.
type Server struct {
	Dial       DialFunc
	Timeout    time.Duration
	BufferSize int
}

// Serve 接受一个已连接的客户端并处理一个 SOCKS5 会话.
func (s *Server) Serve(ctx context.Context, client net.Conn) error {
	defer client.Close()

	if s.Timeout > 0 {
		_ = client.SetDeadline(time.Now().Add(s.Timeout))
	}

	// 1. 握手: VER NMETHODS METHODS
	username, err := s.negotiate(client)
	if err != nil {
		return fmt.Errorf("socks5 negotiate: %w", err)
	}

	// 2. 请求: VER CMD RSV ATYP DST.ADDR DST.PORT
	addr, err := s.readRequest(client)
	if err != nil {
		return fmt.Errorf("socks5 request: %w", err)
	}

	_ = client.SetDeadline(time.Time{})

	// 3. 拨号
	dialCtx, cancel := context.WithTimeout(ctx, s.dialTimeout())
	defer cancel()
	upstream, err := s.Dial(dialCtx, "tcp", addr, username)
	if err != nil {
		s.sendReply(client, socksReply(err))
		return fmt.Errorf("socks5 dial %s: %w", addr, err)
	}
	defer upstream.Close()

	// 4. 回复成功
	if err := s.sendReply(client, 0x00); err != nil {
		return fmt.Errorf("socks5 reply: %w", err)
	}

	// 5. 双向转发
	s.relay(client, upstream)
	return nil
}

func (s *Server) negotiate(client net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return "", err
	}
	if header[0] != 0x05 {
		return "", errors.New("unsupported SOCKS version")
	}
	nmethods := int(header[1])
	if nmethods == 0 {
		return "", errors.New("no auth methods offered")
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return "", err
	}
	method := byte(0xFF)
	hasNoAuth := false
	for _, offered := range methods {
		if offered == 0x02 {
			method = 0x02
			break
		}
		if offered == 0x00 {
			hasNoAuth = true
		}
	}
	if method == 0xFF {
		if !hasNoAuth {
			_, _ = client.Write([]byte{0x05, 0xFF})
			return "", errors.New("no acceptable auth methods")
		}
		method = 0x00
	}
	if _, err := client.Write([]byte{0x05, method}); err != nil {
		return "", err
	}
	if method == 0x02 {
		return s.readUserPass(client)
	}
	return "", nil
}

func (s *Server) readUserPass(client net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return "", err
	}
	if header[0] != 0x01 {
		_, _ = client.Write([]byte{0x01, 0x01})
		return "", errors.New("unsupported username/password auth version")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, username); err != nil {
		return "", err
	}
	length := make([]byte, 1)
	if _, err := io.ReadFull(client, length); err != nil {
		return "", err
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(client, password); err != nil {
		return "", err
	}
	if _, err := client.Write([]byte{0x01, 0x00}); err != nil {
		return "", err
	}
	return string(username), nil
}

func (s *Server) readRequest(client net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(client, header); err != nil {
		return "", err
	}
	if header[0] != 0x05 {
		return "", errors.New("unsupported SOCKS version in request")
	}
	if header[1] != 0x01 {
		return "", fmt.Errorf("unsupported command 0x%02x (only CONNECT)", header[1])
	}

	var host string
	switch header[3] {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03: // 域名
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, lenBuf); err != nil {
			return "", err
		}
		buf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		return "", fmt.Errorf("unsupported address type 0x%02x", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func (s *Server) sendReply(client net.Conn, rep byte) error {
	// VER REP RSV ATYP(IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	_, err := client.Write(reply)
	return err
}

type replyError interface {
	Socks5Reply() byte
}

func socksReply(err error) byte {
	var reply replyError
	if errors.As(err, &reply) {
		return reply.Socks5Reply()
	}
	return 0x05
}

type closeWriter interface {
	CloseWrite() error
}

func tryCloseWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func (s *Server) relay(client, upstream net.Conn) {
	bufSize := s.BufferSize
	if bufSize <= 0 {
		bufSize = 32 * 1024
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.CopyBuffer(upstream, client, make([]byte, bufSize))
		tryCloseWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.CopyBuffer(client, upstream, make([]byte, bufSize))
		tryCloseWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func (s *Server) dialTimeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return 30 * time.Second
}
