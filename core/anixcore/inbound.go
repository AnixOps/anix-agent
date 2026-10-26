package anixcore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/conf"
)

const visionFlow = "xtls-rprx-vision"

type wsNetwork struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

type grpcNetwork struct {
	ServiceName string `json:"serviceName"`
}

// inboundConfig is the anixcore inbound for a panel node: `tag`, `type`,
// `listen`, `listen_port` and the protocol's settings, without users.
func inboundConfig(tag string, info *panel.NodeInfo, options *conf.Options) (map[string]any, error) {
	if info == nil || info.Common == nil {
		return nil, errors.New("node info is missing")
	}
	listen := options.ListenIP
	if listen == "" {
		listen = "0.0.0.0"
	}
	if net.ParseIP(listen) == nil {
		return nil, fmt.Errorf("listen ip %q is invalid", listen)
	}
	inbound := map[string]any{
		"tag":         tag,
		"listen":      listen,
		"listen_port": info.Common.ServerPort,
	}
	switch info.Type {
	case "shadowsocks":
		node := info.Shadowsocks
		if node == nil {
			return nil, errors.New("shadowsocks node info is missing")
		}
		if _, err := shadowsocksKeyLen(node.Cipher); err != nil {
			return nil, err
		}
		inbound["type"] = "shadowsocks"
		inbound["method"] = node.Cipher
		inbound["password"] = node.ServerKey
	case "trojan":
		node := info.Trojan
		if node == nil {
			return nil, errors.New("trojan node info is missing")
		}
		inbound["type"] = "trojan"
		if err := addTLS(inbound, info, options, true); err != nil {
			return nil, err
		}
		if err := addTransport(inbound, node.Network, node.NetworkSettings); err != nil {
			return nil, err
		}
	case "vless", "vmess":
		node := info.VAllss
		if node == nil {
			return nil, fmt.Errorf("%s node info is missing", info.Type)
		}
		inbound["type"] = info.Type
		settings := node.NetworkSettings
		if len(settings) == 0 {
			settings = node.NetworkSettingsBack
		}
		if err := addTransport(inbound, node.Network, settings); err != nil {
			return nil, err
		}
		if info.Security == panel.Reality {
			if info.Type != "vless" {
				return nil, errors.New("reality needs a vless node")
			}
			if _, ok := inbound["transport"]; ok {
				return nil, errors.New("anixcore runs reality only on tcp")
			}
			reality, err := realityConfig(node)
			if err != nil {
				return nil, err
			}
			inbound["reality"] = reality
		} else if err := addTLS(inbound, info, options, false); err != nil {
			return nil, err
		}
	case "hysteria2":
		node := info.Hysteria2
		if node == nil {
			return nil, errors.New("hysteria2 node info is missing")
		}
		inbound["type"] = "hysteria2"
		if err := addTLS(inbound, info, options, true); err != nil {
			return nil, err
		}
		switch node.ObfsType {
		case "":
		case "salamander":
			inbound["obfs"] = map[string]any{"type": "salamander", "password": node.ObfsPassword}
		default:
			return nil, fmt.Errorf("hysteria2 obfs %q is not supported", node.ObfsType)
		}
	case "tuic":
		node := info.Tuic
		if node == nil {
			return nil, errors.New("tuic node info is missing")
		}
		inbound["type"] = "tuic"
		if err := addTLS(inbound, info, options, true); err != nil {
			return nil, err
		}
		if node.CongestionControl != "" {
			inbound["congestion_control"] = node.CongestionControl
		}
	default:
		return nil, fmt.Errorf("anixcore does not serve %q nodes", info.Type)
	}
	return inbound, nil
}

// addTLS sets `tls` from the node's certificate config. QUIC protocols
// always need it; the rest only when the node asks for TLS.
func addTLS(inbound map[string]any, info *panel.NodeInfo, options *conf.Options, required bool) error {
	if !required && info.Security != panel.Tls {
		return nil
	}
	cert := options.CertConfig
	if cert == nil || cert.CertMode == "" || cert.CertMode == "none" {
		if required {
			return fmt.Errorf("%s needs a certificate (CertConfig)", info.Type)
		}
		// The node asks for TLS but the agent terminates none: plain, as
		// the sing-box core does.
		return nil
	}
	if cert.CertFile == "" || cert.KeyFile == "" {
		return errors.New("CertConfig needs CertFile and KeyFile")
	}
	inbound["tls"] = map[string]any{
		"certificate_path": cert.CertFile,
		"key_path":         cert.KeyFile,
	}
	return nil
}

// addTransport sets `transport` for ws and grpc networks.
func addTransport(inbound map[string]any, network string, settings json.RawMessage) error {
	switch network {
	case "", "tcp":
		if len(settings) != 0 {
			var tcp struct {
				Header struct {
					Type string `json:"type"`
				} `json:"header"`
			}
			if err := json.Unmarshal(settings, &tcp); err != nil {
				return fmt.Errorf("decode network settings: %w", err)
			}
			if tcp.Header.Type != "" && tcp.Header.Type != "none" {
				return fmt.Errorf("tcp header %q is not supported", tcp.Header.Type)
			}
		}
		return nil
	case "ws":
		var ws wsNetwork
		if len(settings) != 0 {
			if err := json.Unmarshal(settings, &ws); err != nil {
				return fmt.Errorf("decode network settings: %w", err)
			}
		}
		path, err := url.Parse(ws.Path)
		if err != nil {
			return fmt.Errorf("parse ws path: %w", err)
		}
		transport := map[string]any{"type": "ws", "path": path.Path}
		if ed, err := strconv.Atoi(path.Query().Get("ed")); err == nil && ed > 0 {
			transport["max_early_data"] = ed
		}
		for name, value := range ws.Headers {
			if strings.EqualFold(name, "host") {
				transport["host"] = value
			}
		}
		inbound["transport"] = transport
		return nil
	case "grpc":
		var grpc grpcNetwork
		if len(settings) != 0 {
			if err := json.Unmarshal(settings, &grpc); err != nil {
				return fmt.Errorf("decode network settings: %w", err)
			}
		}
		if grpc.ServiceName == "" {
			return errors.New("grpc network needs a serviceName")
		}
		inbound["transport"] = map[string]any{"type": "grpc", "service_name": grpc.ServiceName}
		return nil
	default:
		return fmt.Errorf("network %q is not supported by anixcore", network)
	}
}

func realityConfig(node *panel.VAllssNode) (map[string]any, error) {
	settings := node.TlsSettings
	if settings.PrivateKey == "" && node.TlsSettingsBack != nil {
		settings = *node.TlsSettingsBack
	}
	if settings.PrivateKey == "" || settings.ServerName == "" {
		return nil, errors.New("reality needs private_key and server_name")
	}
	dest := settings.Dest
	if dest == "" {
		dest = settings.ServerName
	}
	port := 443
	if host, value, err := net.SplitHostPort(dest); err == nil {
		dest = host
		if port, err = strconv.Atoi(value); err != nil {
			return nil, fmt.Errorf("reality dest port %q is invalid", value)
		}
	} else if settings.ServerPort != "" {
		if port, err = strconv.Atoi(settings.ServerPort); err != nil {
			return nil, fmt.Errorf("reality server_port %q is invalid", settings.ServerPort)
		}
	}
	reality := map[string]any{
		"private_key":  settings.PrivateKey,
		"short_ids":    []string{settings.ShortId},
		"server_names": []string{settings.ServerName},
		"handshake":    map[string]any{"server": dest, "server_port": port},
	}
	if node.RealityConfig.MaxTimeDiff != "" {
		if diff, err := time.ParseDuration(node.RealityConfig.MaxTimeDiff); err == nil && diff > 0 {
			reality["max_time_difference_secs"] = int64(diff / time.Second)
		}
	}
	return reality, nil
}

func shadowsocksKeyLen(cipher string) (int, error) {
	switch cipher {
	case "2022-blake3-aes-128-gcm":
		return 16, nil
	case "2022-blake3-aes-256-gcm":
		return 32, nil
	case "2022-blake3-chacha20-poly1305":
		return 0, errors.New("2022-blake3-chacha20-poly1305 has no multi-user mode; use an aes method")
	default:
		return 0, fmt.Errorf("anixcore serves shadowsocks 2022 aes methods only, not %q", cipher)
	}
}

// userName is the anixcore user name of a panel user: its id, which comes
// back in traffic and online reports.
func userName(user panel.UserInfo) string {
	return strconv.Itoa(user.Id)
}

// apiUserFor gives a panel user the credential its node's protocol checks,
// the way the sing-box core does: the UUID, or for Shadowsocks 2022 the
// first key-length bytes of it.
func apiUserFor(info *panel.NodeInfo, user panel.UserInfo) (apiUser, error) {
	out := apiUser{Name: userName(user)}
	switch info.Type {
	case "shadowsocks":
		keyLen, err := shadowsocksKeyLen(info.Shadowsocks.Cipher)
		if err != nil {
			return apiUser{}, err
		}
		if len(user.Uuid) < keyLen {
			return apiUser{}, fmt.Errorf("user %d uuid is too short for a shadowsocks key", user.Id)
		}
		out.Password = base64.StdEncoding.EncodeToString([]byte(user.Uuid[:keyLen]))
	case "trojan", "hysteria2":
		out.Password = user.Uuid
	case "tuic":
		out.UUID = user.Uuid
		out.Password = user.Uuid
	case "vless":
		out.UUID = user.Uuid
		if info.Security == panel.Reality && info.VAllss != nil && info.VAllss.Flow == visionFlow {
			out.Flow = visionFlow
		}
	case "vmess":
		out.UUID = user.Uuid
	default:
		return apiUser{}, fmt.Errorf("anixcore does not serve %q nodes", info.Type)
	}
	return out, nil
}
