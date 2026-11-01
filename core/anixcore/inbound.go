package anixcore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
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

type httpupgradeNetwork struct {
	Path string `json:"path"`
	Host string `json:"host"`
}

type xhttpNetwork struct {
	Path string `json:"path"`
	Host string `json:"host"`
	Mode string `json:"mode"`
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
		"tag":         wireTag(tag),
		"listen":      listen,
		"listen_port": info.Common.ServerPort,
	}
	switch info.Type {
	case "shadowsocks":
		node := info.Shadowsocks
		if node == nil {
			return nil, errors.New("shadowsocks node info is missing")
		}
		inbound["type"] = "shadowsocks"
		inbound["method"] = node.Cipher
		if shadowsocksLegacy(node.Cipher) {
			// Users only: each one's password is its UUID, as the other
			// cores do.
			break
		}
		if _, err := shadowsocksKeyLen(node.Cipher); err != nil {
			return nil, err
		}
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
			if transport, ok := inbound["transport"].(map[string]any); ok && transport["type"] != "xhttp" {
				return nil, errors.New("anixcore runs reality only on tcp and xhttp")
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
	case "anytls":
		node := info.AnyTls
		if node == nil {
			return nil, errors.New("anytls node info is missing")
		}
		inbound["type"] = "anytls"
		if err := addTLS(inbound, info, options, true); err != nil {
			return nil, err
		}
		if len(node.PaddingScheme) > 0 {
			inbound["padding_scheme"] = node.PaddingScheme
		}
	case "iwan":
		node := info.Iwan
		if node == nil {
			return nil, errors.New("iwan node info is missing")
		}
		if node.Pool == "" {
			return nil, errors.New("iwan node needs a pool")
		}
		inbound["type"] = "iwan"
		inbound["pool"] = node.Pool
		if node.MTU != 0 {
			inbound["mtu"] = node.MTU
		}
		if node.DNSUpstream != "" {
			inbound["dns_upstream"] = node.DNSUpstream
		}
		if node.AllowEncrypt != nil {
			inbound["allow_encrypt"] = *node.AllowEncrypt
		}
		inbound["allow_client_to_client"] = node.AllowClientToClient
	case "anx":
		node := info.Anx
		if node == nil {
			return nil, errors.New("anx node info is missing")
		}
		names := node.ServerNames
		if len(names) == 0 && !node.AllowNoSNI {
			return nil, errors.New("anx node needs server names")
		}
		key, err := anxKeyFile()
		if err != nil {
			return nil, err
		}
		inbound["type"] = "anx"
		inbound["key_file"] = key
		inbound["server_names"] = names
		if node.Dest != "" {
			inbound["dest"] = node.Dest
		}
		if len(node.ALPN) > 0 {
			inbound["alpn"] = node.ALPN
		}
		// Only when set: anx-node refuses keys it does not know, so a node
		// on an older anx-node keeps working until it uses them.
		if node.AllowNoSNI {
			inbound["allow_no_sni"] = true
		}
		if node.ShapePlain {
			inbound["shape_plain"] = true
		}
		if node.MaxStreams > 0 {
			inbound["max_streams"] = node.MaxStreams
		}
		// The wg jacket listens on its own UDP port, beside the A2 TCP port.
		if node.WGListenPort > 0 {
			inbound["wg_listen_port"] = node.WGListenPort
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

// addTransport sets `transport` for ws, grpc, httpupgrade and xhttp
// networks.
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
	case "httpupgrade":
		var upgrade httpupgradeNetwork
		if len(settings) != 0 {
			if err := json.Unmarshal(settings, &upgrade); err != nil {
				return fmt.Errorf("decode network settings: %w", err)
			}
		}
		path, err := url.Parse(upgrade.Path)
		if err != nil {
			return fmt.Errorf("parse httpupgrade path: %w", err)
		}
		transport := map[string]any{"type": "httpupgrade", "path": path.Path}
		if ed, err := strconv.Atoi(path.Query().Get("ed")); err == nil && ed > 0 {
			transport["max_early_data"] = ed
		}
		if upgrade.Host != "" {
			transport["host"] = upgrade.Host
		}
		inbound["transport"] = transport
		return nil
	case "xhttp", "splithttp":
		var xhttp xhttpNetwork
		if len(settings) != 0 {
			if err := json.Unmarshal(settings, &xhttp); err != nil {
				return fmt.Errorf("decode network settings: %w", err)
			}
		}
		transport := map[string]any{"type": "xhttp", "path": xhttp.Path}
		if xhttp.Host != "" {
			transport["host"] = xhttp.Host
		}
		if xhttp.Mode != "" {
			transport["mode"] = xhttp.Mode
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

// shadowsocksLegacy reports whether cipher is a Shadowsocks AEAD (SIP004)
// method, which anixcore serves with plain user passwords.
func shadowsocksLegacy(cipher string) bool {
	switch cipher {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305":
		return true
	}
	return false
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
		return 0, fmt.Errorf("anixcore does not serve shadowsocks method %q", cipher)
	}
}

// iwanPassword is a panel user's iWAN password: the first 16 hex digits of
// its UUID, since iWAN passwords are at most 16 bytes. anix-control shows
// users the same value; the login name is the panel user id.
func iwanPassword(uuid string) (string, error) {
	digits := strings.ReplaceAll(uuid, "-", "")
	if len(digits) < 16 {
		return "", errors.New("uuid is too short for an iwan password")
	}
	return strings.ToLower(digits[:16]), nil
}

// anxKeyFile is the path of the Agent's anx-server key, which anx-node's
// anx inbound serves with too (the public half is what Control hands to
// clients). The Agent makes it when it first reports to Control, so a node
// that comes up before that fails with this error and is retried.
var anxKeyFile = func() (string, error) {
	path := filepath.Join(conf.DefaultStateRoot, "anx-server", "server.key")
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("anx server key %s is not made yet", path)
	}
	return path, nil
}

// anxUserKey is a panel user's ANX key: HMAC-SHA-256 of a fixed label under
// the lower-case UUID, 64 hex digits. Control derives the same key for the
// anx:// link (anix-control service.ANXUserKey).
func anxUserKey(uuid string) string {
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	if uuid == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(uuid))
	mac.Write([]byte("anx/panel-user-key/v1"))
	return hex.EncodeToString(mac.Sum(nil))
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
	out := apiUser{Name: userName(user), SpeedLimit: max(user.SpeedLimit, 0), DeviceLimit: max(user.DeviceLimit, 0)}
	switch info.Type {
	case "shadowsocks":
		if shadowsocksLegacy(info.Shadowsocks.Cipher) {
			out.Password = user.Uuid
			break
		}
		keyLen, err := shadowsocksKeyLen(info.Shadowsocks.Cipher)
		if err != nil {
			return apiUser{}, err
		}
		if len(user.Uuid) < keyLen {
			return apiUser{}, fmt.Errorf("user %d uuid is too short for a shadowsocks key", user.Id)
		}
		out.Password = base64.StdEncoding.EncodeToString([]byte(user.Uuid[:keyLen]))
	case "trojan", "hysteria2", "anytls":
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
	case "iwan":
		password, err := iwanPassword(user.Uuid)
		if err != nil {
			return apiUser{}, fmt.Errorf("user %d: %w", user.Id, err)
		}
		out.Password = password
		if info.Iwan != nil {
			out.Address = info.Iwan.FixedAddresses[out.Name]
		}
	case "anx":
		password := anxUserKey(user.Uuid)
		if password == "" {
			return apiUser{}, fmt.Errorf("user %d has no uuid for an anx key", user.Id)
		}
		out.Password = password
	default:
		return apiUser{}, fmt.Errorf("anixcore does not serve %q nodes", info.Type)
	}
	return out, nil
}
