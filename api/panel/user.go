package panel

// UserInfo is one user of a node.
type UserInfo struct {
	Id                    int               `json:"id"`
	Uuid                  string            `json:"uuid"`
	SpeedLimit            int               `json:"speed_limit"` // Mbps
	DeviceLimit           int               `json:"device_limit"`
	WireGuardPeerIP       string            `json:"wireguard_peer_ip"`
	WireGuardPublicKey    string            `json:"wireguard_public_key"`
	WireGuardPresharedKey string            `json:"wireguard_preshared_key"`
	Extra                 map[string]string `json:"extra"`
}

// UserTraffic is the traffic of one user since the last report.
type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}

// OnlineUser is a user connected from IP.
type OnlineUser struct {
	UID int
	IP  string
}
