package panel

type OnlineUser struct {
	UID int
	IP  string
}

type UserInfo struct {
	Id                    int               `json:"id"`
	Uuid                  string            `json:"uuid"`
	SpeedLimit            int               `json:"speed_limit"`
	DeviceLimit           int               `json:"device_limit"`
	WireGuardPeerIP       string            `json:"wireguard_peer_ip"`
	WireGuardPublicKey    string            `json:"wireguard_public_key"`
	WireGuardPresharedKey string            `json:"wireguard_preshared_key"`
	Extra                 map[string]string `json:"extra"`
}

type UserListBody struct {
	Users []UserInfo `json:"users"`
}

type AliveMap struct {
	Alive map[int]int `json:"alive"`
}

type UserTraffic struct {
	UID      int
	Upload   int64
	Download int64
}
