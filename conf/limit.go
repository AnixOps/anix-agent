package conf

// LimitConfig is a node's local speed limits.
type LimitConfig struct {
	// SpeedLimit is in Mbps; 0 is no limit.
	SpeedLimit              int                      `json:"SpeedLimit"`
	EnableDynamicSpeedLimit bool                     `json:"EnableDynamicSpeedLimit"`
	DynamicSpeedLimitConfig *DynamicSpeedLimitConfig `json:"DynamicSpeedLimitConfig"`
}

// DynamicSpeedLimitConfig limits a user who used more than Traffic within
// Periodic to SpeedLimit for ExpireTime.
type DynamicSpeedLimitConfig struct {
	Periodic   int   `json:"Periodic"`   // seconds
	Traffic    int64 `json:"Traffic"`    // bytes
	SpeedLimit int   `json:"SpeedLimit"` // Mbps
	ExpireTime int   `json:"ExpireTime"` // minutes
}
