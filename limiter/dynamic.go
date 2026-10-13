package limiter

import (
	"time"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	"github.com/AnixOps/anix-agent/v5/common/format"
)

func (l *Limiter) AddDynamicSpeedLimit(tag string, userInfo *panel.UserInfo, limitNum int, expire int64) error {
	userLimit := &UserLimitInfo{
		DynamicSpeedLimit: mbpsToBytesPerSecond(limitNum),
		ExpireTime:        time.Now().Add(time.Duration(expire) * time.Second).Unix(),
	}
	l.UserLimitInfo.Store(format.UserTag(tag, userInfo.Uuid), userLimit)
	return nil
}

func mbpsToBytesPerSecond(mbps int) int {
	if mbps <= 0 {
		return 0
	}
	return int((int64(mbps) * 1000000) / 8)
}

// GetUserSpeedLimit returns the currently effective bytes-per-second limit, including the
// node limit and any unexpired dynamic penalty. Expired dynamic limits are
// cleared here so protocol cores can converge back to the user's base rate.
func (l *Limiter) GetUserSpeedLimit(tag, uuid string) int {
	if l == nil {
		return 0
	}
	userLimit := 0
	if value, ok := l.UserLimitInfo.Load(format.UserTag(tag, uuid)); ok {
		info := value.(*UserLimitInfo)
		if info.ExpireTime != 0 && info.ExpireTime <= time.Now().Unix() {
			info.DynamicSpeedLimit = 0
			info.ExpireTime = 0
		}
		userLimit = determineSpeedLimit(info.SpeedLimit, info.DynamicSpeedLimit)
	}
	return determineSpeedLimit(l.SpeedLimit, userLimit)
}

// determineSpeedLimit returns the minimum non-zero rate
func determineSpeedLimit(limit1, limit2 int) (limit int) {
	if limit1 == 0 || limit2 == 0 {
		if limit1 > limit2 {
			return limit1
		} else if limit1 < limit2 {
			return limit2
		} else {
			return 0
		}
	} else {
		if limit1 > limit2 {
			return limit2
		} else if limit1 < limit2 {
			return limit1
		} else {
			return limit1
		}
	}
}
