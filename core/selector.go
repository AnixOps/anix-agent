package core

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/conf"
)

type Selector struct {
	cores map[string]Core
	// order is the configuration order of cores: a node that names no
	// core runs on the first one that serves its protocol.
	order []string
	nodes sync.Map
}

func NewSelector(c []conf.CoreConfig) (Core, error) {
	cs := make(map[string]Core, len(c))
	order := make([]string, 0, len(c))
	for _, t := range c {
		f, ok := cores[strings.ToLower(t.Type)]
		if !ok {
			return nil, errors.New("unknown core type: " + t.Type)
		}
		core1, err := f(&t)
		if err != nil {
			return nil, err
		}
		key := t.Name
		if key == "" {
			key = t.Type
		}
		if _, seen := cs[key]; !seen {
			order = append(order, key)
		}
		cs[key] = core1
	}
	return &Selector{
		cores: cs,
		order: order,
	}, nil
}

func (s *Selector) Start() error {
	for i := range s.cores {
		err := s.cores[i].Start()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Selector) Close() error {
	var errs []error
	for i := range s.cores {
		if err := s.cores[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func isSupported(protocol string, protocols []string) bool {
	for i := range protocols {
		if protocol == protocols[i] {
			return true
		}
	}
	return false
}

func (s *Selector) AddNode(tag string, info *panel.NodeInfo, option *conf.Options) error {
	var core Core
	if len(option.CoreName) > 0 {
		// use name to select core
		if c, ok := s.cores[option.CoreName]; ok {
			core = c
		}
	} else {
		// use type to select core: the first in configuration order
		for _, key := range s.order {
			c := s.cores[key]
			if len(option.Core) == 0 {
				if !isSupported(info.Type, c.Protocols()) {
					continue
				}
			} else if option.Core != c.Type() {
				continue
			}
			core = c
			break
		}
	}
	if core == nil {
		return errors.New("the node type is not support")
	}
	if len(option.Core) == 0 {
		option.Core = core.Type()
		err := option.UnmarshalJSON(option.RawOptions)
		if err != nil {
			return fmt.Errorf("unmarshal option error: %s", err)
		}
		option.RawOptions = nil
	}
	err := core.AddNode(tag, info, option)
	if err != nil {
		return err
	}
	s.nodes.Store(tag, core)
	return nil
}

func (s *Selector) DelNode(tag string) error {
	if t, e := s.nodes.Load(tag); e {
		err := t.(Core).DelNode(tag)
		if err != nil {
			return err
		}
		s.nodes.Delete(tag)
		return nil
	}
	return errors.New("the node is not have")
}

func (s *Selector) AddUsers(p *AddUsersParams) (added int, err error) {
	t, e := s.nodes.Load(p.Tag)
	if !e {
		return 0, errors.New("the node is not have")
	}
	return t.(Core).AddUsers(p)
}

func (s *Selector) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	t, e := s.nodes.Load(tag)
	if !e {
		return nil, errors.New("the node is not have")
	}
	return t.(Core).GetUserTrafficSlice(tag, reset)
}

func (s *Selector) GetOnlineDevice(tag string) ([]panel.OnlineUser, error) {
	t, e := s.nodes.Load(tag)
	if !e {
		return nil, errors.New("the node is not have")
	}
	provider, ok := t.(OnlineDeviceProvider)
	if !ok {
		return nil, nil
	}
	return provider.GetOnlineDevice(tag)
}

func (s *Selector) UpdateUserRateLimit(tag, uuid string, speedLimit int) error {
	t, ok := s.nodes.Load(tag)
	if !ok {
		return errors.New("the node is not have")
	}
	updater, ok := t.(RateLimitUpdater)
	if !ok {
		return nil
	}
	return updater.UpdateUserRateLimit(tag, uuid, speedLimit)
}

func (s *Selector) RollbackUserTrafficSlice(tag string, traffic []panel.UserTraffic) error {
	t, ok := s.nodes.Load(tag)
	if !ok {
		return errors.New("the node is not have")
	}
	rollbacker, ok := t.(TrafficRollbacker)
	if !ok {
		return nil
	}
	return rollbacker.RollbackUserTrafficSlice(tag, traffic)
}

func (s *Selector) DelUsers(users []panel.UserInfo, tag string, info *panel.NodeInfo) error {
	t, e := s.nodes.Load(tag)
	if !e {
		return errors.New("the node is not have")
	}
	return t.(Core).DelUsers(users, tag, info)
}

func (s *Selector) Protocols() []string {
	protocols := make([]string, 0)
	for _, key := range s.order {
		protocols = append(protocols, s.cores[key].Protocols()...)
	}
	return protocols
}

func (s *Selector) Type() string {
	t := "Selector("
	var flag bool
	for _, n := range s.order {
		c := s.cores[n]
		if flag {
			t += " "
		} else {
			flag = true
		}
		if len(n) == 0 {
			t += c.Type()
		} else {
			t += n
		}
	}
	t += ")"
	return t
}
