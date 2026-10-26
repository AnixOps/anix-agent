package anixcore

import (
	"context"
	"fmt"
	"strconv"

	"github.com/AnixOps/anix-agent/v5/api/panel"
	vCore "github.com/AnixOps/anix-agent/v5/core"
)

func (c *Core) AddUsers(p *vCore.AddUsersParams) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.nodes[p.Tag]
	if !ok {
		return 0, fmt.Errorf("anixcore node %s does not exist", p.Tag)
	}
	users := make([]apiUser, 0, len(p.Users))
	for _, user := range p.Users {
		converted, err := apiUserFor(n.info, user)
		if err != nil {
			return 0, err
		}
		users = append(users, converted)
	}
	if len(users) == 0 {
		return 0, nil
	}
	if !n.created {
		for _, user := range users {
			n.users[user.Name] = user
		}
		if err := c.create(p.Tag, n); err != nil {
			for _, user := range users {
				delete(n.users, user.Name)
			}
			return 0, fmt.Errorf("anixcore node %s: %w", p.Tag, err)
		}
		return len(users), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := c.client.addUsers(ctx, p.Tag, users); err != nil {
		return 0, fmt.Errorf("anixcore node %s: %w", p.Tag, err)
	}
	for _, user := range users {
		n.users[user.Name] = user
	}
	return len(users), nil
}

func (c *Core) DelUsers(users []panel.UserInfo, tag string, _ *panel.NodeInfo) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.nodes[tag]
	if !ok {
		return nil
	}
	names := make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, userName(user))
	}
	if n.created && len(names) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()
		if err := c.client.removeUsers(ctx, tag, names); err != nil {
			return fmt.Errorf("anixcore node %s: %w", tag, err)
		}
	}
	for _, name := range names {
		delete(n.users, name)
	}
	return nil
}

func (c *Core) GetUserTrafficSlice(tag string, reset bool) ([]panel.UserTraffic, error) {
	api, created := c.clientFor(tag)
	if !created {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	traffic, err := api.traffic(ctx, tag, reset)
	if err != nil {
		return nil, fmt.Errorf("anixcore node %s: %w", tag, err)
	}
	slice := make([]panel.UserTraffic, 0, len(traffic))
	for _, entry := range traffic {
		uid, err := strconv.Atoi(entry.Name)
		if err != nil || entry.Up+entry.Down == 0 {
			continue
		}
		slice = append(slice, panel.UserTraffic{UID: uid, Upload: entry.Up, Download: entry.Down})
	}
	if len(slice) == 0 {
		return nil, nil
	}
	return slice, nil
}

func (c *Core) GetOnlineDevice(tag string) ([]panel.OnlineUser, error) {
	api, created := c.clientFor(tag)
	if !created {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	online, err := api.online(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("anixcore node %s: %w", tag, err)
	}
	users := make([]panel.OnlineUser, 0, len(online))
	for _, entry := range online {
		uid, err := strconv.Atoi(entry.Name)
		if err != nil {
			continue
		}
		users = append(users, panel.OnlineUser{UID: uid, IP: entry.IP})
	}
	return users, nil
}

// clientFor returns the API client when tag's inbound exists in anixcore.
func (c *Core) clientFor(tag string) (*client, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.nodes[tag]
	return c.client, ok && n.created
}
