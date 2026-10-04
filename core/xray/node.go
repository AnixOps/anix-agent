package xray

import (
	"context"
	"fmt"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/conf"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
)

type DNSConfig struct {
	Servers []interface{} `json:"servers"`
	Tag     string        `json:"tag"`
}

func (c *Xray) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	c.nodeReportMinTrafficBytes[tag] = config.ReportMinTraffic * 1024
	err := updateDNSConfig(info)
	if err != nil {
		if c.debugger.IsEnabled() {
			c.debugger.LogError("updateDNSConfig", tag, err)
		}
		return fmt.Errorf("build dns error: %s", err)
	}
	inboundConfig, err := buildInbound(config, info, tag)
	if err != nil {
		if c.debugger.IsEnabled() {
			c.debugger.LogError("buildInbound", tag, err)
		}
		return fmt.Errorf("build inbound error: %s", err)
	}

	// 调试: 记录 Xray 入站配置
	if c.debugger.IsEnabled() {
		c.debugger.LogXrayConfig(tag, map[string]interface{}{
			"node_type":    info.Type,
			"node_id":      info.Id,
			"security":     info.Security,
			"inbound_tag":  tag,
			"inbound_conf": inboundConfig,
		})
	}

	err = c.addInbound(inboundConfig)
	if err != nil {
		if c.debugger.IsEnabled() {
			c.debugger.LogError("addInbound", tag, err)
		}
		return fmt.Errorf("add inbound error: %s", err)
	}

	// 调试: 记录入站添加成功
	if c.debugger.IsEnabled() {
		port := 0
		if info.Common != nil {
			port = info.Common.ServerPort
		}
		c.debugger.LogInboundAdd(tag, info.Type, port, map[string]interface{}{
			"security": info.Security,
		})
	}

	outBoundConfig, err := buildOutbound(config, tag)
	if err != nil {
		if c.debugger.IsEnabled() {
			c.debugger.LogError("buildOutbound", tag, err)
		}
		return fmt.Errorf("build outbound error: %s", err)
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {
		// Leave no inbound behind for a node that is not added.
		_ = c.removeInbound(tag)
		if c.debugger.IsEnabled() {
			c.debugger.LogError("addOutbound", tag, err)
		}
		return fmt.Errorf("add outbound error: %s", err)
	}
	return nil
}

func (c *Xray) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := c.ihm.AddHandler(context.Background(), handler); err != nil {
		// The manager keeps a handler whose Start failed (a port still in
		// use): drop it, or the tag stays taken and no later add of the
		// node, nor of its previous configuration, can succeed.
		if registered, getErr := c.ihm.GetHandler(context.Background(), handler.Tag()); getErr == nil && registered == handler {
			_ = c.ihm.RemoveHandler(context.Background(), handler.Tag())
		}
		return err
	}
	return nil
}

func (c *Xray) addOutbound(config *core.OutboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	if err := c.ohm.AddHandler(context.Background(), handler); err != nil {
		return err
	}
	return nil
}

func (c *Xray) DelNode(tag string) error {
	// 调试: 记录入站移除
	if c.debugger.IsEnabled() {
		c.debugger.LogInboundRemove(tag)
	}

	err := c.removeInbound(tag)
	if err != nil {
		return fmt.Errorf("remove in error: %s", err)
	}
	err = c.removeOutbound(tag)
	if err != nil {
		return fmt.Errorf("remove out error: %s", err)
	}
	return nil
}

func (c *Xray) removeInbound(tag string) error {
	return c.ihm.RemoveHandler(context.Background(), tag)
}

func (c *Xray) removeOutbound(tag string) error {
	err := c.ohm.RemoveHandler(context.Background(), tag)
	return err
}
