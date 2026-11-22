package conf

import (
	"fmt"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

// Watch reloads the file at path into p when it changes and then calls
// reload. A file that does not load is logged and the running config kept.
func (p *Conf) Watch(path string, reload func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create config watcher: %w", err)
	}
	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return fmt.Errorf("watch config %s: %w", path, err)
	}
	go func() {
		defer watcher.Close()
		var pending <-chan time.Time
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Changes within the wait fold into one reload.
				if event.Op != fsnotify.Chmod && pending == nil {
					pending = time.After(5 * time.Second)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.WithError(err).Error("config watcher")
			case <-pending:
				pending = nil
				// An editor that replaced the file dropped the watch.
				_ = watcher.Add(path)
				next := New()
				if err := next.LoadFromPath(path); err != nil {
					log.WithError(err).Error("reload config failed, keeping the running config")
					continue
				}
				*p = *next
				reload()
			}
		}
	}()
	return nil
}
