package conf

import (
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

// reloadDelay lets an editor or installer finish writing before the file
// is read; changes within it are taken together.
const reloadDelay = 5 * time.Second

// Watch reloads path into p and calls reload whenever the file changes. A
// file that does not parse is logged and p is left as it is.
func (p *Conf) Watch(path string, reload func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return err
	}
	changed := make(chan struct{}, 1)
	go func() {
		defer watcher.Close()
		for {
			select {
			case e := <-watcher.Events:
				if !e.Has(fsnotify.Chmod) {
					select {
					case changed <- struct{}{}:
					default:
					}
				}
			case err := <-watcher.Errors:
				log.WithError(err).Warn("Config file watcher error")
			}
		}
	}()
	go func() {
		for range changed {
			time.Sleep(reloadDelay)
			// Drop changes made while waiting: this load reads them.
			select {
			case <-changed:
			default:
			}
			next := New()
			if err := next.LoadFromPath(path); err != nil {
				log.WithError(err).Error("Config file changed but does not load; keeping the running config")
				continue
			}
			*p = *next
			log.Info("Config file changed, reloading")
			reload()
		}
	}()
	return nil
}
