package context

import "time"

type Timer struct {
	ticker *time.Ticker
	done   chan bool
}
