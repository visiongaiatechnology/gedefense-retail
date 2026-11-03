package app

import "time"

// systemClock is the production clock. It always reports UTC, because every
// persisted timestamp in GeDefense Retail is UTC and the UI localizes on render.
type systemClock struct{}

// Now implements ports.Clock.
func (systemClock) Now() time.Time { return time.Now().UTC() }
