package normalize

import (
	"time"

	"github.com/menta2k/siem-v2/backend/internal/normalize/schema"
)

// Bounds on how far an event time may sit from our own receipt time before we
// stop trusting it. These are deliberately wide: the goal is to catch a broken
// or misconfigured clock, not to police ordinary delivery lag. Logpush in
// particular publishes no maximum delay for standard delivery.
const (
	maxFutureSkew = 24 * time.Hour
	maxPastSkew   = 30 * 24 * time.Hour
	// skewNotable is the point at which skew is worth showing an analyst. Below
	// this, clocks disagree by amounts that never affect interpretation.
	skewNotable = time.Second
)

// AssessTime classifies an event's timestamp against our receipt time and
// returns the quality verdict plus the observed skew in milliseconds.
//
// It never alters the reported time. A provider clock that is wrong is a fact
// about the environment that an analyst needs to see; silently correcting it
// would hide a real misconfiguration and make two systems' logs agree when they
// genuinely do not (FR-013).
func AssessTime(eventTime, receivedAt time.Time) (schema.TimeQuality, int64) {
	if eventTime.IsZero() {
		return schema.TimeQualityImplausible, 0
	}
	delta := receivedAt.Sub(eventTime)
	skewMS := delta.Milliseconds()

	switch {
	case delta < -maxFutureSkew:
		// An event claiming to happen well after we received it cannot be right.
		return schema.TimeQualityImplausible, skewMS
	case delta > maxPastSkew:
		return schema.TimeQualityImplausible, skewMS
	case delta < -skewNotable:
		return schema.TimeQualitySkewed, skewMS
	default:
		return schema.TimeQualityOK, skewMS
	}
}

// ApplyTimeQuality records the assessment on an event, adding the matching
// quality flag so the condition is visible in the UI (FR-070).
func ApplyTimeQuality(e *schema.Event) {
	q, skew := AssessTime(e.EventTime, e.ReceivedAt)
	e.TimeQuality = q
	e.ClockSkewMS = skew
	switch q {
	case schema.TimeQualitySkewed:
		e.AddFlag(schema.FlagClockSkew)
	case schema.TimeQualityImplausible:
		e.AddFlag(schema.FlagImplausibleTime)
	}
}
