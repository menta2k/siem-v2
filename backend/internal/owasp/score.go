package owasp

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// crsAnomalyScoreVar is the TX variable that carries the CRS inbound anomaly
// total.
//
// This is not the variable most people expect. Verification item V1 established
// empirically that under CRS 4, TX:anomaly_score reads 0 and
// TX:inbound_anomaly_score is empty, while TX:blocking_inbound_anomaly_score
// holds the real total. Coraza offers no typed accessor for it, so this constant
// and the test that pins it are the whole contract.
const crsAnomalyScoreVar = "blocking_inbound_anomaly_score"

// anomalyScoreFrom reads the CRS inbound anomaly score from a finished
// transaction. The second return distinguishes "scored zero" from "no score
// found", because FR-035 requires us to say when a result is incomplete rather
// than report a misleading zero.
func anomalyScoreFrom(state plugintypes.TransactionState) (int, bool) {
	values := state.Variables().TX().Get(crsAnomalyScoreVar)
	if len(values) == 0 {
		return 0, false
	}
	score, err := strconv.Atoi(values[0])
	if err != nil {
		return 0, false
	}
	return score, true
}
