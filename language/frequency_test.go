package language

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFrequencyAnalysis(t *testing.T) {
	s := "Hello world, how are you on this wonderful day"
	asserted := FrequencyHistogram{
		104: 0.06521739130434782,
		101: 0.06521739130434782,
		108: 0.08695652173913043,
		111: 0.13043478260869565,
		32:  0.17391304347826086,
		119: 0.06521739130434782,
		114: 0.06521739130434782,
		100: 0.06521739130434782,
		44:  0.021739130434782608,
		97:  0.043478260869565216,
		121: 0.043478260869565216,
		117: 0.043478260869565216,
		110: 0.043478260869565216,
		116: 0.021739130434782608,
		105: 0.021739130434782608,
		115: 0.021739130434782608,
		102: 0.021739130434782608,
	}
	out := FrequencyAnalysis(s)
	assert.Equal(t, asserted, out)
}

func TestHistogramDifference(t *testing.T) {
	a := FrequencyHistogram{
		2:  0.3,
		5:  0.1,
		20: 0.2,
		23: 0.25,
		40: 0.05,
		90: 0.1,
	}

	b := FrequencyHistogram{
		2:  0.0,
		95: 0.5,
		97: 0.5,
	}

	c := FrequencyHistogram{
		2:   0.15,
		20:  0.35,
		23:  0.30,
		90:  0.15,
		100: 0.05,
	}

	assert.Equal(t, 0.0, HistogramDifference(a, a))
	assert.Equal(t, 1.0, HistogramDifference(a, b))
	assert.Equal(t, 0.35631035439043124, HistogramDifference(a, c))
}
