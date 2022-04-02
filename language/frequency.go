package language

import (
	"math"
	"strings"
)

type FrequencyHistogram map[rune]float64

// Typical frequencies of single letters in the English language.
//
// Taken from http://www.practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
// Statistics for the space (32) were added manually, using an estimated
// average-word length of 6 letters. This ensures that the search for keys is
// case-sensitive.
var EnglishMonographFrequencies = FrequencyHistogram{
	32:  0.16666666666666666,
	97:  0.09037099672339077,
	98:  0.01691153155057605,
	99:  0.0334002748123877,
	100: 0.04090476693795582,
	101: 0.12789345735123137,
	102: 0.02304196173765987,
	103: 0.02209068808793996,
	104: 0.05242574780678575,
	105: 0.07747595391607652,
	106: 0.0023253355882042067,
	107: 0.008561462847479126,
	108: 0.04449846739245323,
	109: 0.026741359264348376,
	110: 0.07578480076101891,
	111: 0.02187929394355776,
	112: 0.02187929394355776,
	113: 0.0010569707219110032,
	114: 0.0669062466969665,
	115: 0.07113412958461052,
	116: 0.09449318253884367,
	117: 0.028326815347214884,
	118: 0.011203889652256634,
	119: 0.019342564210971358,
	120: 0.002008244371630906,
	121: 0.018179896416869252,
	122: 0.0011626677941021033,
}

// FrequencyAnalysis performs frequency analysis of the passed string. It
// returns a map with relative frequencies of the respective runes.
//
// The passed string is converted to lowercase, but no other normalization
// takes place. Specifically this means that e.g. punctuation marks are also
// included in the output.
func FrequencyAnalysis(s string) FrequencyHistogram {
	freqs := make(FrequencyHistogram)
	runes := []rune(strings.ToLower(s))
	length := float64(len(runes))

	for _, r := range runes {
		freqs[r] += 1
	}

	for k, _ := range freqs {
		freqs[k] /= length
	}

	return freqs
}

// HistogramDifference compares two frequency histograms for similarity.
//
// Comparison is done using the Hellinger distance. Two completely disjoin
// histograms will have a distance of 1, while to equal ones will have a
// distance of 0.
func HistogramDifference(a, b FrequencyHistogram) float64 {
	var dist float64

	// Get union of keys. One day we'll have a generic function for that :)
	keys := make([]rune, 0)
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		keys = append(keys, k)
	}
	keys = unique(keys)

	// Hellinger distance is 1/sqrt(2) * sqrt[SUM{(sqrt(p_i) - sqrt(q_i))^2}]
	for _, k := range keys {
		dist += math.Pow(math.Sqrt(a[k])-math.Sqrt(b[k]), 2)
	}

	dist = 1 / math.Sqrt(2) * math.Sqrt(dist)

	return dist
}

func unique[T comparable](x []T) []T {
	out := make([]T, 0)
	seen := make(map[T]bool)

	for _, v := range x {
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}

	return out
}
