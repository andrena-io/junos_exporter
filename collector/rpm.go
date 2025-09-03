package collector

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/Juniper/go-netconf/netconf"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	rpmSubsystem = "rpm"

	rpmProbeLabels = []string{"owner", "test", "target", "source", "interface", "probe_type"}
	rpmDesc        = map[string]*prometheus.Desc{
		// Overall test metrics (counters)
		"ProbesSent":          colPromDesc(rpmSubsystem, "probes_sent_total", "Total number of probes sent", rpmProbeLabels),
		"ProbesReceived":      colPromDesc(rpmSubsystem, "probes_received_total", "Total number of probes received", rpmProbeLabels),
		"ProbeLossPercentage": colPromDesc(rpmSubsystem, "probe_loss_percentage", "Percentage of probes lost", rpmProbeLabels),
		
		// RTT metrics for overall test
		"RTTMin":    colPromDesc(rpmSubsystem, "rtt_min_microseconds", "Minimum round trip time in microseconds", rpmProbeLabels),
		"RTTMax":    colPromDesc(rpmSubsystem, "rtt_max_microseconds", "Maximum round trip time in microseconds", rpmProbeLabels),
		"RTTAvg":    colPromDesc(rpmSubsystem, "rtt_avg_microseconds", "Average round trip time in microseconds", rpmProbeLabels),
		"RTTStddev": colPromDesc(rpmSubsystem, "rtt_stddev_microseconds", "Standard deviation of round trip time in microseconds", rpmProbeLabels),
		
		// Positive jitter metrics for overall test
		"JitterPosMin":    colPromDesc(rpmSubsystem, "jitter_positive_min_microseconds", "Minimum positive jitter in microseconds", rpmProbeLabels),
		"JitterPosMax":    colPromDesc(rpmSubsystem, "jitter_positive_max_microseconds", "Maximum positive jitter in microseconds", rpmProbeLabels),
		"JitterPosAvg":    colPromDesc(rpmSubsystem, "jitter_positive_avg_microseconds", "Average positive jitter in microseconds", rpmProbeLabels),
		"JitterPosStddev": colPromDesc(rpmSubsystem, "jitter_positive_stddev_microseconds", "Standard deviation of positive jitter in microseconds", rpmProbeLabels),
		
		// Negative jitter metrics for overall test
		"JitterNegMin":    colPromDesc(rpmSubsystem, "jitter_negative_min_microseconds", "Minimum negative jitter in microseconds", rpmProbeLabels),
		"JitterNegMax":    colPromDesc(rpmSubsystem, "jitter_negative_max_microseconds", "Maximum negative jitter in microseconds", rpmProbeLabels),
		"JitterNegAvg":    colPromDesc(rpmSubsystem, "jitter_negative_avg_microseconds", "Average negative jitter in microseconds", rpmProbeLabels),
		"JitterNegStddev": colPromDesc(rpmSubsystem, "jitter_negative_stddev_microseconds", "Standard deviation of negative jitter in microseconds", rpmProbeLabels),
		
		// Current test metrics (gauges)
		"CurrentTestProbesSent":     colPromDesc(rpmSubsystem, "current_test_probes_sent", "Number of probes sent in current test", rpmProbeLabels),
		"CurrentTestProbesReceived": colPromDesc(rpmSubsystem, "current_test_probes_received", "Number of probes received in current test", rpmProbeLabels),
		"CurrentTestLossPercentage": colPromDesc(rpmSubsystem, "current_test_loss_percentage", "Loss percentage in current test", rpmProbeLabels),
		
		// Last probe metrics
		"LastRTT":       colPromDesc(rpmSubsystem, "last_rtt_microseconds", "Last probe round trip time in microseconds", rpmProbeLabels),
		"LastJitter":    colPromDesc(rpmSubsystem, "last_jitter_microseconds", "Last probe jitter in microseconds", rpmProbeLabels),
		"LastJitterIAT": colPromDesc(rpmSubsystem, "last_jitter_interarrival_microseconds", "Last probe interarrival jitter in microseconds", rpmProbeLabels),
	}
	totalRPMErrors = 0.0
)

// RPMCollector collects RPM metrics, implemented as per the Collector interface.
type RPMCollector struct {
	logger log.Logger
}

// NewRPMCollector returns a new RPMCollector
func NewRPMCollector(logger log.Logger) *RPMCollector {
	return &RPMCollector{logger: logger}
}

// Name of the collector.
func (*RPMCollector) Name() string {
	return rpmSubsystem
}

// Get metrics and send to the Prometheus.Metric channel.
func (c *RPMCollector) Get(ch chan<- prometheus.Metric, conf Config) ([]error, float64) {
	errors := []error{}
	s, err := netconf.DialSSH(conf.SSHTarget, conf.SSHClientConfig)
	if err != nil {
		totalRPMErrors++
		errors = append(errors, fmt.Errorf("could not connect to %q: %s", conf.SSHTarget, err))
		return errors, totalRPMErrors
	}
	defer s.Close()

	// show services rpm probe-results | display xml
	reply, err := s.Exec(netconf.RawMethod(`<get-probe-results/>`))
	if err != nil {
		totalRPMErrors++
		errors = append(errors, fmt.Errorf("could not execute netconf RPC call: %s", err))
		return errors, totalRPMErrors
	}

	var probeResults probeResultsRPC
	if err := xml.Unmarshal([]byte(reply.Data), &probeResults); err != nil {
		totalRPMErrors++
		errors = append(errors, fmt.Errorf("could not unmarshal probe results: %s", err))
		return errors, totalRPMErrors
	}

	for _, probeResult := range probeResults.ProbeResults.ProbeTestResults {
		labels := []string{
			probeResult.Owner,
			probeResult.TestName,
			probeResult.TargetAddress,
			probeResult.SourceAddress,
			probeResult.DestinationInterface,
			probeResult.ProbeType,
		}

		// Process current test results
		if currentResults := probeResult.ProbeTestCurrentResults; currentResults != nil {
			if currentResults.ProbesSent != "" {
				newGauge(c.logger, ch, rpmDesc["CurrentTestProbesSent"], currentResults.ProbesSent, labels...)
			}
			if currentResults.ProbeResponses != "" {
				newGauge(c.logger, ch, rpmDesc["CurrentTestProbesReceived"], currentResults.ProbeResponses, labels...)
			}
			if currentResults.LossPercentage != "" {
				newGauge(c.logger, ch, rpmDesc["CurrentTestLossPercentage"], currentResults.LossPercentage, labels...)
			}
		}

		// Process global test results
		if globalResults := probeResult.ProbeTestGlobalResults; globalResults != nil {
			// Process the generic results for global test
			if globalResults.ProbeTestGenericResults != nil {
				if globalResults.ProbesSent != "" {
					newCounter(c.logger, ch, rpmDesc["ProbesSent"], globalResults.ProbesSent, labels...)
				}
				if globalResults.ProbeResponses != "" {
					newCounter(c.logger, ch, rpmDesc["ProbesReceived"], globalResults.ProbeResponses, labels...)
				}
				if globalResults.LossPercentage != "" {
					newGauge(c.logger, ch, rpmDesc["ProbeLossPercentage"], globalResults.LossPercentage, labels...)
				}

				// Process RTT and jitter metrics
				c.processGenericResults(ch, globalResults.ProbeTestGenericResults, labels)
			}
		}

		// Process last single probe result
		if len(probeResult.ProbeSingleResults) > 0 {
			lastResult := probeResult.ProbeSingleResults[0]
			if lastResult.ProbeStatus == "Response received" && lastResult.RTT != "" {
				newGauge(c.logger, ch, rpmDesc["LastRTT"], lastResult.RTT, labels...)
			}
			if lastResult.RoundTripJitter != "" {
				newGauge(c.logger, ch, rpmDesc["LastJitter"], lastResult.RoundTripJitter, labels...)
			}
			if lastResult.RoundTripInterarrivalJitter != "" {
				newGauge(c.logger, ch, rpmDesc["LastJitterIAT"], lastResult.RoundTripInterarrivalJitter, labels...)
			}
		}
	}

	return errors, totalRPMErrors
}

func (c *RPMCollector) processGenericResults(ch chan<- prometheus.Metric, genericResults *probeTestGenericResults, labels []string) {
	// Process RTT
	if genericResults.ProbeTestRTT != nil && genericResults.ProbeTestRTT.ProbeSummaryResults != nil {
		rtt := genericResults.ProbeTestRTT.ProbeSummaryResults
		if rtt.MinDelay != "" {
			newGauge(c.logger, ch, rpmDesc["RTTMin"], extractMicroseconds(rtt.MinDelay), labels...)
		}
		if rtt.MaxDelay != "" {
			newGauge(c.logger, ch, rpmDesc["RTTMax"], extractMicroseconds(rtt.MaxDelay), labels...)
		}
		if rtt.AvgDelay != "" {
			newGauge(c.logger, ch, rpmDesc["RTTAvg"], extractMicroseconds(rtt.AvgDelay), labels...)
		}
		if rtt.StddevDelay != "" {
			newGauge(c.logger, ch, rpmDesc["RTTStddev"], extractMicroseconds(rtt.StddevDelay), labels...)
		}
	}

	// Process positive jitter
	if genericResults.ProbeTestPositiveJitter != nil && genericResults.ProbeTestPositiveJitter.ProbeSummaryResults != nil {
		jitter := genericResults.ProbeTestPositiveJitter.ProbeSummaryResults
		if jitter.MinDelay != "" {
			newGauge(c.logger, ch, rpmDesc["JitterPosMin"], extractMicroseconds(jitter.MinDelay), labels...)
		}
		if jitter.MaxDelay != "" {
			newGauge(c.logger, ch, rpmDesc["JitterPosMax"], extractMicroseconds(jitter.MaxDelay), labels...)
		}
		if jitter.AvgDelay != "" {
			newGauge(c.logger, ch, rpmDesc["JitterPosAvg"], extractMicroseconds(jitter.AvgDelay), labels...)
		}
		if jitter.StddevDelay != "" {
			newGauge(c.logger, ch, rpmDesc["JitterPosStddev"], extractMicroseconds(jitter.StddevDelay), labels...)
		}
	}

	// Process negative jitter
	if genericResults.ProbeTestNegativeJitter != nil && genericResults.ProbeTestNegativeJitter.ProbeSummaryResults != nil {
		jitter := genericResults.ProbeTestNegativeJitter.ProbeSummaryResults
		if jitter.MinDelay != "" {
			newGauge(c.logger, ch, rpmDesc["JitterNegMin"], extractMicroseconds(jitter.MinDelay), labels...)
		}
		if jitter.MaxDelay != "" {
			newGauge(c.logger, ch, rpmDesc["JitterNegMax"], extractMicroseconds(jitter.MaxDelay), labels...)
		}
		if jitter.AvgDelay != "" {
			newGauge(c.logger, ch, rpmDesc["JitterNegAvg"], extractMicroseconds(jitter.AvgDelay), labels...)
		}
		if jitter.StddevDelay != "" {
			newGauge(c.logger, ch, rpmDesc["JitterNegStddev"], extractMicroseconds(jitter.StddevDelay), labels...)
		}
	}
}

// extractMicroseconds extracts the numeric value from XML attributes or content
func extractMicroseconds(value string) string {
	// The value comes as just a number since junos:format is an attribute
	return strings.TrimSpace(value)
}

// XML structures based on actual Juniper output
type probeResultsRPC struct {
	ProbeResults probeResults `xml:"probe-results"`
}

type probeResults struct {
	ProbeTestResults []probeTestResult `xml:"probe-test-results"`
}

type probeTestResult struct {
	Owner                      string                      `xml:"owner"`
	TestName                   string                      `xml:"test-name"`
	TargetAddress              string                      `xml:"target-address"`
	SourceAddress              string                      `xml:"source-address"`
	ProbeType                  string                      `xml:"probe-type"`
	DestinationInterface       string                      `xml:"destination-interface"`
	ProbeSingleResults         []probeSingleResult         `xml:"probe-single-results"`
	ProbeTestCurrentResults    *probeTestCurrentResults    `xml:"probe-test-current-results"`
	ProbeTestLastResults       *probeTestLastResults       `xml:"probe-test-last-results"`
	ProbeTestGlobalResults     *probeTestGlobalResults     `xml:"probe-test-global-results"`
}

type probeSingleResult struct {
	ProbeStatus                 string `xml:"probe-status"`
	RTT                         string `xml:"rtt"`
	RoundTripJitter             string `xml:"round-trip-jitter"`
	RoundTripInterarrivalJitter string `xml:"round-trip-interarrival-jitter"`
}

type probeTestCurrentResults struct {
	ProbeTestGenericResults *probeTestGenericResults `xml:"probe-test-generic-results"`
	ProbesSent              string                   `xml:"probes-sent"`
	ProbeResponses          string                   `xml:"probe-responses"`
	LossPercentage          string                   `xml:"loss-percentage"`
}

type probeTestLastResults struct {
	ProbeTestGenericResults *probeTestGenericResults `xml:"probe-test-generic-results"`
}

type probeTestGlobalResults struct {
	ProbeTestGenericResults *probeTestGenericResults `xml:"probe-test-generic-results"`
	ProbesSent              string                   `xml:"probes-sent"`
	ProbeResponses          string                   `xml:"probe-responses"`
	LossPercentage          string                   `xml:"loss-percentage"`
}

type probeTestGenericResults struct {
	ProbeTestRTT             *probeTestMetric `xml:"probe-test-rtt"`
	ProbeTestPositiveJitter  *probeTestMetric `xml:"probe-test-positive-round-trip-jitter"`
	ProbeTestNegativeJitter  *probeTestMetric `xml:"probe-test-negative-round-trip-jitter"`
}

type probeTestMetric struct {
	ProbeSummaryResults *probeSummaryResults `xml:"probe-summary-results"`
}

type probeSummaryResults struct {
	ProbeResultsType string `xml:"probe-results-type"`
	Samples          string `xml:"samples"`
	MinDelay         string `xml:"min-delay"`
	MaxDelay         string `xml:"max-delay"`
	AvgDelay         string `xml:"avg-delay"`
	JitterDelay      string `xml:"jitter-delay"`
	StddevDelay      string `xml:"stddev-delay"`
	SumDelay         string `xml:"sum-delay"`
}