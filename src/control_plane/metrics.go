package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricMitigationLevel = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shield_mitigation_level",
		Help: "Current mitigation level (0-5)",
	})
	metricCPUUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shield_cpu_usage",
		Help: "Current CPU usage percentage",
	})
	metricRAMUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shield_ram_usage",
		Help: "Current RAM usage percentage",
	})
	metricMapUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shield_map_usage",
		Help: "Highest BPF Map usage percentage",
	})
	metricQueueDropRatio = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shield_queue_drop_ratio",
		Help: "NIC Queue Drop Ratio (0.0 to 1.0)",
	})
	metricRxRingPressure = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shield_rx_ring_pressure",
		Help: "AF_XDP RX Ring Fill Percentage",
	})
	metricTxRingPressure = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shield_tx_ring_pressure",
		Help: "AF_XDP TX Ring Fill Percentage",
	})
	metricFillRingPressure = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shield_fill_ring_pressure",
		Help: "AF_XDP UMEM Fill Ring Fill Percentage",
	})
	metricCompRingPressure = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shield_completion_ring_pressure",
		Help: "AF_XDP UMEM Completion Ring Fill Percentage",
	})
	metricScanBudget = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shield_scan_budget",
		Help: "Current Adaptive Scan Budget",
	})
	metricSurvivalActivations = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shield_survival_activations",
		Help: "Number of times Survival mode was engaged",
	})
)
