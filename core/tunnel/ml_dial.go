package tunnel

import (
	"context"
	"whispera/neural"
)

func (m *Manager) pickServer(ctx context.Context) string { return m.ml.pickServer(ctx) }

func (m *Manager) runWeightSnapshotLoop() { m.ml.runWeightSnapshotLoop() }

func (m *Manager) ExportMLWeights() *neural.WeightSnapshot { return m.ml.exportWeights() }

func (m *Manager) ImportMLWeights(snap *neural.WeightSnapshot) { m.ml.importWeights(snap) }
