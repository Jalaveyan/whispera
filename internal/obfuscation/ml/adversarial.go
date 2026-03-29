package ml

// adversarial.go — black-box adversarial perturbation engine.
//
// Идея: использовать локальную суррогатную модель (NativeMLEngine) как оракул
// вместо реального DPI. Генерировать минимальные изменения пакета (budget байт),
// которые снижают уверенность суррогата в VPN-классификации.
// По принципу transferability эти же изменения снижают уверенность реального DPI.
//
// Алгоритм:
//  1. Оцениваем чувствительность каждого байта (finite-difference grad estimate)
//  2. Жадно меняем байты с наибольшим влиянием (one-byte attack style)
//  3. Ограничиваем изменения безопасной зоной (trailing padding, не payload)

import (
	"math"
	"sort"
	"sync"
)

const (
	// adversarialConfTarget — целевой порог DPI confidence. Если суррогат уже ниже него, не трогаем пакет.
	adversarialConfTarget = 0.45
	// adversarialBudgetDefault — максимум байт для изменения по умолчанию.
	adversarialBudgetDefault = 12
	// adversarialMinLen — не трогаем пакеты меньше этого размера.
	adversarialMinLen = 32
	// adversarialSafeZoneFrac — доля пакета с конца, считающаяся «безопасной» для изменений (padding-область).
	adversarialSafeZoneFrac = 0.35
)

// AdversarialEngine применяет black-box adversarial perturbations с суррогатной моделью.
type AdversarialEngine struct {
	engine  *NativeMLEngine
	mu      sync.Mutex
	enabled int32 // 1 = включён (atomic, пока не нужен — используем enabled bool)
	Enabled bool
}

// NewAdversarialEngine создаёт движок, использующий переданный NativeMLEngine как оракул.
func NewAdversarialEngine(engine *NativeMLEngine) *AdversarialEngine {
	return &AdversarialEngine{engine: engine, Enabled: true}
}

// PerturbPacket применяет adversarial perturbation к пакету data с бюджетом budget байт.
// Если движок выключен или пакет слишком мал — возвращает data без изменений.
// Применяет изменения только к «безопасной зоне» (последние adversarialSafeZoneFrac байт).
func (ae *AdversarialEngine) PerturbPacket(data []byte, budget int) []byte {
	if !ae.Enabled || ae.engine == nil || len(data) < adversarialMinLen {
		return data
	}
	if budget <= 0 {
		budget = adversarialBudgetDefault
	}

	// Текущая DPI-уверенность суррогата
	conf := ae.dpiConf(data)
	if conf < adversarialConfTarget {
		// Суррогат уже не уверен — не трогаем
		return data
	}

	// Безопасная зона: последние N байт (обычно padding, не крипто-payload)
	safeStart := int(float64(len(data)) * (1.0 - adversarialSafeZoneFrac))
	if safeStart < adversarialMinLen {
		safeStart = adversarialMinLen
	}
	if safeStart >= len(data) {
		return data
	}

	// Оцениваем чувствительность байт в безопасной зоне
	sensitivity := ae.estimateSensitivity(data, safeStart)

	// Жадный поиск: меняем байты с наибольшим влиянием на DPI confidence
	result := ae.greedyFlip(data, safeStart, sensitivity, budget, conf)
	return result
}

// dpiConf возвращает DPI-уверенность суррогата для данных data.
func (ae *AdversarialEngine) dpiConf(data []byte) float64 {
	resp := ae.engine.Predict(data, "tcp", "outbound")
	if resp == nil || len(resp.Predictions) == 0 {
		return 0
	}
	p := resp.Predictions[0]
	if p.DPIType <= 0 {
		return 0
	}
	return p.Confidence
}

type byteCandidate struct {
	pos  int
	gain float64 // насколько снижается DPI-уверенность при изменении этого байта
}

// estimateSensitivity вычисляет finite-difference градиент по байтам в безопасной зоне.
// Возвращает слайс length = (len(data) - safeStart), где каждый элемент = gain от flip.
func (ae *AdversarialEngine) estimateSensitivity(data []byte, safeStart int) []byteCandidate {
	baseConf := ae.dpiConf(data)
	n := len(data) - safeStart
	candidates := make([]byteCandidate, 0, n)

	// Для экономии вычислений сэмплируем: каждый 3-й байт
	step := 1
	if n > 60 {
		step = 3
	}

	probe := make([]byte, len(data))
	copy(probe, data)

	for i := 0; i < n; i += step {
		pos := safeStart + i
		orig := probe[pos]
		// Пробуем XOR с 0xFF (инверсия) — максимальное отклонение
		probe[pos] = orig ^ 0xFF
		newConf := ae.dpiConf(probe)
		gain := baseConf - newConf
		if gain > 0 {
			candidates = append(candidates, byteCandidate{pos: pos, gain: gain})
		}
		probe[pos] = orig
	}

	// Сортируем по убыванию gain
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].gain > candidates[j].gain
	})
	return candidates
}

// greedyFlip жадно меняет байты пока DPI-уверенность не упадёт ниже цели или бюджет не исчерпан.
func (ae *AdversarialEngine) greedyFlip(
	data []byte,
	safeStart int,
	candidates []byteCandidate,
	budget int,
	initialConf float64,
) []byte {
	if len(candidates) == 0 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)
	currentConf := initialConf
	changed := 0

	for _, c := range candidates {
		if changed >= budget {
			break
		}
		if currentConf < adversarialConfTarget {
			break
		}
		// Применяем flip и проверяем реальный эффект
		orig := result[c.pos]
		result[c.pos] = orig ^ 0xFF
		newConf := ae.dpiConf(result)
		if newConf < currentConf {
			currentConf = newConf
			changed++
		} else {
			// Откат — этот байт не помог
			result[c.pos] = orig
		}
	}

	return result
}

// entropyOfSlice — вспомогательная функция для оценки энтропии участка.
func entropyOfSlice(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	e := 0.0
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}

// PerturbEntropy снижает энтропию хвоста пакета, заменяя случайные байты
// структурированными (printable ASCII). Это снижает вероятность срабатывания
// entropy-based DPI-сигнатур.
func (ae *AdversarialEngine) PerturbEntropy(data []byte, targetEntropy float64) []byte {
	if len(data) < adversarialMinLen {
		return data
	}
	safeStart := int(float64(len(data)) * (1.0 - adversarialSafeZoneFrac))
	if safeStart >= len(data) {
		return data
	}
	current := entropyOfSlice(data[safeStart:])
	if current <= targetEntropy {
		return data
	}
	result := make([]byte, len(data))
	copy(result, data)
	// Заменяем байты с высокой «редкостью» на пробелы/буквы
	printable := []byte("                abcdefghijklmnopqrstuvwxyz0123456789")
	for i := safeStart; i < len(result); i++ {
		result[i] = printable[int(result[i])%len(printable)]
		if entropyOfSlice(result[safeStart:]) <= targetEntropy {
			break
		}
	}
	return result
}

// globalAdversarialEngine — синглтон, инициализируется при первом вызове GetAdversarialEngine.
var (
	globalAdversarialOnce   sync.Once
	globalAdversarialEngine *AdversarialEngine
)

// GetAdversarialEngine возвращает глобальный экземпляр AdversarialEngine.
func GetAdversarialEngine() *AdversarialEngine {
	globalAdversarialOnce.Do(func() {
		globalAdversarialEngine = NewAdversarialEngine(nativeEngine)
	})
	return globalAdversarialEngine
}
