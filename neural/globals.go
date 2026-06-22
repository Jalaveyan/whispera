package neural

import (
	"os"
)

var nativeEngine *NativeMLEngine
var globalDataCollector *DataCollector

func SetMLServerURL(url, token string) {
	if url != "" {
		os.Setenv("WHISPERA_ML_SERVER", url)
		if globalDataCollector != nil {
			globalDataCollector.SetMLServer(url, token)
		}
	}
}

func init() {
	modelDir := os.Getenv("WHISPERA_ML_MODEL_DIR")
	if modelDir == "" {
		modelDir = "./ml_models"
	}
	nativeEngine = NewNativeMLEngine(modelDir)

	dataDir := os.Getenv("WHISPERA_ML_DATA_DIR")
	if dataDir == "" {
		dataDir = "./ml_data"
	}
	globalDataCollector = NewDataCollector(10000, dataDir)
}

func GetNativeEngine() *NativeMLEngine {
	return nativeEngine
}
