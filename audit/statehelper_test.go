package audit

import (
	"os"
	"strconv"
)

// writeRawStateForTest 直接覆盖消费进度位点，用于构造崩溃窗口。
func writeRawStateForTest(path string, seq int64) error {
	return os.WriteFile(path,
		[]byte("{\"committed_seq\":"+strconv.FormatInt(seq, 10)+"}\n"), 0o644)
}
