package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// BatchID 批次标识，按创建顺序单调、可排序：B-000001 形式。
type BatchID string

// Decision 是一条事件的完整判定记录，随批次持久化，
// 其中包含策略版本与判定依据，保证事后可解释、可复现。
type Decision struct {
	Seq           int64         `json:"seq"`
	EventID       string        `json:"event_id"`
	Source        Source        `json:"source"`
	Type          string        `json:"type"`
	OccurredAt    time.Time     `json:"occurred_at"`
	EvaluatedAt   time.Time     `json:"evaluated_at"`
	PolicyVersion PolicyVersion `json:"policy_version"`
	Matched       bool          `json:"matched"`
	RuleID        RuleID        `json:"rule_id,omitempty"`
	Verdict       Verdict       `json:"verdict"`
	Basis         string        `json:"basis"`
	Event         Event         `json:"event"`
	Batch         BatchID       `json:"batch"`
}

// Manifest 描述一个批次文件的元数据。批次文件以
// “临时文件写完 + 原子改名”发布；改名之前目录里不存在该批次名，
// 查询只读已改名文件，因此轮转期间绝不会看到半截批次。
type Manifest struct {
	ID             BatchID         `json:"id"`
	File           string          `json:"file"`
	CreatedAt      time.Time       `json:"created_at"`
	SealedAt       time.Time       `json:"sealed_at,omitempty"`
	Sealed         bool            `json:"sealed"`
	Count          int             `json:"count"`
	MinSeq         int64           `json:"min_seq"`
	MaxSeq         int64           `json:"max_seq"`
	SizeBytes      int64           `json:"size_bytes"`
	PolicyVersions []PolicyVersion `json:"policy_versions,omitempty"`
}

// manifestEnvelope 是批次文件最后一行的封存标记。
// 它与 Decision 形状完全不同，靠显式标记字段区分。
type manifestEnvelope struct {
	Manifest  bool     `json:"_manifest"`
	Manifest_ Manifest `json:"manifest"`
}

// MarshalDecision 将一条判定编码为单行 JSON。
func MarshalDecision(d Decision) ([]byte, error) {
	return json.Marshal(d)
}

// WriteManifestFooter 把封存清单追加为批次文件最后一行。
func WriteManifestFooter(w io.Writer, m Manifest) error {
	env := manifestEnvelope{Manifest: true, Manifest_: m}
	line, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_, err = w.Write(append(line, '\n'))
	return err
}

// ReadBatchFile 读取一个已封存批次文件，返回其中的决策与清单。
// 若缺少清单尾或内容损坏，显式返回错误，由调用方按内部失败处理。
func ReadBatchFile(path string) ([]Decision, Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, Manifest{}, err
	}
	defer f.Close()
	return readBatch(f)
}

func readBatch(r io.Reader) ([]Decision, Manifest, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var decisions []Decision
	var manifest *Manifest
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var probe struct {
			Manifest bool `json:"_manifest"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return nil, Manifest{}, err
		}
		if probe.Manifest {
			var env manifestEnvelope
			if err := json.Unmarshal(line, &env); err != nil {
				return nil, Manifest{}, err
			}
			m := env.Manifest_
			manifest = &m
			continue
		}
		var d Decision
		if err := json.Unmarshal(line, &d); err != nil {
			return nil, Manifest{}, err
		}
		decisions = append(decisions, d)
	}
	if err := sc.Err(); err != nil {
		return nil, Manifest{}, err
	}
	if manifest == nil {
		return nil, Manifest{}, errors.New("batch file is not sealed: manifest footer missing")
	}
	if manifest.Count != len(decisions) {
		return nil, Manifest{}, errors.New("batch manifest count mismatch")
	}
	return decisions, *manifest, nil
}

// ParseBatchSeq 从批次标识解析序号，用于确定下一个批次号。
func ParseBatchSeq(id BatchID) (int64, bool) {
	s := string(id)
	if !strings.HasPrefix(s, "B-") {
		return 0, false
	}
	var n int64
	for i := 2; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	if len(s) == 2 {
		return 0, false
	}
	return n, true
}
