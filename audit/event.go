package audit

import (
	"bytes"
	"encoding/json"
	"time"
)

// Source 标识事件来源。只有登记过的来源才允许接入。
type Source string

// Verdict 是规则路由对事件给出的结论。
type Verdict string

const (
	VerdictAllow   Verdict = "allow"
	VerdictDeny    Verdict = "deny"
	VerdictFlag    Verdict = "flag"
	VerdictNoMatch Verdict = "no_match"
)

// 单事件内容的附加护栏，防止属性表被滥用。
const (
	MaxEventIDLen     = 256
	MaxAttrEntries    = 100
	MaxAttrKeyBytes   = 256
	MaxAttrValueBytes = 4096
)

// Event 是规范化后的审计事件。敏感字段（SourceIP/Email）与普通
// 属性分开存放，便于查询侧按权限投影。
type Event struct {
	ID         string            `json:"id"`
	Source     Source            `json:"source"`
	Type       string            `json:"type"`
	OccurredAt time.Time         `json:"occurred_at"`
	Actor      string            `json:"actor,omitempty"`
	Action     string            `json:"action,omitempty"`
	Resource   string            `json:"resource,omitempty"`
	SourceIP   string            `json:"source_ip,omitempty"`
	Email      string            `json:"email,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// ParseEvent 解析原始字节并执行入站校验。拒绝原因严格区分：
//   - 整体或字段超限 → CodeOversized
//   - 非合法 JSON     → CodeFormat
//   - 必填项缺失/空值 → CodeMissingField
//   - 来源未登记     → CodeUnknownSource
//
// 任何拒绝都显式返回原因码，绝不静默丢弃。
func ParseEvent(raw []byte, maxBytes int, knownSources map[Source]struct{}) (*Event, *Error) {
	if maxBytes > 0 && len(raw) > maxBytes {
		return nil, newError(CodeOversized, "payload",
			"event payload exceeds limit", nil)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, newError(CodeFormat, "payload", "empty payload", nil)
	}
	var ev Event
	dec := json.NewDecoder(bytes.NewReader(raw))
	// 不允许尾随内容，避免把多条 JSON / 垃圾输入悄悄接受。
	if err := dec.Decode(&ev); err != nil {
		return nil, newError(CodeFormat, "payload", "invalid JSON", err)
	}
	if dec.More() {
		return nil, newError(CodeFormat, "payload", "multiple JSON values", nil)
	}
	if err := ev.Validate(knownSources); err != nil {
		return nil, err
	}
	return &ev, nil
}

// Validate 校验已结构化事件的必填字段、长度护栏与来源登记。
func (e *Event) Validate(knownSources map[Source]struct{}) *Error {
	if e == nil {
		return newError(CodeMissingField, "event", "nil event", nil)
	}
	if e.ID == "" {
		return newError(CodeMissingField, "id", "event id is required", nil)
	}
	if len(e.ID) > MaxEventIDLen {
		return newError(CodeOversized, "id", "event id too long", nil)
	}
	if e.Source == "" {
		return newError(CodeMissingField, "source", "source is required", nil)
	}
	if knownSources != nil {
		if _, ok := knownSources[e.Source]; !ok {
			return newError(CodeUnknownSource, "source",
				"source is not registered", nil)
		}
	}
	if e.Type == "" {
		return newError(CodeMissingField, "type", "type is required", nil)
	}
	if e.OccurredAt.IsZero() {
		return newError(CodeMissingField, "occurred_at",
			"occurred_at is required", nil)
	}
	if len(e.Attributes) > MaxAttrEntries {
		return newError(CodeOversized, "attributes",
			"too many attribute entries", nil)
	}
	for k, v := range e.Attributes {
		if len(k) > MaxAttrKeyBytes {
			return newError(CodeOversized, "attributes."+k,
				"attribute key too long", nil)
		}
		if len(v) > MaxAttrValueBytes {
			return newError(CodeOversized, "attributes."+k,
				"attribute value too long", nil)
		}
	}
	return nil
}
