package main

import (
	"time"

	"github.com/google/uuid"
	"github.com/valyala/fastjson"
)

// ── Deterministic Event ID (UUID5 from Kafka coordinates) ──────────────────
// Matches Python: uuid5(c71f0000-e1d0-4a6b-b5c3-deadbeef0042, "topic:partition:offset")
var clifEventNS = uuid.Must(uuid.Parse("c71f0000-e1d0-4a6b-b5c3-deadbeef0042"))

var nilUUID = uuid.MustParse("00000000-0000-0000-0000-000000000000")

func deterministicEventID(topic string, partition int32, offset int64) string {
	key := topic + ":" + itoa32(partition) + ":" + itoa64(offset)
	return uuid.NewSHA1(clifEventNS, []byte(key)).String()
}

// ── Topic → Table mapping ──────────────────────────────────────────────────

var topicTableMap = map[string]string{
	"raw-logs":         "raw_logs",
	"security-events":  "security_events",
	"process-events":   "process_events",
	"network-events":   "network_events",
	"triage-scores":    "triage_scores",
	"hunter-results":   "hunter_investigations",
	"verifier-results": "verifier_results",
	"feedback-labels":  "feedback_labels",
}

// inputTables get a deterministic event_id injected from Kafka coordinates
var inputTables = map[string]bool{
	"raw_logs":         true,
	"security_events":  true,
	"process_events":   true,
	"network_events":   true,
}

// ── Table metadata ─────────────────────────────────────────────────────────

type TableMeta struct {
	Columns []string
	Builder func(v *fastjson.Value) []any
}

var tableMeta = map[string]*TableMeta{
	"raw_logs":              {Columns: rawLogsCols, Builder: buildRawLogRow},
	"security_events":       {Columns: securityEventsCols, Builder: buildSecurityEventRow},
	"process_events":        {Columns: processEventsCols, Builder: buildProcessEventRow},
	"network_events":        {Columns: networkEventsCols, Builder: buildNetworkEventRow},
	"triage_scores":         {Columns: triageScoresCols, Builder: buildTriageScoreRow},
	"hunter_investigations": {Columns: hunterInvestigationsCols, Builder: buildHunterInvestigationRow},
	"verifier_results":      {Columns: verifierResultsCols, Builder: buildVerifierResultRow},
	"feedback_labels":       {Columns: feedbackLabelsCols, Builder: buildFeedbackLabelRow},
	"dead_letter_events":    {Columns: deadLetterCols, Builder: nil},
}

// ── Column lists ───────────────────────────────────────────────────────────

var rawLogsCols = []string{
	"event_id", "timestamp", "received_at", "level", "source", "message",
	"metadata", "user_id", "ip_address", "request_id",
	"anchor_tx_id", "anchor_batch_hash",
}

var securityEventsCols = []string{
	"event_id", "timestamp", "severity", "category", "source", "description",
	"user_id", "ip_address", "hostname",
	"mitre_tactic", "mitre_technique", "ai_confidence", "ai_explanation",
	"anchor_tx_id", "metadata",
}

var processEventsCols = []string{
	"event_id", "timestamp", "hostname", "pid", "ppid", "uid", "gid",
	"binary_path", "arguments", "cwd", "exit_code",
	"container_id", "pod_name", "namespace", "syscall",
	"is_suspicious", "detection_rule", "anchor_tx_id", "metadata",
}

var networkEventsCols = []string{
	"event_id", "timestamp", "hostname",
	"src_ip", "src_port", "dst_ip", "dst_port",
	"protocol", "direction", "bytes_sent", "bytes_received", "duration_ms",
	"pid", "binary_path", "container_id", "pod_name", "namespace",
	"dns_query", "geo_country", "is_suspicious", "detection_rule",
	"anchor_tx_id", "metadata",
}

var triageScoresCols = []string{
	"event_id", "timestamp", "source_type", "hostname", "source_ip", "user_id",
	"template_id", "template_rarity",
	"combined_score", "lgbm_score", "eif_score", "arf_score",
	"score_std_dev", "agreement", "ci_lower", "ci_upper",
	"asset_multiplier", "adjusted_score",
	"action", "ioc_match", "ioc_confidence",
	"mitre_tactic", "mitre_technique",
	"shap_top_features", "shap_summary",
	"features_stale", "model_version", "disagreement_flag",
}

var hunterInvestigationsCols = []string{
	"alert_id", "started_at", "completed_at", "status",
	"hostname", "source_ip", "user_id", "trigger_score",
	"severity", "finding_type", "summary", "evidence_json",
	"correlated_events", "mitre_tactics", "mitre_techniques",
	"recommended_action", "confidence",
}

var verifierResultsCols = []string{
	"investigation_id", "alert_id", "started_at", "completed_at", "status",
	"verdict", "confidence", "evidence_verified", "merkle_batch_ids",
	"timeline_json", "ioc_correlations",
	"priority", "recommended_action", "analyst_summary",
	"report_narrative", "evidence_json",
}

var feedbackLabelsCols = []string{
	"event_id", "score_id", "timestamp",
	"label", "confidence", "analyst_id", "notes",
	"original_combined", "original_lgbm", "original_eif", "original_arf",
}

var deadLetterCols = []string{
	"timestamp", "failed_stage", "source_topic",
	"error_message", "raw_payload", "retry_count",
}

// ── Row builders ───────────────────────────────────────────────────────────

func buildRawLogRow(v *fastjson.Value) []any {
	meta := ensureMap(v.Get("metadata"))
	return []any{
		safeUUID(v, "_event_id"),              // event_id
		parseTimestamp(v, "timestamp"),         // timestamp
		time.Now().UTC(),                       // received_at
		safeStr(v, "level", "INFO"),           // level
		safeStr(v, "source", "unknown"),       // source
		safeStr(v, "message", ""),             // message
		meta,                                   // metadata Map(String,String)
		mapStr(meta, "user_id", ""),           // user_id
		safeStrOr(v, "ip_address", mapStr(meta, "ip_address", "0.0.0.0")), // ip_address
		mapStr(meta, "request_id", ""),        // request_id
		"",                                     // anchor_tx_id
		"",                                     // anchor_batch_hash
	}
}

func buildSecurityEventRow(v *fastjson.Value) []any {
	meta := ensureMap(v.Get("metadata"))
	return []any{
		safeUUID(v, "_event_id"),              // event_id
		parseTimestamp(v, "timestamp"),         // timestamp
		safeInt(v, "severity", 0),             // severity
		safeStr(v, "category", "unknown"),     // category
		safeStr(v, "source", "unknown"),       // source
		safeStr(v, "description", ""),         // description
		safeStr(v, "user_id", ""),             // user_id
		safeStr(v, "ip_address", "0.0.0.0"),  // ip_address
		safeStr(v, "hostname", ""),            // hostname
		safeStr(v, "mitre_tactic", ""),        // mitre_tactic
		safeStr(v, "mitre_technique", ""),     // mitre_technique
		safeFloat(v, "ai_confidence", 0.0),    // ai_confidence
		safeStr(v, "ai_explanation", ""),       // ai_explanation
		"",                                     // anchor_tx_id
		meta,                                   // metadata
	}
}

func buildProcessEventRow(v *fastjson.Value) []any {
	meta := ensureMap(v.Get("metadata"))
	return []any{
		safeUUID(v, "_event_id"),              // event_id
		parseTimestamp(v, "timestamp"),         // timestamp
		safeStr(v, "hostname", ""),            // hostname
		safeInt(v, "pid", 0),                  // pid
		safeInt(v, "ppid", 0),                 // ppid
		safeInt(v, "uid", 0),                  // uid
		safeInt(v, "gid", 0),                  // gid
		safeStr(v, "binary_path", ""),         // binary_path
		safeStr(v, "arguments", ""),           // arguments
		safeStr(v, "cwd", ""),                 // cwd
		safeInt(v, "exit_code", -1),           // exit_code
		safeStr(v, "container_id", ""),        // container_id
		safeStr(v, "pod_name", ""),            // pod_name
		safeStr(v, "namespace", ""),           // namespace
		safeStr(v, "syscall", ""),             // syscall
		safeInt(v, "is_suspicious", 0),        // is_suspicious
		safeStr(v, "detection_rule", ""),       // detection_rule
		"",                                     // anchor_tx_id
		meta,                                   // metadata
	}
}

func buildNetworkEventRow(v *fastjson.Value) []any {
	meta := ensureMap(v.Get("metadata"))
	return []any{
		safeUUID(v, "_event_id"),              // event_id
		parseTimestamp(v, "timestamp"),         // timestamp
		safeStr(v, "hostname", ""),            // hostname
		safeStr(v, "src_ip", "0.0.0.0"),      // src_ip
		safeInt(v, "src_port", 0),             // src_port
		safeStr(v, "dst_ip", "0.0.0.0"),      // dst_ip
		safeInt(v, "dst_port", 0),             // dst_port
		safeStr(v, "protocol", "TCP"),         // protocol
		safeStr(v, "direction", "outbound"),   // direction
		safeInt(v, "bytes_sent", 0),           // bytes_sent
		safeInt(v, "bytes_received", 0),       // bytes_received
		safeInt(v, "duration_ms", 0),          // duration_ms
		safeInt(v, "pid", 0),                  // pid
		safeStr(v, "binary_path", ""),         // binary_path
		safeStr(v, "container_id", ""),        // container_id
		safeStr(v, "pod_name", ""),            // pod_name
		safeStr(v, "namespace", ""),           // namespace
		safeStr(v, "dns_query", ""),           // dns_query
		safeStr(v, "geo_country", ""),         // geo_country
		safeInt(v, "is_suspicious", 0),        // is_suspicious
		safeStr(v, "detection_rule", ""),       // detection_rule
		"",                                     // anchor_tx_id
		meta,                                   // metadata
	}
}

func buildTriageScoreRow(v *fastjson.Value) []any {
	// Support both v7 (final_score, label, ae_score, user) and
	// v6 (combined_score, action, eif_score, user_id) field names.
	combinedScore := floatFallback(v, "final_score", "combined_score", 0.0)
	aeOrEif := floatFallback(v, "ae_score", "eif_score", 0.0)
	action := strFallback(v, "label", "action", "discard")
	userID := strFallback(v, "user", "user_id", "")

	return []any{
		safeUUID(v, "event_id"),               // event_id
		parseTimestamp(v, "timestamp"),         // timestamp
		safeStr(v, "source_type", ""),         // source_type
		safeStr(v, "hostname", ""),            // hostname
		safeStr(v, "source_ip", ""),           // source_ip
		userID,                                 // user_id
		safeStr(v, "template_id", ""),         // template_id
		safeFloat(v, "template_rarity", 0.0),  // template_rarity
		combinedScore,                          // combined_score ← v7: final_score
		safeFloat(v, "lgbm_score", 0.0),       // lgbm_score
		aeOrEif,                                // eif_score ← v7: ae_score
		safeFloat(v, "arf_score", 0.0),        // arf_score (v6 only)
		safeFloat(v, "score_std_dev", 0.0),    // score_std_dev (v6 only)
		safeFloat(v, "agreement", 0.0),        // agreement (v6 only)
		safeFloat(v, "ci_lower", 0.0),         // ci_lower (v6 only)
		safeFloat(v, "ci_upper", 0.0),         // ci_upper (v6 only)
		safeFloat(v, "asset_multiplier", 1.0), // asset_multiplier (v6 only)
		combinedScore,                          // adjusted_score ← v7: same as final_score
		action,                                 // action (Enum8) ← v7: label
		safeInt(v, "ioc_match", 0),            // ioc_match
		safeInt(v, "ioc_confidence", 0),       // ioc_confidence
		safeStr(v, "mitre_tactic", ""),        // mitre_tactic
		safeStr(v, "mitre_technique", ""),     // mitre_technique
		safeStr(v, "shap_top_features", ""),   // shap_top_features
		safeStr(v, "shap_summary", ""),        // shap_summary
		safeInt(v, "features_stale", 0),       // features_stale
		safeStr(v, "model_version", ""),       // model_version
		safeInt(v, "disagreement_flag", 0),    // disagreement_flag
	}
}

func buildHunterInvestigationRow(v *fastjson.Value) []any {
	return []any{
		safeUUID(v, "alert_id"),                // alert_id
		parseTimestamp(v, "started_at"),         // started_at
		parseNullableTimestamp(v, "completed_at"), // completed_at (Nullable)
		safeStr(v, "status", "pending"),        // status (Enum8)
		safeStr(v, "hostname", ""),             // hostname
		safeStr(v, "source_ip", ""),            // source_ip
		safeStr(v, "user_id", ""),              // user_id
		safeFloat(v, "trigger_score", 0.0),     // trigger_score
		safeStr(v, "severity", "info"),         // severity (Enum8)
		safeStr(v, "finding_type", ""),         // finding_type
		safeStr(v, "summary", ""),              // summary
		safeStr(v, "evidence_json", ""),        // evidence_json
		safeUUIDArray(v, "correlated_events"),  // correlated_events Array(UUID)
		safeStrArray(v, "mitre_tactics"),        // mitre_tactics Array(String)
		safeStrArray(v, "mitre_techniques"),     // mitre_techniques Array(String)
		safeStr(v, "recommended_action", ""),   // recommended_action
		safeFloat(v, "confidence", 0.0),        // confidence
	}
}

func buildVerifierResultRow(v *fastjson.Value) []any {
	return []any{
		safeUUID(v, "investigation_id"),         // investigation_id
		safeUUID(v, "alert_id"),                 // alert_id
		parseTimestamp(v, "started_at"),          // started_at
		parseNullableTimestamp(v, "completed_at"), // completed_at (Nullable)
		safeStr(v, "status", "pending"),         // status (Enum8)
		safeStr(v, "verdict", "inconclusive"),   // verdict (Enum8)
		safeFloat(v, "confidence", 0.0),          // confidence
		safeInt(v, "evidence_verified", 0),       // evidence_verified
		safeStrArray(v, "merkle_batch_ids"),       // merkle_batch_ids Array(String)
		safeStr(v, "timeline_json", ""),          // timeline_json
		safeStr(v, "ioc_correlations", ""),        // ioc_correlations
		safeStr(v, "priority", "P4"),             // priority (Enum8)
		safeStr(v, "recommended_action", ""),     // recommended_action
		safeStr(v, "analyst_summary", ""),         // analyst_summary
		safeStr(v, "report_narrative", ""),         // report_narrative
		safeStr(v, "evidence_json", ""),            // evidence_json
	}
}

func buildFeedbackLabelRow(v *fastjson.Value) []any {
	return []any{
		safeUUID(v, "event_id"),                 // event_id
		safeNullableUUID(v, "score_id"),         // score_id (Nullable UUID)
		parseTimestamp(v, "timestamp"),           // timestamp
		safeStr(v, "label", "unknown"),          // label (Enum8)
		safeStr(v, "confidence", "medium"),       // confidence (Enum8)
		safeStr(v, "analyst_id", ""),             // analyst_id
		safeStr(v, "notes", ""),                  // notes
		safeFloat(v, "original_combined", 0.0),   // original_combined
		safeFloat(v, "original_lgbm", 0.0),       // original_lgbm
		safeFloat(v, "original_eif", 0.0),        // original_eif
		safeFloat(v, "original_arf", 0.0),        // original_arf
	}
}

// ── JSON extraction helpers ────────────────────────────────────────────────

func safeStr(v *fastjson.Value, key string, def string) string {
	f := v.Get(key)
	if f == nil || f.Type() == fastjson.TypeNull {
		return def
	}
	b, err := f.StringBytes()
	if err != nil {
		// Not a string type — try raw representation
		return f.String()
	}
	return string(b)
}

func safeStrOr(v *fastjson.Value, key string, fallback string) string {
	f := v.Get(key)
	if f == nil || f.Type() == fastjson.TypeNull {
		return fallback
	}
	b, err := f.StringBytes()
	if err != nil {
		return fallback
	}
	s := string(b)
	if s == "" {
		return fallback
	}
	return s
}

func safeInt(v *fastjson.Value, key string, def int64) int64 {
	f := v.Get(key)
	if f == nil || f.Type() == fastjson.TypeNull {
		return def
	}
	n, err := f.Int64()
	if err != nil {
		return def
	}
	return n
}

func safeFloat(v *fastjson.Value, key string, def float64) float64 {
	f := v.Get(key)
	if f == nil || f.Type() == fastjson.TypeNull {
		return def
	}
	n, err := f.Float64()
	if err != nil {
		return def
	}
	return n
}

// floatFallback tries primary key first, then fallback key, then default.
func floatFallback(v *fastjson.Value, primary, fallback string, def float64) float64 {
	if f := v.Get(primary); f != nil && f.Type() != fastjson.TypeNull {
		if n, err := f.Float64(); err == nil {
			return n
		}
	}
	return safeFloat(v, fallback, def)
}

// strFallback tries primary key first, then fallback key, then default.
func strFallback(v *fastjson.Value, primary, fallback string, def string) string {
	if f := v.Get(primary); f != nil && f.Type() != fastjson.TypeNull {
		if b, err := f.StringBytes(); err == nil {
			return string(b)
		}
	}
	return safeStr(v, fallback, def)
}

func safeUUID(v *fastjson.Value, key string) string {
	f := v.Get(key)
	if f == nil || f.Type() == fastjson.TypeNull {
		return nilUUID.String()
	}
	b, err := f.StringBytes()
	if err != nil {
		return nilUUID.String()
	}
	s := string(b)
	if len(s) == 36 && s[8] == '-' {
		return s
	}
	return nilUUID.String()
}

func safeNullableUUID(v *fastjson.Value, key string) *string {
	f := v.Get(key)
	if f == nil || f.Type() == fastjson.TypeNull {
		return nil
	}
	b, err := f.StringBytes()
	if err != nil {
		return nil
	}
	s := string(b)
	if len(s) == 36 && s[8] == '-' {
		return &s
	}
	return nil
}

func parseTimestamp(v *fastjson.Value, key string) time.Time {
	f := v.Get(key)
	if f == nil || f.Type() == fastjson.TypeNull {
		return time.Now().UTC()
	}
	b, err := f.StringBytes()
	if err != nil {
		return time.Now().UTC()
	}
	s := string(b)
	if s == "" {
		return time.Now().UTC()
	}
	// Try common ISO-8601 formats
	for _, layout := range tsLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

var tsLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02T15:04:05Z",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05.000Z",
	"2006-01-02T15:04:05.000000Z",
	"2006-01-02T15:04:05.000000000Z",
}

func parseNullableTimestamp(v *fastjson.Value, key string) *time.Time {
	f := v.Get(key)
	if f == nil || f.Type() == fastjson.TypeNull {
		return nil
	}
	t := parseTimestamp(v, key)
	return &t
}

func ensureMap(v *fastjson.Value) map[string]string {
	m := make(map[string]string)
	if v == nil || v.Type() == fastjson.TypeNull {
		return m
	}
	switch v.Type() {
	case fastjson.TypeObject:
		obj, _ := v.Object()
		obj.Visit(func(k []byte, val *fastjson.Value) {
			if val.Type() == fastjson.TypeString {
				b, _ := val.StringBytes()
				m[string(k)] = string(b)
			} else {
				m[string(k)] = val.String()
			}
		})
	case fastjson.TypeString:
		// JSON-encoded string — try to parse it
		b, err := v.StringBytes()
		if err != nil {
			return m
		}
		inner, err := fastjson.ParseBytes(b)
		if err != nil || inner.Type() != fastjson.TypeObject {
			return m
		}
		obj, _ := inner.Object()
		obj.Visit(func(k []byte, val *fastjson.Value) {
			if val.Type() == fastjson.TypeString {
				sb, _ := val.StringBytes()
				m[string(k)] = string(sb)
			} else {
				m[string(k)] = val.String()
			}
		})
	}
	return m
}

func mapStr(m map[string]string, key string, def string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return def
}

func safeStrArray(v *fastjson.Value, key string) []string {
	f := v.Get(key)
	if f == nil || f.Type() != fastjson.TypeArray {
		return []string{}
	}
	arr, _ := f.Array()
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		if item.Type() == fastjson.TypeString {
			b, _ := item.StringBytes()
			result = append(result, string(b))
		} else {
			result = append(result, item.String())
		}
	}
	return result
}

func safeUUIDArray(v *fastjson.Value, key string) []string {
	f := v.Get(key)
	if f == nil || f.Type() != fastjson.TypeArray {
		return []string{}
	}
	arr, _ := f.Array()
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		if item.Type() == fastjson.TypeString {
			b, _ := item.StringBytes()
			s := string(b)
			if len(s) == 36 && s[8] == '-' {
				result = append(result, s)
			} else {
				result = append(result, nilUUID.String())
			}
		} else {
			result = append(result, nilUUID.String())
		}
	}
	return result
}

// ── Integer-to-string helpers (avoids strconv import in hot path) ──────────

func itoa32(n int32) string {
	return itoa64(int64(n))
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
