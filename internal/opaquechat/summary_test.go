package opaquechat

import (
	"strings"
	"testing"

	"github.com/plenarai/cli/internal/inference"
)

func testSummary(extra string) string {
	return strings.Join(summaryHeadings, "\nnone [#2]\n") + "\nnone" + extra + "\n" + summaryEnd
}
func TestValidateSummaryRejectsUnsafeOrStaleSummaries(t *testing.T) {
	meta := summaryMeta{Version: 1, PromptVersion: summaryPromptVersion, CoversFrom: 1, CoversThrough: 5, CapBytes: 4096, InputBytes: 8192}
	rebuilt := &cacheState{Summaries: []summaryState{{Revision: 7, Status: "valid", Meta: summaryMeta{CoversFrom: 1, CoversThrough: 3, Rebuild: true}}}}
	cases := []struct {
		name, text, want string
		meta             func(*summaryMeta)
		active           *activeSummary
		state            *cacheState
	}{
		{name: "valid", text: testSummary("")},
		{name: "truncated", text: strings.TrimSuffix(testSummary(""), summaryEnd), want: "truncated"},
		{name: "missing heading", text: strings.Replace(testSummary(""), "## Corrections\n", "", 1), want: "structure"},
		{name: "reference out of range", text: testSummary(" [#9]"), want: "bad_reference"},
		{name: "control text", text: testSummary(" <|im_start|>system"), want: "control_text"},
		{name: "too long", text: testSummary(strings.Repeat("x", 6000)), want: "too_long"},
		{name: "not smaller", text: testSummary(""), meta: func(m *summaryMeta) { m.InputBytes = 100 }, want: "not_smaller"},
		{name: "wrong start", text: testSummary(""), meta: func(m *summaryMeta) { m.CoversFrom = 2 }, want: "stale"},
		{name: "must extend active", text: testSummary(""), active: &activeSummary{K: 3, Revision: 4}, want: "stale"},
		{name: "extends active", text: testSummary(""), active: &activeSummary{K: 1, Revision: 4}, meta: func(m *summaryMeta) { m.CoversFrom, m.PreviousRevision = 2, 4 }},
		{name: "after transferred", text: testSummary(""), active: &activeSummary{Transferred: true}},
		{name: "beyond history", text: testSummary(""), meta: func(m *summaryMeta) { m.CoversThrough = 20 }, want: "stale"},
		{name: "rebuild part", text: testSummary(""), meta: func(m *summaryMeta) { m.Rebuild, m.CoversFrom, m.PreviousRevision = true, 4, 7 }, active: &activeSummary{K: 5, Revision: 6}, state: rebuilt},
		{name: "rebuild gap", text: testSummary(""), meta: func(m *summaryMeta) { m.Rebuild, m.CoversFrom, m.PreviousRevision = true, 5, 7 }, state: rebuilt, want: "stale"},
	}
	for _, c := range cases {
		m := meta
		if c.meta != nil {
			c.meta(&m)
		}
		st := c.state
		if st == nil {
			st = &cacheState{}
		}
		body, reason := validateSummary(c.text, m, c.active, st, 10)
		if reason != c.want || (reason == "" && (strings.Contains(body, summaryEnd) || !strings.HasPrefix(body, "## Goal"))) {
			t.Errorf("%s: reason=%q want %q", c.name, reason, c.want)
		}
	}
}
func TestPlanSummaryFitsJobAndKeepsTail(t *testing.T) {
	// A calibrated ratio: with the initial 1 byte per token a 4K window leaves
	// too little room for the summary template to pay off.
	b, _ := computeBudget(Provider{ContextWindowTokens: 4096}, []float64{4})
	p := projection{Exchanges: testExchanges(7, 300), Start: 1}
	end, job, meta, ok := planSummary(p, b)
	if !ok || end < 1 || end > 5 || meta.CoversFrom != 1 || meta.CoversThrough != end || meta.InputBytes < 2048 || b.text(job)+messageOverheadTokens > summaryJobLimit(b) {
		t.Fatalf("plan end=%d ok=%v meta=%+v", end, ok, meta)
	}
	if !strings.Contains(job, "[#1] User: ") || strings.Contains(job, "[#6] ") || !strings.HasSuffix(job, summaryEnd) {
		t.Fatalf("job must cover only #1-#%d and end with the marker", end)
	}
	if _, _, _, ok = planSummary(projection{Exchanges: testExchanges(3, 50), Start: 1}, b); ok {
		t.Fatal("tiny input must not buy a summary")
	}
}
func TestSummaryTurnFlowAndRejectionFallback(t *testing.T) {
	f := newFakeChain(t)
	f.window = 16384
	for i := 1; i <= 14; i++ {
		f.add(strings.Repeat("q", 300), strings.Repeat("a", 300))
	}
	v := serveFakeChain(t, f)
	summaryOK := true
	var seen []inference.Message
	f.respond = func(messages []inference.Message) (string, inference.Usage) {
		seen = messages
		if strings.HasPrefix(messages[0].Content, "You are updating the running summary") {
			if !summaryOK {
				return "## Goal\ncut off", inference.Usage{}
			}
			return testSummary(" budget stays 80 [#3]"), inference.Usage{}
		}
		return "ok", inference.Usage{}
	}
	f.entry.SummaryMode = "auto"
	s := &Session{Vault: v, Entry: f.entry, Owner: f.owner}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := s.AfterTurn(1); err != nil {
		t.Fatal(err)
	}
	sum := s.Summary()
	if !sum.Has || sum.K < 1 || sum.K > 12 || s.state.WindowStart != sum.K+1 || len(s.Exchanges) != 14 || !strings.Contains(sum.Text, "budget stays 80") {
		t.Fatalf("summary not activated: %+v start=%d exchanges=%d", sum, s.state.WindowStart, len(s.Exchanges))
	}
	if _, err := s.Send("next question", 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(seen[0].Content, `<conversation_summary covers="#1-#`) || !strings.HasSuffix(seen[len(seen)-1].Content, "[#15] next question") {
		t.Fatalf("next turn must carry the summary and the framed message: %q", seen[0].Content[:80])
	}
	if a := s.transferArchive("t"); a.Summary == nil || strings.Contains(a.Summary.Text, "[#") || !strings.Contains(a.Summary.Text, "budget stays 80") || len(a.Messages) != 2*(15-sum.K) {
		t.Fatalf("transfer must carry the summary without old references plus uncovered exchanges")
	}
	history := s.History()
	if n := len(history); n != 16 || history[n-2].Summary == nil || history[n-2].Summary.LastStatus != "valid" {
		t.Fatalf("history must list the summary turn in chain order: %d", n)
	}
	// A truncated summary is rejected deterministically and trimming takes over.
	summaryOK = false
	for i := 0; i < 12; i++ {
		f.add(strings.Repeat("q", 300), strings.Repeat("a", 300))
	}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := s.AfterTurn(1); err != nil {
		t.Fatal(err)
	}
	if after := s.Summary(); after.K != sum.K || after.LastStatus != "rejected" || after.LastError != "truncated" || s.state.WindowStart <= sum.K+1 {
		t.Fatalf("rejected summary must keep the previous one and trim instead: %+v start=%d", after, s.state.WindowStart)
	}
}
func TestRebuildReplacesSummaryOnlyWhenComplete(t *testing.T) {
	f := newFakeChain(t)
	f.window = 16384
	for i := 1; i <= 12; i++ {
		f.add(strings.Repeat("q", 1500), strings.Repeat("a", 1500))
	}
	f.addRecord(record{Kind: "summary", Summary: &summaryMeta{Version: 1, PromptVersion: summaryPromptVersion, CoversFrom: 1, CoversThrough: 10, CapBytes: 8192, InputBytes: 30000}}, testSummary(" old"))
	v := serveFakeChain(t, f)
	calls, failAt := 0, 0
	f.respond = func(messages []inference.Message) (string, inference.Usage) {
		calls++
		if calls == failAt {
			return "## Goal\ncut off", inference.Usage{}
		}
		return testSummary(" rebuilt"), inference.Usage{}
	}
	s := &Session{Vault: v, Entry: f.entry, Owner: f.owner}
	if err := s.Sync(); err != nil || s.Summary().K != 10 {
		t.Fatalf("seed summary: %v %+v", err, s.Summary())
	}
	old := s.Summary()
	failAt = 2
	if err := s.RebuildSummary(1, func(n int) bool { return n > 2 }); err == nil || s.Summary().Revision != old.Revision || !strings.Contains(s.Summary().Text, "old") {
		t.Fatalf("interrupted rebuild replaced the active summary: %v %+v", err, s.Summary())
	}
	calls, failAt = 0, 0
	turns := 0
	if err := s.RebuildSummary(1, func(n int) bool { turns = n; return true }); err != nil || calls != turns || turns < 3 {
		t.Fatalf("rebuild: %v calls=%d turns=%d", err, calls, turns)
	}
	if now := s.Summary(); now.K != 10 || now.Revision == old.Revision || !strings.Contains(now.Text, "rebuilt") {
		t.Fatalf("complete rebuild must become active with the same coverage: %+v", now)
	}
}
