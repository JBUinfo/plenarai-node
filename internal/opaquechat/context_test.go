package opaquechat

import (
	"errors"
	"strings"
	"testing"
)

func testExchanges(n, size int) []Exchange {
	out := []Exchange{}
	for i := 1; i <= n; i++ {
		out = append(out, Exchange{N: i, Revision: int64(i), User: strings.Repeat("u", size), Assistant: strings.Repeat("a", size)})
	}
	return out
}
func TestProjectionAlternatesAndKeepsStablePrefix(t *testing.T) {
	p := projection{Constraints: []string{"budget is 80"}, Exchanges: testExchanges(3, 10), Start: 1}
	msgs := buildProjection(p, "next question")
	if len(msgs) != 7 || !strings.HasPrefix(msgs[0].Content, "<plenarai_context>") || !strings.Contains(msgs[0].Content, "- budget is 80") || !strings.Contains(msgs[0].Content, "[#1] ") {
		t.Fatalf("context block missing: %#v", msgs[0])
	}
	for i, m := range msgs {
		if want := map[bool]string{true: "user", false: "assistant"}[i%2 == 0]; m.Role != want {
			t.Fatalf("roles do not alternate at %d: %s", i, m.Role)
		}
	}
	if last := msgs[len(msgs)-1].Content; !strings.HasSuffix(last, "\n\n[#4] next question") || !strings.HasPrefix(last, "<plenarai_context_note>All previous") {
		t.Fatalf("current message framing: %q", last)
	}
	p.Exchanges = append(p.Exchanges, Exchange{N: 4, User: "next question", Assistant: "ok"})
	next := buildProjection(p, "another")
	for i := 0; i < 6; i++ {
		if next[i] != msgs[i] {
			t.Fatalf("prefix changed between turns at message %d", i)
		}
	}
	first := buildProjection(projection{Constraints: []string{"r"}, Start: 1}, "hello")
	if len(first) != 1 || strings.Contains(first[0].Content, "plenarai_context_note") || !strings.HasSuffix(first[0].Content, "</plenarai_context>\n\n[#1] hello") {
		t.Fatalf("first turn framing: %q", first[0].Content)
	}
}
func TestPlanWindowCompactsInStepsAndNeverDropsCurrent(t *testing.T) {
	b, err := computeBudget(Provider{ContextWindowTokens: 4096}, nil)
	if err != nil || b.P != 2612 || b.High != 1959 || b.Low != 1175 {
		t.Fatalf("budget %+v %v", b, err)
	}
	p := projection{Exchanges: testExchanges(5, 150), Start: 1}
	if a, err := planWindow(p, b, afterTurn, ""); err != nil || a != 1 {
		t.Fatalf("compacted below HIGH: %d %v", a, err)
	}
	p.Exchanges = testExchanges(7, 150)
	a, err := planWindow(p, b, afterTurn, "")
	p.Start = a
	if err != nil || a == 1 || b.messages(baseMessages(p)) > b.Low || len(p.Exchanges)-a+1 < 2 {
		t.Fatalf("expected one step down to LOW: start=%d used=%d %v", a, b.messages(baseMessages(p)), err)
	}
	p.Exchanges = testExchanges(8, 150)
	if again, _ := planWindow(p, b, afterTurn, ""); again != a {
		t.Fatalf("window moved again before reaching HIGH: %d -> %d", a, again)
	}
	if _, err = planWindow(p, b, beforeSend, strings.Repeat("x", 3000)); !errors.Is(err, errDoesNotFit) {
		t.Fatalf("oversized current message was not rejected: %v", err)
	}
	many := projection{Constraints: []string{"keep"}, Exchanges: testExchanges(100, 1), Start: 1}
	start, err := planWindow(many, Budget{W: 32768, S: 256, P: 22682, High: 17011, Low: 10206, R: 1}, beforeSend, "q")
	many.Start = start
	msgs := buildProjection(many, "q")
	if err != nil || len(msgs) > maxProjectionMessages || !strings.Contains(msgs[0].Content, "- keep") || !strings.HasSuffix(msgs[len(msgs)-1].Content, "] q") {
		t.Fatalf("message limit or requirements lost: %d %v", len(msgs), err)
	}
}
