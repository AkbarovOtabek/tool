package leaks

import (
	"encoding/json"
	"testing"

	"pentkit/internal/store"
)

func TestParseLeakixProducesFindings(t *testing.T) {
	raw := `{
	  "Leaks": [
	    {"host":"db.bank.uz","port":"9200","event_type":"elasticsearch","summary":"open index with data","time":"2026-01-01","tags":["database","open"],
	     "leak":{"severity":"high","dataset":{"rows":120000}}}
	  ],
	  "Services": [
	    {"host":"bank.uz","port":"443","event_type":"HttpPlugin","summary":"nginx"}
	  ]
	}`
	var r leakixResp
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	n := parseLeakix(st, "bank.uz", r)
	if n != 2 {
		t.Fatalf("ожидалось 2 находки, получено %d", n)
	}
	all := st.All()
	var gotHigh bool
	for _, f := range all {
		if f.Type != store.TypeLeak {
			t.Errorf("тип должен быть leak, получен %s", f.Type)
		}
		if f.Severity == store.SevHigh {
			gotHigh = true
		}
	}
	if !gotHigh {
		t.Error("ожидалась находка high (leak с severity:high)")
	}
}

func TestMapLeakSevDefaultsMedium(t *testing.T) {
	if mapLeakSev("") != store.SevMedium {
		t.Error("пустой severity должен давать medium (факт утечки)")
	}
	if mapLeakSev("critical") != store.SevCritical {
		t.Error("critical не смаппился")
	}
}
