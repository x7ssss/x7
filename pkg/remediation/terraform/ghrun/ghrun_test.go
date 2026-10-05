package ghrun

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunClassify(t *testing.T) {
	tests := []struct {
		name string
		run  Run
		want State
	}{
		{"cancelled", Run{Status: "completed", Conclusion: "cancelled"}, Terminal},
		{"timed_out", Run{Status: "completed", Conclusion: "timed_out"}, Terminal},
		{"failure", Run{Status: "completed", Conclusion: "failure"}, Terminal},
		{"conclusion only", Run{Conclusion: "failure"}, Terminal},
		{"in_progress", Run{Status: "in_progress"}, Active},
		{"queued", Run{Status: "queued"}, Active},
		{"waiting", Run{Status: "waiting"}, Active},
		{"unknown fails safe", Run{Status: "weird"}, Active},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.run.Classify(); got != tt.want {
				t.Errorf("Classify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing auth header")
		}
		switch r.URL.Path {
		case "/repos/o/r/actions/runs/1":
			w.Write([]byte(`{"status":"completed","conclusion":"cancelled"}`))
		case "/repos/o/r/actions/runs/2":
			w.Write([]byte(`{"status":"in_progress","conclusion":null}`))
		case "/repos/o/r/actions/runs/3":
			w.Write([]byte(`not json`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := &Checker{BaseURL: srv.URL + "/", Token: "tok"}

	run, err := c.GetRun(context.Background(), "o/r", "1")
	if err != nil || run.Classify() != Terminal {
		t.Fatalf("run 1: %+v %v", run, err)
	}
	run, err = c.GetRun(context.Background(), "o/r", "2")
	if err != nil || run.Classify() != Active {
		t.Fatalf("run 2: %+v %v", run, err)
	}
	if _, err = c.GetRun(context.Background(), "o/r", "3"); err == nil {
		t.Error("expected decode error")
	}
	if _, err = c.GetRun(context.Background(), "o/r", "404"); err == nil {
		t.Error("expected HTTP error")
	}
	if _, err = c.GetRun(context.Background(), "", "1"); err == nil {
		t.Error("expected missing-arg error")
	}
}
