package tests

import (
	"testing"

	"github.com/onyx/internal/consumer"
	"github.com/onyx/internal/detector"
)

func TestOutboundHTTP(t *testing.T) {
	tpl := findTemplate(t, "outbound_http")
	lg := categoryLogger("network")

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		want  bool
	}{
		{
			name:  "positive: net_connect to port 443 (HTTPS)",
			event: newNetEvent("net_connect", "93.184.216.34", 443, "tcp", ""),
			want:  true,
		},
		{
			name:  "positive: net_connect to port 80 (HTTP)",
			event: newNetEvent("net_connect", "93.184.216.34", 80, "tcp", ""),
			want:  true,
		},
		{
			name:  "negative: net_connect to port 5432 (postgres)",
			event: newNetEvent("net_connect", "10.0.0.5", 5432, "tcp", ""),
			want:  false,
		},
		{
			name:  "negative: wrong event type (net_send)",
			event: newNetEvent("net_send", "93.184.216.34", 443, "tcp", "GET"),
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detector.Evaluate(tpl, tc.event, nil)
			lg.Printf("%-50s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUnusualPort(t *testing.T) {
	tpl := findTemplate(t, "unusual_port")
	lg := categoryLogger("network")

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		want  bool
	}{
		{
			name:  "positive: net_connect to port 8888 (unusual)",
			event: newNetEvent("net_connect", "45.33.32.156", 8888, "tcp", ""),
			want:  true,
		},
		{
			name:  "positive: net_connect to port 4444 (unusual)",
			event: newNetEvent("net_connect", "10.0.0.1", 4444, "tcp", ""),
			want:  true,
		},
		{
			name:  "negative: net_connect to port 443 (common)",
			event: newNetEvent("net_connect", "93.184.216.34", 443, "tcp", ""),
			want:  false,
		},
		{
			name:  "negative: net_connect to port 22 (SSH, common)",
			event: newNetEvent("net_connect", "10.0.0.1", 22, "tcp", ""),
			want:  false,
		},
		{
			name:  "negative: net_connect to port 53 (DNS, common)",
			event: newNetEvent("net_connect", "8.8.8.8", 53, "udp", ""),
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detector.Evaluate(tpl, tc.event, nil)
			lg.Printf("%-50s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHTTPPost(t *testing.T) {
	tpl := findTemplate(t, "http_post")
	lg := categoryLogger("network")

	cases := []struct {
		name  string
		event *consumer.EnrichedEvent
		want  bool
	}{
		{
			name:  "positive: net_send with POST",
			event: newNetEvent("net_send", "93.184.216.34", 443, "tcp", "POST"),
			want:  true,
		},
		{
			name:  "negative: net_send with GET",
			event: newNetEvent("net_send", "93.184.216.34", 443, "tcp", "GET"),
			want:  false,
		},
		{
			name:  "negative: net_connect (wrong event type, even with POST-capable port)",
			event: newNetEvent("net_connect", "93.184.216.34", 443, "tcp", ""),
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detector.Evaluate(tpl, tc.event, nil)
			lg.Printf("%-50s got=%-5v want=%-5v", tc.name, got, tc.want)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
