// detector.go — YAML-template-driven risk scorer.
//
// Rules are no longer hardcoded Go closures. Instead, each rule is a YAML
// file under the onyx-templates directory. The Detector loads all templates at
// startup via the templates package, then evaluates them against each event
// using engine.Evaluate().
//
// Risk score guide (unchanged from v1):
//
//	0–20   informational
//	21–50  low risk     (model loading, outbound HTTP)
//	51–75  medium risk  (download+exec, sensitive file)
//	76–100 high risk    (ssh key access, self-modification)
//	101+   critical     (multiple high-risk patterns in same session)
package detector

import (
	"fmt"
	"slices"

	"github.com/onyx/internal/consumer"
	"github.com/onyx/internal/correlator"
	tmpl "github.com/onyx/internal/templates"
	"go.uber.org/zap"
)

// Detector holds the loaded template set and evaluates them per event.
type Detector struct {
	templates []tmpl.Template
	logger    *zap.Logger
}

// New loads all YAML templates from templatesDir and returns a ready Detector.
// Returns an error if the directory is missing or any template fails to parse.
func New(logger *zap.Logger, templatesDir string) (*Detector, error) {
	templates, err := tmpl.Load(templatesDir)
	if err != nil {
		return nil, fmt.Errorf("detector: loading templates from %q: %w", templatesDir, err)
	}

	logger.Info("detection templates loaded",
		zap.Int("count", len(templates)),
		zap.String("dir", templatesDir),
	)

	return &Detector{templates: templates, logger: logger}, nil
}

// Analyze runs every loaded template against ev and its session.
// When a template fires it:
//   - appends the template ID to ev.Tags (deduplicated)
//   - adds info.risk-score to ev.RiskScore
//   - applies the same tag and score to the session
//
// Returns ev for chaining.
func (d *Detector) Analyze(ev *consumer.EnrichedEvent, sess *correlator.Session) *consumer.EnrichedEvent {
	for i := range d.templates {
		t := &d.templates[i]

		if !Evaluate(t, ev, sess) {
			continue
		}

		// Template fired — apply tag, score, and named rule record.
		if !slices.Contains(ev.Tags, t.ID) {
			ev.Tags = append(ev.Tags, t.ID)
		}
		ev.RiskScore += t.Info.RiskScore
		ev.MatchedRules = append(ev.MatchedRules, consumer.MatchedRule{
			ID:       t.ID,
			Name:     t.Info.Name,
			Severity: t.Info.Severity,
		})

		if sess != nil {
			sess.Lock()
			sess.Tag(t.ID)
			sess.RiskScore += t.Info.RiskScore
			sess.Unlock()
		}

		d.logger.Debug("template matched",
			zap.String("id", t.ID),
			zap.String("severity", t.Info.Severity),
			zap.Int("risk_score", t.Info.RiskScore),
			zap.Uint32("pid", ev.Pid),
			zap.String("comm", ev.Comm),
			zap.String("session", ev.AISessionID),
		)
	}
	return ev
}
