# Pre-Installation AI Security Ruleset

Security rules enforced **before** a pre-trained AI model (HuggingFace, Ollama, LM Studio) is permitted to run in the environment. Each rule defines what to check, the severity, and the action to take (BLOCK, WARN, or AUDIT) when the check fails.

## Behavior & Alignment Rules

These rules assess whether a pre-trained model has adequate safety evaluation, alignment testing, and truthfulness benchmarks before it is deployed. Fine-tuning can silently degrade safety alignment — even benign fine-tuning on innocuous datasets has been shown to reduce refusal rates and introduce emergent misalignment. These checks ensure models are behaviorally vetted before production use.

Rules are defined as YAML files in [`rules/behavior-alignment/`](rules/behavior-alignment/).

| Rule ID | Name | Action | Severity | Description |
|---------|------|--------|----------|-------------|
| [AI-BA-001](rules/behavior-alignment/AI-BA-001.yaml) | Fine-tuned with no safety evaluation documentation | **WARN** | MEDIUM | Model is a fine-tuned derivative with no documented safety evaluation (e.g. HarmBench, JailbreakBench, red-teaming). Fine-tuning can degrade alignment and introduce emergent misalignment. |
| [AI-BA-002](rules/behavior-alignment/AI-BA-002.yaml) | Garak attack success rate exceeds 15% threshold | **WARN** | MEDIUM | Model fails baseline behavioral testing — Attack Success Rate (ASR) from NVIDIA Garak exceeds 15% on enterprise probe set. Indicates elevated risk of jailbreaks, prompt injection, or harmful outputs. |
| [AI-BA-003](rules/behavior-alignment/AI-BA-003.yaml) | Behavioral benchmarks not run within last 90 days | **AUDIT** | LOW | No record of HarmBench, JailbreakBench, or equivalent safety benchmarks run for this model within the last 90 days. Periodic re-evaluation is recommended as behavioral risk can change with model updates. |
| [AI-BA-004](rules/behavior-alignment/AI-BA-004.yaml) | TruthfulQA score below peer median for model class | **AUDIT** | LOW | Model scores below peer median on TruthfulQA for its size/class. Indicates higher tendency to generate misinformation or confabulation. |

### Action levels

| Action | Meaning |
|--------|---------|
| **BLOCK** | Installation is denied. Must be remediated before the model can be used. |
| **WARN** | Installation is allowed only with explicit acknowledgment and documented risk acceptance. |
| **AUDIT** | Finding is logged for compliance. No blocking, but appears in reports and audit trails. |

### Framework references

These rules map to established security frameworks:

- **OWASP LLM Top 10**: LLM04:2025 (Data and Model Poisoning), LLM09 (Misinformation)
- **MITRE ATLAS**: AML.T0018 (Backdoor ML Model)
- **NIST AI RMF**: MEASURE 2 (AI risks assessed)
- **EU AI Act**: Article 9 (Risk management)

### Rule schema

Every rule file follows the schema defined in [`schema/rule_schema.json`](schema/rule_schema.json). Required fields: `rule_id`, `name`, `description`, `severity`, `action`, `category`. See any rule YAML for the full structure including `frameworks`, `remediation`, `applicable_platforms`, `check_type`, and `tags`.
