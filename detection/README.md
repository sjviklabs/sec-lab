# Detection Engineering

Detection rules, correlation logic, and alert tuning methodology for the SOC lab.

## Philosophy

Good detection is not about writing the most rules. It is about writing the *right* rules and keeping them honest.

**Defense in depth for alerting** means no single detection layer is trusted alone. Network-level detections miss encrypted C2. Endpoint detections miss living-off-the-land if the binary is trusted. Log-based detections miss what is not logged. Layering these creates overlap where a miss at one layer is caught by another.

**Signal-to-noise ratio** is the metric that matters most. A SOC drowning in false positives is functionally blind -- analysts stop reading alerts, and real threats hide in the noise. Every rule must earn its place. If a rule generates more noise than signal after tuning, it gets removed or rearchitected, not ignored.

**Tuning is continuous.** Detection rules are not write-once artifacts. Environments change, baselines shift, and adversaries adapt. Every rule should have a tuning history: when it was last reviewed, what the false positive rate is, and what adjustments were made.

## Why Sigma

Rules in this repo use the [Sigma](https://github.com/SigmaHQ/sigma) format because:

- **Vendor-neutral:** Sigma rules describe *what* to detect, not *how* in a specific SIEM. They convert to Splunk SPL, Elastic KQL, Microsoft Sentinel, and others via the `sigma-cli` toolchain.
- **Community standard:** The SigmaHQ repository contains thousands of peer-reviewed rules. Writing in the same format means contributing back is trivial and consuming community rules requires no translation.
- **Version-controllable:** YAML files diff cleanly in Git, making rule changes auditable.
- **Testable:** Sigma rules can be validated against log samples before deployment, reducing the "deploy and hope" cycle.

## Structure

```
detection/
├── sigma-rules/          # Individual Sigma detection rules
├── alert-logic/          # Correlation patterns and threshold documentation
└── README.md             # This file
```

## Rule Lifecycle

1. **Draft** -- rule written, not yet tested against real logs
2. **Test** -- deployed in detection-only mode (no alerting), measuring false positive rate
3. **Active** -- alerting enabled, tuned to acceptable noise level
4. **Deprecated** -- superseded or no longer relevant, kept for reference
