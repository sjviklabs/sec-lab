# Threshold vs. Anomaly Detection

When to use static thresholds and when to use baseline-driven anomaly detection.

## Static Thresholds

A fixed value that fires when crossed. Simple, predictable, easy to explain.

**Use thresholds when:**
- The behavior has a clear "never normal" boundary (e.g., 50 failed logins in 5 minutes)
- The baseline is stable and well-understood
- You need deterministic, reproducible alerts (compliance, audit)
- False positive tuning is straightforward (adjust the number)

**Examples:**
| Rule | Threshold | Rationale |
|------|-----------|-----------|
| Failed logins from single IP | > 10 in 10 min | Legitimate users mistype 1-3 times, not 10 |
| Outbound data transfer | > 500 MB to single external IP in 1 hour | Normal uploads are small; bulk transfer is unusual |
| Account lockouts | > 3 in 1 hour for same account | Indicates brute force or misconfigured integration |
| New admin accounts created | > 0 outside change window | Admin account creation should always be planned |

**Strengths:** Transparent, debuggable, no training period, no math.
**Weakness:** Cannot adapt. A threshold set for Monday traffic will false-positive on Friday's batch jobs, or miss a slow-and-low attack that stays just under the line.

## Anomaly / Baseline Detection

Compare current behavior against a learned baseline. Fires on deviation, not a fixed number.

**Use anomaly detection when:**
- "Normal" varies by time of day, day of week, or user role
- You are looking for unknown-unknowns (novel attack patterns)
- The volume or pattern of activity matters more than any single event
- Static thresholds would require constant manual tuning

**Examples:**
| Rule | Baseline | Deviation |
|------|----------|-----------|
| User login hours | User typically logs in 08:00-18:00 weekdays | Login at 03:00 on a Saturday |
| DNS query volume per host | Host averages 200 queries/hour | Spike to 5,000 queries/hour (possible DNS tunneling) |
| Process execution on server | Server runs 12 known processes | New process `nc.exe` appears for the first time |
| Data access per user | User accesses 10-20 files/day | User accesses 500 files in 2 hours |

**Strengths:** Adapts to environment, catches slow attacks, surfaces things you did not think to write a rule for.
**Weakness:** Requires training period, produces opaque alerts ("this is unusual" is not actionable by itself), baselines drift, seasonal changes cause false positives.

## The Practical Answer

Use both. They cover different gaps.

- **Thresholds** are your guardrails -- hard limits that should never be crossed regardless of context.
- **Anomalies** are your peripheral vision -- surfacing things that are unusual enough to warrant a look.

Layer them: a threshold catches the brute force spray, the anomaly catches the single successful login from a country the user has never visited. Neither alone is sufficient.

**One rule of thumb:** If you can define "bad" with a number, use a threshold. If you can only define "weird compared to normal," use anomaly detection. If you cannot define either, you do not understand the data well enough to alert on it yet -- start with dashboards and manual review.
