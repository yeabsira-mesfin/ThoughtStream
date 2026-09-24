# Risk Model

The prioritization score is deliberately simple and explainable.

## Inputs

1. **Scanner severity** establishes a baseline.
2. **CVSS** can raise that baseline when a scanner provides a numeric score.
3. **Internet exposure** adds risk because the attack surface is externally reachable.
4. **Known exploitability** adds risk when a finding has evidence of practical exploitation.

## Baselines

| Severity | Baseline |
| --- | ---: |
| Critical | 85 |
| High | 70 |
| Medium | 50 |
| Low | 25 |
| Info | 5 |

CVSS is converted to a 0 to 100 scale and the higher value is kept. Internet exposure adds 8 points and known exploitability adds 12 points. Scores are capped at 100.

This model is not intended to replace organizational risk analysis. In a production program, additional context could include data classification, business criticality, asset ownership, reachability, EPSS, KEV status, compensating controls, and remediation age.
