# CTI-REALM: SABER and Inspect Native

SABER uses the same standard **25- and 50-sample datasets** as the
[Inspect-native implementation](https://github.com/UKGovernmentBEIS/inspect_evals/tree/a89ec031839514d91ed9679f00900c2847934f74/src/inspect_evals/cti_realm).
The 25-sample set is a subset of the 50, giving 50 unique scenarios.
The main differences are how agents run and how their work is scored and reported.

## Standardized agents

Inspect native constructs its own CTI-REALM ReAct agent. SABER instead uses the
same shared React, GitHub Copilot and Claude Code integrations used by other
SABER domains.

We keep this separation so that cross-domain comparisons use a consistent
agent implementation rather than benchmark-specific agent tuning. The domain
provides its tasks and tools; the shared harness provides agent execution.
Standardization does not mean every domain has identical tools or budgets.

## Fine-grained checkpoint scoring

Both implementations use the C0-C4 rubric: CTI research, MITRE techniques,
data exploration, query iteration and detection quality.

Inspect native returns these components together in one score dictionary.
SABER registers them as independently reported checkpoint strategies and
combines them into `saber_overall`. This follows the scoring conventions of
other SABER domains and makes it easier to identify where an agent succeeds
or struggles, rather than relying only on its final score.

Scoring examines recorded tool calls and responses, relevant assistant
text/reasoning, and the final submission. It is not simply a count of tool calls.
The headline weights match, but some evidence-selection and failure-handling
rules differ, so the two implementations need not produce identical scores.

## No extra checkpoint coaching

SABER's checkpoints observe the agent's work; they do not guide it through a
required sequence or feed checkpoint scores back to help it finish the task.
The agent receives the detection objective, basic task/output instructions and
tool descriptions, without extra checkpoint hints, scoring weights or ground-truth
answers. Judge prompts are separate from the evaluated agent's instructions.

The shared harness still supplies its normal execution and completion behavior.
Upstream's standard variant is also minimally guided; its optional seeded-memory
variant adds guidance that is not part of this SABER domain.

## Execution differences

- **Budgets:** SABER's default is 70 tool calls; Inspect native defaults to
  70 messages. These are different units, not equivalent limits.
- **Completion:** SABER retains its shared harness's final-answer behavior;
  Inspect-native ReAct uses an explicit submit tool.
- **Infrastructure:** SABER integrates domain tools and services with its shared
  sandbox lifecycle. Inspect native manages shared Kusto and host-side tools
  alongside a networkless code sandbox.

We retain the SABER integration for consistent operation and maintainability
across domains, not to reproduce every detail of Inspect-native execution.
Results should therefore be described as **CTI-REALM evaluated with SABER's
harness and scoring**, rather than treated as interchangeable upstream scores.

See the [domain README](README.md) for usage and scoring details.
