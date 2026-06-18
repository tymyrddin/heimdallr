"""heimdallr UI: the Flask surface over the OpenSearch + Sigma detection range.

Mental model: bundles are data, rules are logic, findings are output. The spine is
the Run object (heimdallr-runs / heimdallr-findings); the pages are views over it.
"""