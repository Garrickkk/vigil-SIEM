# rules/

Custom Wazuh detection rules and decoders go here, next.

The plan:

1. Run the [attack scenarios](../docs/attack-scenarios.md) against default
   Wazuh and fill in the *Observed* column of the
   [comparison](../docs/comparison.md).
2. For each gap (sudo command content, `usermod -aG sudo`, generic web
   login brute force, sensitive-file probes, cross-source correlation…),
   write a rule here, starting from Trellis's 20 rules.
3. Every rule ships with a sample log line and the rule ID it should
   trigger, checked with `wazuh-logtest` inside the manager container.

Custom rule IDs use the 100000–109999 range, so they never collide with
Wazuh's built-in ruleset.
