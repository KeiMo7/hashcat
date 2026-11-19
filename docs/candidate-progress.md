# Candidate progress

`--candidate-progress` keeps a record of which candidates a straight attack has
already tried. A later run with the same hashes and base source can use that
record after changing the rule set, so candidates that are already covered do
not have to be generated and hashed again.

The option is off by default. Without it hashcat uses the existing single
rule-set ordering, restore position and rule handling unchanged.

## What identifies a tried candidate

A record names a base range, the dictionary position and the rule context that
was applied to that range. The rule context is the normalized rule command
sequence. It is not the rule file name and it is not the generated candidate
text.

That distinction matters. Two different rules can produce the same candidate
text, but later decoding paths can differ. They therefore remain separate
records and are both tried. The same rule context from two rule files is the
same decode path and is recorded once.

The ledger is also scoped by a signature of the hash mode, target digests,
salts, base source, encoding, wordlist options and the base-side `-j` rule.
Changing the rule set does not invalidate the records. Changing the hashes or
the base word source does, and the run starts from scratch with a warning.
The base source is read once at startup to bind the ledger to its contents, so
an edited wordlist with the same size cannot inherit records from the old one.

## Ordering

With `--candidate-progress`, the run is rule-major:

1. Rule files are read in command-line order.
2. Rules inside a file are read in file order.
3. `--rules-concat` keeps that order as one list.
4. Each rule is tried over the base source in source order before the next rule.

This order is fixed for the run and is also the order in which batch intervals
are appended to the ledger. Without `--rules-concat`, repeated `-r` options
still use the existing chaining behavior, and each chained rule is one context.

## Duplicates

Deduplication is enabled by default when `--candidate-progress` is enabled.
Repeated occurrences of the same normalized rule context are collapsed, and the
first occurrence keeps its position in the generation order.

`--candidate-dedup-disable` keeps every rule occurrence in the current run.
This is for cases where trying a duplicate is preferable to the risk of
missing it. The cost is proportional to the duplicated rule contexts: every
kept duplicate is generated and hashed again. If a candidate identity is
already present in an earlier run's record, candidate progress still skips it,
because retrying it would contradict the resume contract. The switch controls
duplicate rules within the current rule list, not records from earlier runs.

## Files and format

The ledger lives beside the session files:

    <session>.candidate-progress/<run-signature>/<ruleset-signature>/<YYYYMM>.hcp

Partitions are monthly. A resume scans every month partition for the run and
every rule-set directory it finds, because a new rule set may share contexts
with more than one earlier set. Cross-month and cross-rule-set reads are the
expected cost of allowing a rule set to change.

The text format is:

    HCP1 run=<run-signature> source=<source-signature> ruleset=<ruleset-signature> month=<YYYYMM>
    T <sequence> <rule-context> <dict-pos> <start> <end> <count> <checksum>

Each `T` line is one completed batch interval. `start` is inclusive and `end`
is exclusive. `count` is the number of candidate positions in that interval.
The checksum is paw64 over the line before the final space and checksum field.
The sequence number preserves the order in which intervals were appended.

The format records tried candidates, not a rule file offset. A rule-file line
number or a rule index would stop meaning anything as soon as the rule set
changed.

At the end of the rule walk hashcat prints:

    Candidate progress: tried-before=<n> skipped=<n> new=<n> dedup-skipped=<n>

`tried-before` is the coverage the loaded records supplied for the selected
rule contexts. `skipped` is the part of that coverage the run actually removed
from its work. `new` is the number of candidates that reached a completed
batch. `dedup-skipped` is the coverage removed by collapsing duplicate rule
contexts in the current rule list.

## Mismatch and damage

Records are used only when the run and source signatures match and when the
record's rule context exists in the current rule set. Recorded contexts that
are absent from the new rule set are ignored.

If no recorded context matches the current rule set, hashcat says so and starts
from scratch. If a header is invalid, a checksum does not match, a line is
truncated or an unknown record type appears, hashcat reports the damaged file,
discards the run's ledger and starts from scratch. A damaged ledger can cause
duplicate work, but it never removes coverage.

## Cleaning old rule sets

`--candidate-progress-prune` removes rule-set directories for the current run
and source that are not the current rule-set signature. Use it when the old
rule sets are no longer needed and the cross-set scan has become expensive.
It does not remove records belonging to another hash target or base source.

## Limits

The candidate ledger applies to straight attacks whose candidates are base
words amplified by rules. It is not used for mask-only attacks, combinator and
hybrid candidates built from a second source, or `--slow-candidates`. When the
option is given for an unsupported attack, hashcat prints a warning and runs
the attack without candidate progress.

The run needs one base word source. A single dictionary, a directory expanded
to one ordered source list, or a feed that presents its sources as one keyspace
is supported. A queue of dictionaries with different round-local positions is
not, because a record cannot name the same base position across those rounds.

`--candidate-progress` is refused together with `--skip` or `--limit`. Those
options address the original run window, while the ledger addresses the tried
candidate set, and silently applying one as the other would skip the wrong
range.
