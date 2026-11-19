#!/usr/bin/env python3

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HASHCAT = os.path.join(ROOT, "hashcat")


def run(cwd, session, rules, extra=None):
    profile = os.path.join(cwd, "profile")
    os.makedirs(profile, exist_ok=True)
    cmd = [
        HASHCAT,
        "-D", "1",
        "--force",
        "-m", "0",
        "-a", "0",
        "--potfile-disable",
        "--self-test-disable",
        "--session", session,
        "--profile-dir", profile,
    ]
    if extra:
        cmd.extend(extra)
    cmd.extend([
        os.path.join(cwd, "hash.txt"),
        os.path.join(cwd, "words.txt"),
        "-r", os.path.join(cwd, rules),
    ])
    proc = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout


def summary(output):
    match = re.search(
        r"Candidate progress: tried-before=(\d+) skipped=(\d+) new=(\d+) dedup-skipped=(\d+)",
        output,
    )
    if match is None:
        raise AssertionError("candidate progress summary missing")
    return tuple(int(value) for value in match.groups())


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    if not os.path.isfile(HASHCAT):
        print("build hashcat first", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="hashcat-candidate-progress-") as work:
        with open(os.path.join(work, "words.txt"), "w", encoding="ascii") as fp:
            fp.write("alpha\nbeta\ngamma\n")
        with open(os.path.join(work, "r1.rule"), "w", encoding="ascii") as fp:
            fp.write("$1\n$2\n")
        with open(os.path.join(work, "r2.rule"), "w", encoding="ascii") as fp:
            fp.write("$2\n$3\n")
        target = hashlib.md5(b"beta3").hexdigest()
        with open(os.path.join(work, "hash.txt"), "w", encoding="ascii") as fp:
            fp.write(target + "\n")

        rc1, out1 = run(work, "switch", "r1.rule", ["--candidate-progress"])
        check(rc1 == 1, "first rule set should exhaust")
        check(summary(out1) == (0, 0, 6, 0), "first rule set should try six candidates")

        rc2, out2 = run(work, "switch", "r2.rule", ["--candidate-progress"])
        check(rc2 == 0, "second rule set should crack")
        check(summary(out2) == (3, 3, 3, 0), "second rule set should skip the shared rule")
        check("Recovered........: 1/1" in out2, "second rule set did not recover the target")

        rc3, out3 = run(work, "plain", "r2.rule")
        check(rc3 == 0, "uninterrupted run should crack")
        check("Recovered........: 1/1" in out3, "uninterrupted run did not recover the target")

        rc4, _ = run(work, "source", "r1.rule", ["--candidate-progress"])
        check(rc4 == 1, "source binding setup should exhaust")
        with open(os.path.join(work, "words.txt"), "r+b") as fp:
            fp.seek(0)
            fp.write(b"alphA")
        rc5, out5 = run(work, "source", "r1.rule", ["--candidate-progress"])
        check(rc5 == 1, "changed source should exhaust")
        check(summary(out5) == (0, 0, 6, 0), "changed source inherited records")

        partitions = []
        for base, _, files in os.walk(os.path.join(work, "profile", "sessions", "switch.candidate-progress")):
            partitions.extend(os.path.join(base, name) for name in files if name.endswith(".hcp"))
        check(partitions, "candidate progress wrote no partition")

        seq = []
        intervals = {}
        for path in sorted(partitions):
            file_seq = []
            with open(path, "r", encoding="ascii") as fp:
                for line in fp:
                    if line.startswith("T "):
                        fields = line.split()
                        value = int(fields[1])
                        seq.append(value)
                        file_seq.append(value)
                        intervals.setdefault(fields[2], []).append((int(fields[4]), int(fields[5])))
            check(file_seq == sorted(file_seq), "batch order is not monotonic inside " + path)
        check(len(seq) == len(set(seq)), "batch sequence numbers are not unique across runs")
        for rule_id, spans in intervals.items():
            spans.sort()
            covered = 0
            last = 0
            for start, end in spans:
                check(start >= last, "batch ranges overlap for " + rule_id)
                covered += end - start
                last = end
            check((spans[0][0], covered) == (0, 3), "recorded range is incomplete for " + rule_id)

        print("candidate progress switch test passed")
        print("first run:  tried-before=0 skipped=0 new=6")
        print("second run: tried-before=3 skipped=3 new=3, recovered 1/1")

    return 0


if __name__ == "__main__":
    sys.exit(main())
