"""RQ3 (EvalPlus): Profile AI vs human implementations at scaled inputs.

Loads data/corpus/evalplus_ai.jsonl (produced by generate_evalplus_ai.py),
runs each implementation at multiple input sizes, measures wall time, and
runs VibeGuard static analysis on AI code to detect performance smells.

Results are saved to results/energy_evalplus/:
  rq3_evalplus_raw.csv      — per-sample × per-size timing rows
  rq3_evalplus_summary.csv  — per-task mean AI vs human wall time + ratio
  rq3_evalplus_findings.csv — VibeGuard findings on AI code
  summary.json              — aggregate stats + Mann-Whitney test

Usage:
    python -m experiments.rq3_evalplus_profile
    python -m experiments.rq3_evalplus_profile --corpus data/corpus/evalplus_ai.jsonl --runs 7
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from corpus.schema import CorpusSample

# ---------------------------------------------------------------------------
# Input generators for each selected task
# Each entry: sizes to test, and a function (n, rng) -> tuple of args
# Keep quadratic-risk tasks at smaller n to avoid multi-minute hangs
# ---------------------------------------------------------------------------
def _floats(n, rng): return [rng.uniform(0, 1000) for _ in range(n)]
def _ints(n, rng):   return [rng.randint(-1000, 1000) for _ in range(n)]
def _pos_ints(n, rng): return [rng.randint(1, 10000) for _ in range(n)]
def _ints_dups(n, rng): return [rng.randint(0, max(1, n // 4)) for _ in range(n)]
def _mixed_ints(n, rng): return [rng.randint(-100, 100) for _ in range(n)]
def _alpha_string(n, rng):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "".join(rng.choice(chars) for _ in range(n))
def _string_list(n, rng):
    prefixes = ["alpha", "beta", "gamma", "delta", "epsilon"]
    return [rng.choice(prefixes) + str(i) for i in range(n)]

INPUT_SCALERS: dict[str, dict] = {
    # Quadratic-risk: AI may write O(n²) pairwise comparison
    "HumanEval/0": {
        "sizes": [300, 700, 1500, 3000],
        "args_fn": lambda n, rng: (_floats(n, rng), 0.5),
    },
    # Linear but potential multi-pass vs single-pass
    "HumanEval/4": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_floats(n, rng),),
    },
    # String-concat smell: += in loop vs join
    "HumanEval/5": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_ints(n, rng), 0),
    },
    # Running max vs nested comparisons
    "HumanEval/9": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_ints(n, rng),),
    },
    # set vs repeated lower() checks
    "HumanEval/16": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_alpha_string(n, rng),),
    },
    # Quadratic-risk: O(n²) pairwise vs O(n log n) sorted scan
    "HumanEval/20": {
        "sizes": [200, 500, 1000, 2000],
        "args_fn": lambda n, rng: (_floats(n, rng),),
    },
    # Two min/max passes vs one
    "HumanEval/21": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_floats(n, rng),),
    },
    # list membership O(n²) vs set O(n)
    "HumanEval/26": {
        "sizes": [1000, 3000, 7000, 15000],
        "args_fn": lambda n, rng: (_ints_dups(n, rng),),
    },
    # string concat vs join
    "HumanEval/27": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_alpha_string(n, rng),),
    },
    # manual loop vs list comp / startswith
    "HumanEval/29": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_string_list(n, rng), "al"),
    },
    # filter vs manual loop
    "HumanEval/30": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_mixed_ints(n, rng),),
    },
    # sort third elements in-place
    "HumanEval/33": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_ints(n, rng),),
    },
    # sorted(set()) vs manual dedup with list membership
    "HumanEval/34": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_ints_dups(n, rng),),
    },
    # O(n³) naive vs O(n²) with set — keep n small
    "HumanEval/40": {
        "sizes": [50, 100, 200, 350],
        "args_fn": lambda n, rng: ([rng.randint(-10, 10) for _ in range(n)],),
    },
    # append loop vs list comp
    "HumanEval/42": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_ints(n, rng),),
    },
    # O(n²) naive vs O(n) with set
    "HumanEval/43": {
        "sizes": [500, 1500, 4000, 8000],
        "args_fn": lambda n, rng: ([rng.randint(-50, 50) for _ in range(n)],),
    },
    # sort-based median
    "HumanEval/47": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_ints(n, rng),),
    },
    # all() vs manual early-exit loop
    "HumanEval/52": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, 200) for _ in range(n)], 100),
    },
    # monotonic check: all()+zip vs manual loop
    "HumanEval/57": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (list(range(n)),),  # always monotonic → no early exit
    },
    # set intersection vs nested loops O(n²)
    "HumanEval/58": {
        "sizes": [300, 700, 1500, 3000],
        "args_fn": lambda n, rng: (
            [rng.randint(0, n) for _ in range(n)],
            [rng.randint(0, n) for _ in range(n)],
        ),
    },
    # min/max interleaved sort
    "HumanEval/70": {
        "sizes": [1000, 5000, 15000, 50000],
        "args_fn": lambda n, rng: (_floats(n, rng),),
    },
    # filter list for numbers without even digits
    "HumanEval/104": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_pos_ints(n, rng),),
    },
    # even-element exchange feasibility check
    "HumanEval/110": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            [rng.choice([1, 3, 5, 7]) for _ in range(n)],
            [rng.choice([0, 2, 4, 6]) for _ in range(n)],
        ),
    },
    # top-k elements
    "HumanEval/120": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (_ints(n, rng), min(10, n)),
    },
    # sum odd elements at odd positions
    "HumanEval/121": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, 100) for _ in range(n)],),
    },
    # --- new 25 ---
    # filter list of strings by substring match
    "HumanEval/7": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            [rng.choice(["alpha", "beta", "gamma", "alphabeta", "delta"]) + str(i) for i in range(n)],
            "al",
        ),
    },
    # sum and product of list — potential two-pass vs one-pass
    "HumanEval/8": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(1, 10) for _ in range(n)],),
    },
    # all_prefixes — string concat in loop opportunity
    "HumanEval/14": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: ("".join(rng.choice("abcdefghij") for _ in range(n)),),
    },
    # how_many_times — manual substring count vs str.count()
    "HumanEval/18": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            "ab" * (n // 2),
            "ab",
        ),
    },
    # filter_integers — isinstance check on mixed list
    "HumanEval/22": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            [rng.randint(0, 10) if rng.random() > 0.5 else str(rng.randint(0, 10)) for _ in range(n)],
        ),
    },
    # concatenate — join list of strings; AI may use +=
    "HumanEval/28": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            [rng.choice(["hello", "world", "foo", "bar"]) for _ in range(n)],
        ),
    },
    # max_element — max() builtin vs manual loop
    "HumanEval/35": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(-1000, 1000) for _ in range(n)],),
    },
    # sort_even — sort only even-indexed positions
    "HumanEval/37": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, 1000) for _ in range(n)],),
    },
    # remove_vowels — string filtering; join vs concat
    "HumanEval/51": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            "".join(rng.choice("aeiouAEIOUbcdfghjklmnpqrstvwxyz") for _ in range(n)),
        ),
    },
    # correct_bracketing '<' '>' — balance check
    "HumanEval/56": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ("<" * (n // 2) + ">" * (n // 2),),
    },
    # derivative — polynomial coefficients list
    "HumanEval/62": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(-10, 10) for _ in range(n)],),
    },
    # vowels_count — count vowels in string
    "HumanEval/64": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            "".join(rng.choice("aeiouAEIOUbcdfghjklmnpqrstvwxyz") for _ in range(n)),
        ),
    },
    # pluck — find smallest even-valued element with index
    "HumanEval/68": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(1, 1000) for _ in range(n)],),
    },
    # search — largest integer appearing >= that many times
    "HumanEval/69": {
        "sizes": [1000, 5000, 15000, 50000],
        "args_fn": lambda n, rng: ([rng.randint(1, max(1, n // 10)) for _ in range(n)],),
    },
    # total_match — compare total char lengths of two string lists
    "HumanEval/74": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            [rng.choice(["apple", "fig", "kiwi"]) for _ in range(n // 2)],
            [rng.choice(["banana", "cherry", "date"]) for _ in range(n // 2)],
        ),
    },
    # is_happy — sliding 3-char window: no two adjacent same
    "HumanEval/80": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            "".join(rng.choice("abcde") for _ in range(n)),
        ),
    },
    # add — sum even elements at odd indices
    "HumanEval/85": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, 100) for _ in range(n)],),
    },
    # anti_shuffle — sort characters within each word
    "HumanEval/86": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: (
            " ".join(
                "".join(rng.choice("abcdefghijklmnop") for _ in range(rng.randint(3, 8)))
                for _ in range(n)
            ),
        ),
    },
    # sort_array — sort by number of 1-bits (special rule)
    "HumanEval/88": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, 255) for _ in range(n)],),
    },
    # skjkasdkd — largest prime digit sum in list
    "HumanEval/94": {
        "sizes": [1000, 5000, 15000, 50000],
        "args_fn": lambda n, rng: ([rng.randint(1, 10000) for _ in range(n)],),
    },
    # words_string — split comma/space separated string into words
    "HumanEval/101": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: (
            " ".join(rng.choice(["hello", "world", "foo", "bar", "baz"]) for _ in range(n)),
        ),
    },
    # count_nums — count elements with positive digit sum (negatives allowed)
    "HumanEval/108": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(-1000, 1000) for _ in range(n)],),
    },
    # move_one_ball — can array be sorted by single cyclic rotation?
    "HumanEval/109": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (list(range(n)),),  # already sorted → True quickly
    },
    # histogram — character frequency from space-separated lowercase letters
    "HumanEval/111": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: (
            " ".join(rng.choice("abcdefghij") for _ in range(n)),
        ),
    },
    # odd_count — count odd digits in each string number
    "HumanEval/113": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            [str(rng.randint(100, 999999)) for _ in range(n)],
        ),
    },
    # --- batch 3 scalers (tasks 51-100) ---
    "HumanEval/1": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: ("() " * n,),
    },
    "HumanEval/3": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(-5, 10) for _ in range(n)],),
    },
    "HumanEval/10": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: ("".join(rng.choice("abcde") for _ in range(n)),),
    },
    "HumanEval/11": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            "".join(rng.choice("01") for _ in range(n)),
            "".join(rng.choice("01") for _ in range(n)),
        ),
    },
    "HumanEval/12": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            ["".join(rng.choice("abcde") for _ in range(rng.randint(1, 20))) for _ in range(n)],
        ),
    },
    "HumanEval/17": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: (
            " ".join(rng.choice(["o", "o|", ".|"]) for _ in range(n)),
        ),
    },
    "HumanEval/19": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: (
            " ".join(rng.choice(["zero","one","two","three","four","five","six","seven","eight","nine"]) for _ in range(n)),
        ),
    },
    "HumanEval/38": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ("".join(rng.choice("abcdefghij") for _ in range(n * 3)),),
    },
    "HumanEval/48": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ("".join(rng.choice("abcde") for _ in range(n)),),
    },
    "HumanEval/50": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ("".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n)),),
    },
    "HumanEval/54": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            "".join(rng.choice("abcde") for _ in range(n)),
            "".join(rng.choice("abcde") for _ in range(n)),
        ),
    },
    "HumanEval/61": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ("(" * (n // 2) + ")" * (n // 2),),
    },
    "HumanEval/66": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            "".join(rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(n)),
        ),
    },
    "HumanEval/72": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(1, 10) for _ in range(n)], n * 5),
    },
    "HumanEval/73": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, 5) for _ in range(n)],),
    },
    "HumanEval/78": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ("".join(rng.choice("0123456789ABCDEF") for _ in range(n)),),
    },
    "HumanEval/82": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ("".join(rng.choice("abcde") for _ in range(n)),),
    },
    # get_row: O(n²) grid — keep n small
    "HumanEval/87": {
        "sizes": [50, 200, 500, 1000],
        "args_fn": lambda n, rng: (
            [[rng.randint(1, n) for _ in range(n)] for _ in range(n)],
            rng.randint(1, n),
        ),
    },
    "HumanEval/89": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ("".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n)),),
    },
    "HumanEval/90": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, n) for _ in range(n)],),
    },
    "HumanEval/91": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: (
            ". ".join(
                ("I " if rng.random() > 0.5 else "the ") + rng.choice(["cat","dog","bird"]) + " runs"
                for _ in range(n)
            ),
        ),
    },
    "HumanEval/93": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            "".join(rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(n)),
        ),
    },
    # count_up_to: count primes < n (sieve vs trial division)
    "HumanEval/96": {
        "sizes": [1000, 10000, 50000, 200000],
        "args_fn": lambda n, rng: (n,),
    },
    "HumanEval/98": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            "".join(rng.choice("aeiouAEIOUbcdfghjklmnpqrstvwxyz") for _ in range(n)),
        ),
    },
    # make_a_pile: generate n arithmetic pile sizes
    "HumanEval/100": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (n,),
    },
    "HumanEval/105": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, 15) for _ in range(n)],),
    },
    "HumanEval/112": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            "".join(rng.choice("abcde") for _ in range(n)),
            "".join(rng.choice("abcde") for _ in range(max(1, n // 10))),
        ),
    },
    "HumanEval/114": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(-100, 100) for _ in range(n)],),
    },
    # max_fill: 2D grid — keep n moderate
    "HumanEval/115": {
        "sizes": [50, 200, 500, 1000],
        "args_fn": lambda n, rng: (
            [[rng.randint(0, 1) for _ in range(n)] for _ in range(n)],
            max(1, n // 5),
        ),
    },
    "HumanEval/116": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, 255) for _ in range(n)],),
    },
    "HumanEval/117": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: (
            " ".join("".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(2, 6))) for _ in range(n)),
            3,
        ),
    },
    "HumanEval/122": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(-999, 999) for _ in range(n)], n // 2),
    },
    "HumanEval/125": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: (
            (", " if rng.random() > 0.5 else " ").join(
                "".join(rng.choice("abcde") for _ in range(rng.randint(2, 6))) for _ in range(n)
            ),
        ),
    },
    "HumanEval/126": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (sorted([rng.randint(0, n) for _ in range(n)]),),
    },
    "HumanEval/128": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(-10, 10) for _ in range(n)],),
    },
    "HumanEval/132": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ("".join(rng.choice("[]") for _ in range(n)),),
    },
    "HumanEval/133": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.uniform(-10, 10) for _ in range(n)],),
    },
    "HumanEval/135": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, 1000) for _ in range(n)],),
    },
    "HumanEval/136": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(-100, 100) for _ in range(n)],),
    },
    "HumanEval/140": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            " ".join("".join(rng.choice("abcde") for _ in range(rng.randint(1, 5))) for _ in range(n)),
        ),
    },
    "HumanEval/142": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.uniform(-10, 10) for _ in range(n)],),
    },
    "HumanEval/143": {
        "sizes": [500, 2000, 5000, 15000],
        "args_fn": lambda n, rng: (
            " ".join("".join(rng.choice("abcde") for _ in range(rng.randint(2, 8))) for _ in range(n)),
        ),
    },
    "HumanEval/145": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(-1000, 1000) for _ in range(n)],),
    },
    "HumanEval/146": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.randint(0, 999) for _ in range(n)],),
    },
    # get_max_triples: O(n²) loop — keep n small
    "HumanEval/147": {
        "sizes": [100, 300, 700, 1500],
        "args_fn": lambda n, rng: (n,),
    },
    "HumanEval/149": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            ["".join(rng.choice("abcde") for _ in range(rng.choice([2, 4, 6]))) for _ in range(n)],
        ),
    },
    "HumanEval/151": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: ([rng.choice([-3.0, -1.0, 0.0, 1.0, 3.0, 5.0]) for _ in range(n)],),
    },
    "HumanEval/152": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            [rng.randint(0, 100) for _ in range(n)],
            [rng.randint(0, 100) for _ in range(n)],
        ),
    },
    "HumanEval/158": {
        "sizes": [2000, 10000, 30000, 100000],
        "args_fn": lambda n, rng: (
            ["".join(rng.choice("abcdefghij") for _ in range(rng.randint(3, 8))) for _ in range(n)],
        ),
    },
    # generate_integers: list even ints from 2 to n
    "HumanEval/163": {
        "sizes": [1000, 10000, 100000, 1000000],
        "args_fn": lambda n, rng: (2, n),
    },
}

# Harness template executed in the subprocess
_HARNESS = """\
import json, sys, time, statistics

with open(sys.argv[1]) as _f:
    _args = json.load(_f)

{code}

# warmup
for _ in range({warmup}):
    try:
        {entry_point}(*_args)
    except Exception:
        pass

# timed runs
_times = []
for _ in range({n_runs}):
    _t0 = time.perf_counter()
    try:
        {entry_point}(*_args)
    except Exception:
        pass
    _times.append(time.perf_counter() - _t0)

print(json.dumps({{
    "times": _times,
    "median": statistics.median(_times),
    "mean": statistics.mean(_times),
}}))
"""

TIMEOUT_SECONDS = 60  # per call — marks as TIMEOUT if exceeded


def _profile_one(
    code: str,
    entry_point: str,
    args: tuple,
    n_runs: int = 5,
    warmup: int = 1,
) -> dict[str, Any]:
    """Run one implementation with given args; return timing dict or error."""
    harness = _HARNESS.format(
        code=code,
        entry_point=entry_point,
        warmup=warmup,
        n_runs=n_runs,
    )
    with tempfile.TemporaryDirectory(prefix="vg_ep_") as tmp:
        args_file = Path(tmp) / "args.json"
        harness_file = Path(tmp) / "harness.py"
        # Serialize args — convert tuples to lists recursively
        args_file.write_text(json.dumps(list(args)), encoding="utf-8")
        harness_file.write_text(harness, encoding="utf-8")

        try:
            result = subprocess.run(
                [sys.executable, str(harness_file), str(args_file)],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "TIMEOUT", "median": None, "mean": None}

        if result.returncode != 0 or not result.stdout.strip():
            return {
                "ok": False,
                "error": result.stderr.strip()[:300] or "no output",
                "median": None,
                "mean": None,
            }
        try:
            data = json.loads(result.stdout.strip().splitlines()[-1])
            data["ok"] = True
            return data
        except Exception as exc:
            return {"ok": False, "error": str(exc), "median": None, "mean": None}


def _run_vibeguard(code: str, task_id: str, source: str) -> list[dict]:
    """Run VibeGuard static analysis; return list of finding dicts."""
    import tempfile, ast
    try:
        from security.core.scanner import Scanner
        from security.analyzers.smells.analyzer import SmellAnalyzer
        from security.analyzers.performance.analyzer import PerformanceAnalyzer

        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as fh:
            fh.write(code)
            path = fh.name

        rows: list[dict] = []
        # Security findings via Scanner
        for item in Scanner()._scan_file(path):
            if isinstance(item, list):
                items = item
            elif item is None:
                continue
            else:
                items = [item]
            for f in items:
                if f is None:
                    continue
                rows.append({
                    "task_id": task_id,
                    "source": source,
                    "rule_id": getattr(f, "rule_id", ""),
                    "cwe": getattr(f, "cwe", None),
                    "severity": str(getattr(f, "severity", "")),
                    "category": str(getattr(f, "category", "")),
                    "message": str(getattr(f, "message", ""))[:120],
                })

        # Smell + Performance findings
        tree = ast.parse(code)
        lines = code.splitlines()
        for Cls in [SmellAnalyzer, PerformanceAnalyzer]:
            for item in Cls().analyze(tree, path, lines):
                items2 = item if isinstance(item, list) else ([item] if item else [])
                for f in items2:
                    if f is None:
                        continue
                    rows.append({
                        "task_id": task_id,
                        "source": source,
                        "rule_id": getattr(f, "rule_id", ""),
                        "cwe": getattr(f, "cwe", None),
                        "severity": str(getattr(f, "severity", "")),
                        "category": str(getattr(f, "category", "")),
                        "message": str(getattr(f, "message", ""))[:120],
                    })
        return rows
    except Exception as exc:
        return [{"task_id": task_id, "source": source, "error": str(exc)}]


def _load_corpus(path: Path) -> list[CorpusSample]:
    samples = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            if row.get("task_id") not in INPUT_SCALERS:
                continue
            samples.append(
                CorpusSample(
                    id=row["id"],
                    task_id=row["task_id"],
                    source=row["source"],
                    prompt=row.get("prompt", ""),
                    code=row["code"],
                    reference_solution=row.get("reference_solution", ""),
                    tests=row.get("tests"),
                    entry_point=row.get("entry_point"),
                    expected_security_labels=row.get("expected_security_labels", []),
                    tags=row.get("tags", []),
                    metadata=row.get("metadata", {}),
                )
            )
    return samples


def run_profile(
    corpus_path: Path,
    out_dir: Path,
    n_runs: int = 5,
    warmup: int = 1,
    seed: int = 42,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    samples = _load_corpus(corpus_path)
    if not samples:
        print(f"ERROR: no samples loaded from {corpus_path}", file=sys.stderr)
        sys.exit(1)

    # Group by task_id
    by_task: dict[str, list[CorpusSample]] = {}
    for s in samples:
        by_task.setdefault(s.task_id, []).append(s)

    print(f"Tasks: {len(by_task)}  |  Samples: {len(samples)}")

    raw_rows: list[dict] = []
    findings_rows: list[dict] = []

    total_tasks = len(by_task)
    for ti, (task_id, task_samples) in enumerate(sorted(by_task.items()), 1):
        scaler = INPUT_SCALERS[task_id]
        sizes = scaler["sizes"]
        args_fn = scaler["args_fn"]
        entry_point = task_samples[0].entry_point or task_id.split("/")[-1]

        print(f"\n[{ti:02d}/{total_tasks}] {task_id}  ({entry_point})  n={sizes}")

        # Run VibeGuard on all AI samples for this task
        for s in task_samples:
            if s.source != "human":
                findings = _run_vibeguard(s.code, task_id, s.source)
                findings_rows.extend(findings)

        rng = random.Random(seed)

        for n in sizes:
            try:
                args = args_fn(n, rng)
            except Exception as exc:
                print(f"    n={n:>7} args generation failed: {exc}")
                continue

            for s in task_samples:
                label = s.source if s.source == "human" else s.source.split(":")[-1]
                print(f"    n={n:>7}  [{label}]", end=" ", flush=True)
                result = _profile_one(
                    code=s.code,
                    entry_point=entry_point,
                    args=args,
                    n_runs=n_runs,
                    warmup=warmup,
                )
                if result["ok"]:
                    med = result["median"]
                    print(f"{med:.4f}s")
                else:
                    med = None
                    print(f"ERR: {result['error'][:60]}")

                raw_rows.append({
                    "task_id": task_id,
                    "entry_point": entry_point,
                    "sample_id": s.id,
                    "source": s.source,
                    "n": n,
                    "ok": result["ok"],
                    "error": result.get("error", ""),
                    "median_wall_s": med,
                    "mean_wall_s": result.get("mean"),
                    "times": json.dumps(result.get("times", [])),
                })

    # Write raw CSV
    raw_path = out_dir / "rq3_evalplus_raw.csv"
    if raw_rows:
        with raw_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(raw_rows[0].keys()))
            writer.writeheader()
            writer.writerows(raw_rows)
        print(f"\nWrote {len(raw_rows)} timing rows → {raw_path}")

    # Write findings CSV
    findings_path = out_dir / "rq3_evalplus_findings.csv"
    if findings_rows:
        with findings_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(findings_rows[0].keys()))
            writer.writeheader()
            writer.writerows(findings_rows)
        print(f"Wrote {len(findings_rows)} finding rows → {findings_path}")

    # Build summary: per-task mean wall time for human vs AI, ratio
    _build_summary(raw_rows, findings_rows, out_dir)


def _build_summary(raw_rows: list[dict], findings_rows: list[dict], out_dir: Path) -> None:
    from collections import defaultdict
    import statistics as stats_mod

    # Gather wall times per (task_id, source_type, n)
    human_times: dict[str, list[float]] = defaultdict(list)
    ai_times: dict[str, list[float]] = defaultdict(list)

    for row in raw_rows:
        if not row["ok"] or row["median_wall_s"] is None:
            continue
        tid = row["task_id"]
        val = float(row["median_wall_s"])
        if row["source"] == "human":
            human_times[tid].append(val)
        else:
            ai_times[tid].append(val)

    summary_rows = []
    for tid in sorted(set(list(human_times) + list(ai_times))):
        hvals = human_times.get(tid, [])
        avals = ai_times.get(tid, [])
        hmean = stats_mod.mean(hvals) if hvals else None
        amean = stats_mod.mean(avals) if avals else None
        ratio = (amean / hmean) if (hmean and amean and hmean > 0) else None
        summary_rows.append({
            "task_id": tid,
            "human_mean_wall_s": f"{hmean:.6f}" if hmean else "",
            "ai_mean_wall_s": f"{amean:.6f}" if amean else "",
            "ai_vs_human_ratio": f"{ratio:.3f}" if ratio else "",
            "ai_slower": "yes" if (ratio and ratio > 1.05) else ("no" if ratio else ""),
        })

    summary_path = out_dir / "rq3_evalplus_summary.csv"
    if summary_rows:
        with summary_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(summary_rows[0].keys()))
            writer.writeheader()
            writer.writerows(summary_rows)
        print(f"Wrote summary → {summary_path}")

    # Print summary table
    slower = [r for r in summary_rows if r["ai_slower"] == "yes"]
    faster = [r for r in summary_rows if r["ai_slower"] == "no"]
    print(f"\n{'Task':<25} {'Human (s)':>12} {'AI (s)':>12} {'Ratio':>8} {'Verdict':>10}")
    print("-" * 75)
    for r in summary_rows:
        print(
            f"{r['task_id']:<25} "
            f"{r['human_mean_wall_s']:>12} "
            f"{r['ai_mean_wall_s']:>12} "
            f"{r['ai_vs_human_ratio']:>8} "
            f"{r['ai_slower']:>10}"
        )
    print("-" * 75)
    print(f"AI slower on {len(slower)}/{len(summary_rows)} tasks | AI faster/same: {len(faster)}")

    # Count smell findings
    perf_findings = [f for f in findings_rows if f.get("category") == "performance"]
    smell_findings = [f for f in findings_rows if f.get("category") == "smell"]

    # Mann-Whitney on AI vs human times (all sizes pooled)
    all_human = [float(r["median_wall_s"]) for r in raw_rows if r["ok"] and r["source"] == "human" and r["median_wall_s"]]
    all_ai = [float(r["median_wall_s"]) for r in raw_rows if r["ok"] and r["source"] != "human" and r["median_wall_s"]]

    mw_result = {}
    if len(all_human) >= 3 and len(all_ai) >= 3:
        try:
            from scipy.stats import mannwhitneyu
            u_stat, p_val = mannwhitneyu(all_ai, all_human, alternative="greater")
            mw_result = {"u": float(u_stat), "p": float(p_val)}
            print(f"\nMann-Whitney U={u_stat:.0f} p={p_val:.4g} (AI > Human wall time, one-sided)")
        except ImportError:
            pass

    summary_json = {
        "corpus": str(out_dir / "rq3_evalplus_raw.csv"),
        "n_tasks": len(summary_rows),
        "n_ai_slower": len(slower),
        "n_ai_faster_or_same": len(faster),
        "n_perf_findings_ai": len(perf_findings),
        "n_smell_findings_ai": len(smell_findings),
        "mannwhitney": mw_result,
        "summary": summary_rows,
    }
    json_path = out_dir / "summary.json"
    json_path.write_text(json.dumps(summary_json, indent=2), encoding="utf-8")
    print(f"Wrote {json_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="RQ3 EvalPlus: AI vs Human profiling.")
    parser.add_argument(
        "--corpus", default="data/corpus/evalplus_ai.jsonl",
        help="Combined human + AI corpus JSONL.",
    )
    parser.add_argument("--out", default="results/energy_evalplus", help="Output directory.")
    parser.add_argument("--runs", type=int, default=5, help="Timed runs per sample×size.")
    parser.add_argument("--warmup", type=int, default=1, help="Warmup runs (not timed).")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for input generation.")
    args = parser.parse_args()

    run_profile(
        corpus_path=Path(args.corpus),
        out_dir=Path(args.out),
        n_runs=args.runs,
        warmup=args.warmup,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
