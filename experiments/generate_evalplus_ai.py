"""Generate AI solutions for 25 selected EvalPlus algorithmic tasks.

Reads human reference solutions from data/corpus/evalplus.jsonl,
generates AI solutions via OpenAI for two models (gpt-4o, gpt-4o-mini),
and writes a combined corpus to data/corpus/evalplus_ai.jsonl.

The 25 tasks are chosen for algorithmic complexity: they admit naive
implementations that differ meaningfully in runtime from optimal ones,
making them good candidates for AI vs human performance comparison.

Usage:
    python -m experiments.generate_evalplus_ai
    python -m experiments.generate_evalplus_ai --models gpt-4o-mini --out data/corpus/evalplus_ai_mini.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from corpus.providers.openai_provider import OpenAIProvider
from corpus.schema import CorpusSample, write_corpus

# ---------------------------------------------------------------------------
# 25 selected task IDs — chosen for algorithmic scalability
# ---------------------------------------------------------------------------
SELECTED_TASK_IDS = {
    # --- original 25 ---
    "HumanEval/0",   # has_close_elements       — O(n²) naive vs O(n log n)
    "HumanEval/4",   # mean_absolute_deviation   — multi-pass vs single-pass
    "HumanEval/5",   # intersperse               — += vs list comprehension
    "HumanEval/9",   # rolling_max               — re-max vs running max
    "HumanEval/16",  # count_distinct_characters — set vs repeated check
    "HumanEval/20",  # find_closest_elements     — O(n²) naive vs O(n log n)
    "HumanEval/21",  # rescale_to_unit           — two min/max passes vs one
    "HumanEval/26",  # remove_duplicates         — list membership vs set O(n²) vs O(n)
    "HumanEval/27",  # flip_case                 — string concat vs join
    "HumanEval/29",  # filter_by_prefix          — manual loop vs list comp
    "HumanEval/30",  # get_positive              — filter vs manual loop
    "HumanEval/33",  # sort_third                — sort every third element
    "HumanEval/34",  # unique                    — sorted(set()) vs manual dedup
    "HumanEval/40",  # triples_sum_to_zero       — O(n³) naive vs O(n²) with set
    "HumanEval/42",  # incr_list                 — append loop vs list comp
    "HumanEval/43",  # pairs_sum_to_zero         — O(n²) naive vs O(n) with set
    "HumanEval/47",  # median                    — sort + index
    "HumanEval/52",  # below_threshold           — all() vs manual loop
    "HumanEval/57",  # monotonic                 — all() with zip vs manual loop
    "HumanEval/58",  # common                    — nested loops vs set intersection
    "HumanEval/70",  # strange_sort_list         — pop(0) O(n²) vs two-pointer
    "HumanEval/104", # unique_digits             — filter + digit check
    "HumanEval/110", # exchange                  — even-element exchange check
    "HumanEval/120", # maximum                   — top-k elements
    "HumanEval/121", # solution                  — sum odd elements at odd positions
    # --- batch 2 (tasks 26-50) ---
    "HumanEval/7",   # filter_by_substring       — list filter with substring match
    "HumanEval/8",   # sum_product               — single-pass sum+product vs two passes
    "HumanEval/14",  # all_prefixes              — string concat in loop vs join
    "HumanEval/18",  # how_many_times            — manual scan vs str.count()
    "HumanEval/22",  # filter_integers           — isinstance filter
    "HumanEval/28",  # concatenate               — join vs += accumulation
    "HumanEval/35",  # max_element               — max() vs manual loop
    "HumanEval/37",  # sort_even                 — sort even-indexed elements
    "HumanEval/51",  # remove_vowels             — string filter (join vs concat)
    "HumanEval/56",  # correct_bracketing        — bracket balance check
    "HumanEval/62",  # derivative                — polynomial derivative coefficients
    "HumanEval/64",  # vowels_count              — vowel counting in string
    "HumanEval/68",  # pluck                     — find smallest even in list
    "HumanEval/69",  # search                    — search largest value >= count
    "HumanEval/74",  # total_match               — compare total char counts in two lists
    "HumanEval/80",  # is_happy                  — sliding 3-char window check
    "HumanEval/85",  # add                       — sum even elements at odd positions
    "HumanEval/86",  # anti_shuffle              — sort each word's characters
    "HumanEval/88",  # sort_array                — binary-count based sort
    "HumanEval/94",  # skjkasdkd                 — largest prime in list
    "HumanEval/101", # words_string              — split string into word list
    "HumanEval/108", # count_nums               — count elements with positive digit sum
    "HumanEval/109", # move_one_ball            — rotation sort feasibility
    "HumanEval/111", # histogram                — character frequency dict
    "HumanEval/113", # odd_count                — odd digit count per string
    # --- batch 3 (tasks 51-100) ---
    "HumanEval/1",   # separate_paren_groups    — parse string of balanced paren groups
    "HumanEval/3",   # below_zero               — detect negative bank balance
    "HumanEval/10",  # make_palindrome          — shortest palindrome from string
    "HumanEval/11",  # string_xor               — XOR two binary strings
    "HumanEval/12",  # longest                  — longest string in list
    "HumanEval/17",  # parse_music              — parse music notation string
    "HumanEval/19",  # sort_numbers             — sort number words
    "HumanEval/38",  # decode_cyclic            — decode cyclic-encoded string
    "HumanEval/48",  # is_palindrome            — palindrome check on string
    "HumanEval/50",  # decode_shift             — decode shifted string
    "HumanEval/54",  # same_chars               — two strings same character sets
    "HumanEval/61",  # correct_bracketing       — balanced () check
    "HumanEval/66",  # digitSum                 — sum of uppercase ASCII values
    "HumanEval/72",  # will_it_fly              — palindrome + sum threshold
    "HumanEval/73",  # smallest_change          — min edits for list palindrome
    "HumanEval/78",  # hex_key                  — count prime hex digits in string
    "HumanEval/82",  # prime_length             — check if string length is prime
    "HumanEval/87",  # get_row                  — find element in 2D list
    "HumanEval/89",  # encrypt                  — rotate characters by 4 positions
    "HumanEval/90",  # next_smallest            — second smallest distinct element
    "HumanEval/91",  # is_bored                 — count sentences starting with "I"
    "HumanEval/93",  # encode                   — shift chars + swap case
    "HumanEval/96",  # count_up_to              — count primes up to n
    "HumanEval/98",  # count_upper              — uppercase vowels at even positions
    "HumanEval/100", # make_a_pile              — generate pile sizes
    "HumanEval/105", # by_length                — filter 1-9 integers, name-sorted
    "HumanEval/112", # reverse_delete           — remove chars not in set, check palindrome
    "HumanEval/114", # minSubArraySum           — minimum subarray sum
    "HumanEval/115", # max_fill                 — minimum bucket fills for wells
    "HumanEval/116", # sort_array               — sort by count of 1-bits
    "HumanEval/117", # select_words             — words with exactly n consonants
    "HumanEval/122", # add_elements             — sum 2-digit numbers up to index k
    "HumanEval/125", # split_words              — split on space or comma
    "HumanEval/126", # is_sorted                — sorted with at most one duplicate
    "HumanEval/128", # prod_signs               — product of signs array
    "HumanEval/132", # is_nested                — nested bracket structure check
    "HumanEval/133", # sum_squares              — sum ceil(x)² for list
    "HumanEval/135", # can_arrange              — largest unsorted index
    "HumanEval/136", # largest_smallest_integers — largest neg + smallest pos
    "HumanEval/140", # fix_spaces               — replace multi-spaces with underscores
    "HumanEval/142", # sum_squares_2            — sum of rounded squares
    "HumanEval/143", # words_in_sentence        — filter words by prime length
    "HumanEval/145", # order_by_points          — sort integers by digit sum
    "HumanEval/146", # specialFilter            — filter by first/last digit constraints
    "HumanEval/147", # get_max_triples          — count triples where sum % 3 == 0
    "HumanEval/149", # sorted_list_sum          — sort even-length strings
    "HumanEval/151", # double_the_difference    — sum squares of odd floats
    "HumanEval/152", # compare                  — element-wise difference of two lists
    "HumanEval/158", # find_max                 — word with most unique characters
    "HumanEval/163", # generate_integers        — even integers between a and b
}

_GENERATION_SYSTEM = (
    "You are an expert Python programmer. Complete the given Python function. "
    "Return ONLY the complete Python code with the function implementation, "
    "including any necessary imports. Do not add any explanation or markdown."
)

_GENERATION_PROMPT = (
    "Complete the following Python function. Return only the complete Python code "
    "(including the function signature and docstring), no explanation.\n\n{prompt}"
)


def _load_selected(corpus_path: Path) -> list[CorpusSample]:
    """Load only the 25 selected tasks from the evalplus corpus JSONL."""
    selected = []
    with corpus_path.open(encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            if row.get("task_id") in SELECTED_TASK_IDS:
                selected.append(
                    CorpusSample(
                        id=row["id"],
                        task_id=row["task_id"],
                        source=row["source"],
                        prompt=row["prompt"],
                        code=row["code"],
                        reference_solution=row.get("reference_solution", row["code"]),
                        tests=row.get("tests"),
                        entry_point=row.get("entry_point"),
                        expected_security_labels=row.get("expected_security_labels", []),
                        tags=row.get("tags", []),
                        metadata=row.get("metadata", {}),
                    )
                )
    return selected


def _generate_for_task(
    task: CorpusSample,
    provider: OpenAIProvider,
) -> CorpusSample:
    """Generate one AI solution for a task and return a CorpusSample."""
    prompt = _GENERATION_PROMPT.format(prompt=task.prompt)
    record = provider.generate_record(prompt, cache_variant="evalplus-perf")
    meta = dict(task.metadata)
    meta.update({
        "generated_for": task.id,
        "provider": f"openai:{provider.model}",
        "generation": {k: v for k, v in record.items() if k not in {"prompt", "raw", "code"}},
    })
    return CorpusSample(
        id=f"{task.task_id}::openai:{provider.model}::evalplus-perf",
        task_id=task.task_id,
        source=f"openai:{provider.model}",
        prompt=task.prompt,
        code=record["code"],
        reference_solution=task.reference_solution,
        tests=task.tests,
        entry_point=task.entry_point,
        expected_security_labels=list(task.expected_security_labels),
        tags=["ai-generated", "evalplus", "humanevalplus"],
        metadata=meta,
    )


def generate(
    corpus_path: Path,
    models: list[str],
    out_path: Path,
    cache_dir: str = "data/cache",
) -> None:
    human_tasks = _load_selected(corpus_path)
    if not human_tasks:
        print(f"ERROR: No matching tasks found in {corpus_path}", file=sys.stderr)
        sys.exit(1)
    print(f"Loaded {len(human_tasks)} human reference tasks.")

    all_samples: list[CorpusSample] = list(human_tasks)

    for model in models:
        provider = OpenAIProvider(model=model, cache_dir=cache_dir, temperature=0.2)
        print(f"\nGenerating with {model} ...")
        for i, task in enumerate(human_tasks, 1):
            print(f"  [{i:02d}/{len(human_tasks)}] {task.task_id} ({task.entry_point})", end=" ", flush=True)
            try:
                ai_sample = _generate_for_task(task, provider)
                all_samples.append(ai_sample)
                print("OK")
            except Exception as exc:
                print(f"FAILED: {exc}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    count = write_corpus(all_samples, out_path)
    print(f"\nWrote {count} samples to {out_path}")
    print(f"  Human:  {len(human_tasks)}")
    print(f"  AI:     {count - len(human_tasks)}  ({len(models)} models × {len(human_tasks)} tasks)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate AI solutions for 25 EvalPlus tasks.")
    parser.add_argument(
        "--corpus", default="data/corpus/evalplus.jsonl",
        help="Path to existing evalplus human corpus JSONL.",
    )
    parser.add_argument(
        "--models", nargs="+", default=["gpt-4o", "gpt-4o-mini"],
        help="OpenAI model(s) to use (default: gpt-4o gpt-4o-mini).",
    )
    parser.add_argument(
        "--out", default="data/corpus/evalplus_ai.jsonl",
        help="Output JSONL path.",
    )
    parser.add_argument("--cache-dir", default="data/cache", help="LLM response cache directory.")
    args = parser.parse_args()

    generate(
        corpus_path=Path(args.corpus),
        models=args.models,
        out_path=Path(args.out),
        cache_dir=args.cache_dir,
    )


if __name__ == "__main__":
    main()
