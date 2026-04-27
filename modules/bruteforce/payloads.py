from __future__ import annotations

import itertools
import os
from typing import Iterable

from core.models import Payload

DEFAULT_WORDLIST_PATH = os.path.join("config", "payloads", "common_passwords.txt")


def _resolve_wordlist_file(wordlist_path: str | None = None) -> str | None:
    candidate = wordlist_path or DEFAULT_WORDLIST_PATH
    if os.path.exists(candidate):
        return candidate
    return None


def _read_words(path: str) -> list[str]:
    words: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            word = line.strip()
            if not word:
                continue
            words.append(word)
    return words


def apply_mutations(base_word: str, *, mutation_level: int = 1) -> list[str]:
    """
    Generate common password variants for practical dictionary attacks.

    mutation_level:
      0 - no mutation (base word only)
      1 - basic case variants + common short suffixes
      2 - adds extended suffix patterns (years, combos)
      3 - adds level 2 + leet transformations
    """
    if mutation_level <= 0:
        return [base_word] if base_word else []

    word = base_word.strip()
    if not word:
        return []

    lower_word = word.lower()
    cap_word = word.capitalize()
    variants = {
        word,
        lower_word,
        word.upper(),
        cap_word,
    }

    basic_suffixes = ["1", "12", "123", "!", "@123"]
    for suffix in basic_suffixes:
        variants.add(f"{word}{suffix}")

    if mutation_level >= 2:
        suffixes = [
            "1234",
            "12345",
            "@",
            "#",
            "$",
            "!!",
            "1!",
            "123!",
            "2023",
            "2024",
            "2025",
            "2026",
        ]
        for suffix in suffixes:
            variants.add(f"{word}{suffix}")
            variants.add(f"{lower_word}{suffix}")
            variants.add(f"{cap_word}{suffix}")

    if mutation_level >= 3:
        leet_word = (
            lower_word.replace("a", "@")
            .replace("o", "0")
            .replace("e", "3")
            .replace("i", "1")
            .replace("s", "$")
        )
        if leet_word != lower_word:
            variants.add(leet_word)
            variants.add(leet_word.capitalize())
            variants.add(f"{leet_word}123")
            variants.add(f"{leet_word}!")

    return [variant for variant in variants if variant]


def _iter_dictionary_candidates(
    words: Iterable[str],
    *,
    enable_mutation: bool,
    mutation_level: int,
) -> Iterable[str]:
    for word in words:
        if enable_mutation:
            for variant in apply_mutations(word, mutation_level=mutation_level):
                yield variant
            continue
        yield word


def get_dictionary_payloads(
    *,
    wordlist_path: str | None = None,
    enable_mutation: bool = True,
    mutation_level: int = 1,
    max_candidates: int = 0,
) -> list[Payload]:
    """
    Build dictionary payload list from configured wordlist.
    """
    file_path = _resolve_wordlist_file(wordlist_path=wordlist_path)
    if not file_path:
        return []
    words = _read_words(file_path)

    payloads: list[Payload] = []
    seen: set[str] = set()
    for candidate in _iter_dictionary_candidates(
        words,
        enable_mutation=enable_mutation,
        mutation_level=mutation_level,
    ):
        if candidate in seen:
            continue
        seen.add(candidate)
        payloads.append(
            Payload(
                value=candidate,
                attack_type="BF-dictionary",
                risk_level="high",
            )
        )
        if max_candidates > 0 and len(payloads) >= max_candidates:
            break
    return payloads


def get_true_bruteforce_payloads(
    *,
    charset: str,
    min_length: int = 1,
    max_length: int,
    max_candidates: int = 0,
) -> list[Payload]:
    """
    Generate exhaustive brute-force payloads up to max_length.
    """
    payloads: list[Payload] = []
    if not charset or max_length <= 0:
        return payloads
    if min_length < 1:
        min_length = 1
    if min_length > max_length:
        return payloads

    emitted = 0
    for length in range(min_length, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            payloads.append(
                Payload(
                    value="".join(combo),
                    attack_type="BF-true_bruteforce",
                    risk_level="high",
                )
            )
            emitted += 1
            if max_candidates > 0 and emitted >= max_candidates:
                return payloads

    return payloads
