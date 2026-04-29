from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import quote

from core.models import Payload


class PayloadMutator:
    """Generate payload variants for filter and WAF bypass attempts."""

    @staticmethod
    def bypass_special_chars(
        payload_str: str,
        *,
        include_url_encoding: bool = True,
        include_double_url_encoding: bool = False,
        include_unicode_escape: bool = False,
    ) -> list[str]:
        """
        Apply special-character bypass strategies.
        """
        mutated: set[str] = {payload_str}

        if include_url_encoding:
            # Standard URL encoding
            url_encoded = quote(payload_str, safe="")
            mutated.add(url_encoded)
            if include_double_url_encoding:
                # Double URL encoding (for single-pass decoders)
                mutated.add(quote(url_encoded, safe=""))

        if include_unicode_escape:
            # Unicode escaping for non-alnum chars
            unicode_encoded = "".join(
                f"\\u{ord(char):04x}" if not char.isalnum() else char
                for char in payload_str
            )
            mutated.add(unicode_encoded)

        return list(mutated)

    @staticmethod
    def bypass_spaces(payload_str: str) -> list[str]:
        """
        Apply whitespace bypass strategies frequently seen in SQL/WAF evasions.
        """
        return [
            payload_str,
            payload_str.replace(" ", "/**/"),
            payload_str.replace(" ", "%09"),
            payload_str.replace(" ", "%0a"),
            payload_str.replace(" ", "+"),
        ]

    @staticmethod
    def bypass_case(payload_str: str) -> list[str]:
        """
        Apply case-alternation bypass strategies.
        """
        mutated = {
            payload_str,
            payload_str.upper(),
            payload_str.lower(),
            "".join(
                char.upper() if index % 2 == 0 else char.lower()
                for index, char in enumerate(payload_str)
            ),
        }
        return list(mutated)

    @staticmethod
    def bypass_null_byte(payload_str: str) -> list[str]:
        """
        Apply null-byte prefix/suffix variants.
        """
        return [
            payload_str,
            f"{payload_str}%00",
            f"%00{payload_str}",
        ]

    @staticmethod
    def _replace_keyword_ignore_case(payload_str: str, keyword: str, replacement: str) -> str:
        return re.sub(re.escape(keyword), replacement, payload_str, flags=re.IGNORECASE)

    @classmethod
    def bypass_keyword_split(cls, payload_str: str) -> list[str]:
        """
        Split SQL keywords to evade naive signature matching.
        """
        mutated: set[str] = {payload_str}
        upper_payload = payload_str.upper()

        if "SELECT" in upper_payload:
            mutated.add(cls._replace_keyword_ignore_case(payload_str, "SELECT", "SEL/**/ECT"))
            mutated.add(
                cls._replace_keyword_ignore_case(payload_str, "SELECT", "/*!50000SELECT*/")
            )

        if "UNION" in upper_payload:
            mutated.add(cls._replace_keyword_ignore_case(payload_str, "UNION", "UN/**/ION"))
            mutated.add(
                cls._replace_keyword_ignore_case(payload_str, "UNION", "/*!50000UNION*/")
            )

        return list(mutated)

    @staticmethod
    def _expand_values(values: set[str], mutator: Callable[[str], list[str]]) -> set[str]:
        expanded: set[str] = set()
        for value in values:
            expanded.update(mutator(value))
        return expanded

    @classmethod
    def apply_all_evasions(
        cls,
        base_payload: Payload,
        *,
        include_space_bypass: bool = True,
        include_url_encoding: bool = True,
        include_double_url_encoding: bool = False,
        include_unicode_escape: bool = False,
        include_case_bypass: bool = False,
        include_null_byte_bypass: bool = False,
        include_keyword_split_bypass: bool = False,
    ) -> list[Payload]:
        """
        Expand one payload into multiple bypass variants while preserving metadata.
        """
        final_values: set[str] = {base_payload.value}

        if include_space_bypass:
            final_values = cls._expand_values(final_values, cls.bypass_spaces)

        if include_case_bypass:
            final_values = cls._expand_values(final_values, cls.bypass_case)

        if include_null_byte_bypass:
            final_values = cls._expand_values(final_values, cls.bypass_null_byte)

        if include_keyword_split_bypass:
            final_values = cls._expand_values(final_values, cls.bypass_keyword_split)

        if include_url_encoding or include_double_url_encoding or include_unicode_escape:
            def _special_mutator(value: str) -> list[str]:
                return cls.bypass_special_chars(
                    value,
                    include_url_encoding=include_url_encoding,
                    include_double_url_encoding=include_double_url_encoding,
                    include_unicode_escape=include_unicode_escape,
                )

            final_values = cls._expand_values(final_values, _special_mutator)

        return [
            Payload(
                value=mutated_value,
                attack_type=base_payload.attack_type,
                risk_level=base_payload.risk_level,
            )
            for mutated_value in sorted(final_values)
        ]

    @classmethod
    def expand_payloads(
        cls,
        payloads: list[Payload],
        *,
        include_space_bypass: bool = True,
        include_url_encoding: bool = True,
        include_double_url_encoding: bool = False,
        include_unicode_escape: bool = False,
        include_case_bypass: bool = False,
        include_null_byte_bypass: bool = False,
        include_keyword_split_bypass: bool = False,
    ) -> list[Payload]:
        """
        Expand a payload list and de-duplicate by payload value.
        """
        deduped: dict[str, Payload] = {}
        for payload in payloads:
            for mutated in cls.apply_all_evasions(
                payload,
                include_space_bypass=include_space_bypass,
                include_url_encoding=include_url_encoding,
                include_double_url_encoding=include_double_url_encoding,
                include_unicode_escape=include_unicode_escape,
                include_case_bypass=include_case_bypass,
                include_null_byte_bypass=include_null_byte_bypass,
                include_keyword_split_bypass=include_keyword_split_bypass,
            ):
                deduped.setdefault(mutated.value, mutated)
        return list(deduped.values())
