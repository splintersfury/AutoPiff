"""
Unit tests for Ghidra address-token normalization.

Tests that FUN_/DAT_/PTR_LOOP_/LAB_/switchD_ address tokens are replaced
with stable placeholders, while hex literals, named symbols, and short
tokens are left untouched.
"""

import hashlib
import re

import pytest

# Inline copy of the normalization logic (same regex and function as in
# karton_patch_differ.py) to avoid importing the module which pulls in
# karton, pefile, mwdblib.
_ADDR_TOKEN_RE = re.compile(r'\b(FUN|DAT|PTR_LOOP|LAB|switchD)_[0-9a-fA-F]{4,}\b')


def normalize_address_tokens(code: str) -> str:
    return _ADDR_TOKEN_RE.sub(lambda m: m.group(1) + '_ADDR', code)


# ---------------------------------------------------------------------------
# Token replacement tests
# ---------------------------------------------------------------------------

class TestNormalizeAddressTokens:
    """Tests for normalize_address_tokens()."""

    def test_fun_token(self):
        assert normalize_address_tokens("call FUN_1c001ca80()") == "call FUN_ADDR()"

    def test_dat_token(self):
        assert normalize_address_tokens("mov rax, DAT_1c003f200") == "mov rax, DAT_ADDR"

    def test_ptr_loop_token(self):
        assert normalize_address_tokens("jmp PTR_LOOP_1c0026170") == "jmp PTR_LOOP_ADDR"

    def test_lab_token(self):
        assert normalize_address_tokens("goto LAB_1c005dac5;") == "goto LAB_ADDR;"

    def test_switchd_token(self):
        assert normalize_address_tokens("switchD_1c006abc:") == "switchD_ADDR:"

    def test_hex_literal_untouched(self):
        """Plain hex literals like 0x1c001ca80 must NOT be normalized."""
        code = "if (x == 0x1c001ca80)"
        assert normalize_address_tokens(code) == code

    def test_named_symbol_untouched(self):
        """Real symbol names should pass through unchanged."""
        code = "call ExFreePoolWithTag(ptr);"
        assert normalize_address_tokens(code) == code

    def test_short_hex_untouched(self):
        """Tokens with < 4 hex digits are not Ghidra addresses."""
        code = "FUN_abc"  # only 3 hex digits
        assert normalize_address_tokens(code) == code

    def test_multiple_tokens_in_one_line(self):
        code = "FUN_1c001ca80(DAT_1c003f200, LAB_1c005dac5)"
        expected = "FUN_ADDR(DAT_ADDR, LAB_ADDR)"
        assert normalize_address_tokens(code) == expected

    def test_multiline(self):
        code = "call FUN_1c001ca80()\ngoto LAB_1c005dac5;\n"
        expected = "call FUN_ADDR()\ngoto LAB_ADDR;\n"
        assert normalize_address_tokens(code) == expected

    def test_idempotent(self):
        """Applying normalization twice gives the same result."""
        code = "FUN_1c001ca80(DAT_1c003f200)"
        once = normalize_address_tokens(code)
        twice = normalize_address_tokens(once)
        assert once == twice

    def test_empty_string(self):
        assert normalize_address_tokens("") == ""


# ---------------------------------------------------------------------------
# Hash-equality tests (simulates _align_functions matching)
# ---------------------------------------------------------------------------

class TestNormalizedHashing:
    """Verify that relocated-but-identical code hashes equally after normalization."""

    @staticmethod
    def _norm_hash(code: str) -> str:
        return hashlib.md5(normalize_address_tokens(code).encode('utf-8')).hexdigest()

    def test_relocated_code_hashes_equal(self):
        """Same logic at different addresses should hash identically."""
        old_code = """\
void FUN_1c001ca80(void) {
    int x = DAT_1c003f200;
    if (x > 0) {
        FUN_1c001cb00();
    }
}"""
        new_code = """\
void FUN_1c001cac0(void) {
    int x = DAT_1c003f240;
    if (x > 0) {
        FUN_1c001cb40();
    }
}"""
        assert self._norm_hash(old_code) == self._norm_hash(new_code)

    def test_real_change_hashes_differ(self):
        """A genuine code change should produce different hashes."""
        old_code = """\
void FUN_1c001ca80(void) {
    memcpy(dst, src, len);
}"""
        new_code = """\
void FUN_1c001cac0(void) {
    if (len <= bufsize) {
        memcpy(dst, src, len);
    }
}"""
        assert self._norm_hash(old_code) != self._norm_hash(new_code)

    def test_identical_code_same_address(self):
        """Identical code (same address) should obviously hash equally."""
        code = "void FUN_1c001ca80(void) { return; }"
        assert self._norm_hash(code) == self._norm_hash(code)
