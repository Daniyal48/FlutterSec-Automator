"""Binary analysis module — locates SSL pinning offsets in libflutter.so.

Detection strategy cascade
--------------------------
All three strategies are attempted in order.  Results are de-duplicated by
virtual address and merged into a single sorted list.

1. **Symbol scan** — Searches the ELF symbol table (via LIEF) for well-known
   BoringSSL / Flutter SSL function names.  Exact, zero false-positives, but
   only works on *unstripped* production builds.

2. **Pattern scan** — Slides ARM64/ARM32/x86_64 byte-sequence patterns over
   the ``.text`` segment using Python :mod:`re` with ``??`` wildcard support.
   Patterns are loaded from ``data/patterns.yaml`` and filtered by architecture
   and Flutter version prefix before scanning.

3. **Version-map lookup** — If both the above strategies find nothing, the
   detected engine hash / Build-ID is cross-referenced against the
   ``offsets`` block inside ``data/version_map.yaml``, which carries
   pre-computed ``{symbol, virtual_address, file_offset}`` tuples that were
   extracted from official Flutter release binaries.

Custom exceptions
-----------------
:class:`OffsetNotFoundError` is raised (by callers that require at least one
result) when all three strategies come up empty.
:class:`BinaryParseError` wraps LIEF failures on corrupted inputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import lief  # type: ignore[import-untyped]
import yaml

from fluttersec.core.version_detector import EngineVersion
from fluttersec.utils.logger import get_logger

log = get_logger(__name__)

_PATTERNS_PATH = Path(__file__).parent.parent / "data" / "patterns.yaml"
_VERSION_MAP_PATH = Path(__file__).parent.parent / "data" / "version_map.yaml"

# Well-known BoringSSL / Flutter SSL symbol names to hunt for in the symbol table.
_SSL_SYMBOLS: tuple[str, ...] = (
    "ssl_verify_peer_cert",
    "SSL_CTX_set_custom_verify",
    "SSL_CTX_set_verify",
    "ssl_client_hello_cb",
    "x509_verify_cert_error_string",
    "ssl_crypto_x509_session_verify_cert_chain",
    "boringssl_self_test",
    "ssl_verify_cert_chain",
    "tls1_handshake_digest",
)

# Per-symbol bypass metadata used by both the symbol scanner and the Frida template.
# bypass_return : value the NativeCallback will return (0 = ssl_verify_ok / false,
#                 1 = ssl_verify_ok / true, depending on BoringSSL convention).
# return_type   : Frida NativeCallback return type string.
# arg_types     : Frida NativeCallback argument type list.
_SSL_SYMBOL_METADATA: dict[str, dict] = {
    # ssl_verify_peer_cert(SSL*, uint8_t*) -> enum ssl_verify_result_t
    # ssl_verify_ok == 0 in BoringSSL.
    "ssl_verify_peer_cert": {
        "bypass_return": 0,
        "return_type": "int",
        "arg_types": ["pointer", "pointer"],
    },
    # ssl_crypto_x509_session_verify_cert_chain(SSL*, int) -> bool (1 = verified OK)
    "ssl_crypto_x509_session_verify_cert_chain": {
        "bypass_return": 1,
        "return_type": "int",
        "arg_types": ["pointer", "int"],
    },
    # ssl_verify_cert_chain(SSL*, STACK_OF_X509*) -> bool (1 = OK)
    "ssl_verify_cert_chain": {
        "bypass_return": 1,
        "return_type": "int",
        "arg_types": ["pointer", "pointer"],
    },
    # SSL_CTX_set_custom_verify(SSL_CTX*, int, callback*) -> void
    # Making this a no-op prevents a custom verifier from being installed.
    "SSL_CTX_set_custom_verify": {
        "bypass_return": 0,
        "return_type": "void",
        "arg_types": ["pointer", "int", "pointer"],
    },
    # SSL_CTX_set_verify -- void, suppress any verify mode change.
    "SSL_CTX_set_verify": {
        "bypass_return": 0,
        "return_type": "void",
        "arg_types": ["pointer", "int", "pointer"],
    },
    # Fallback defaults for any other matched symbol.
    "_default": {
        "bypass_return": 0,
        "return_type": "int",
        "arg_types": ["pointer", "pointer"],
    },
}


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class BinaryParseError(Exception):
    """Raised when LIEF cannot parse the provided ELF binary.

    This guards against corrupted, packed, or non-ELF inputs that would
    otherwise cause LIEF to return ``None`` or raise internally.

    Args:
        lib_path: Path to the binary that failed to parse.
        detail: Human-readable reason from LIEF (if available).
    """

    def __init__(self, lib_path: Path, detail: str = "") -> None:
        self.lib_path = lib_path
        super().__init__(
            f"LIEF failed to parse '{lib_path.name}'"
            + (f": {detail}" if detail else "")
        )


class OffsetNotFoundError(Exception):
    """Raised when no SSL pinning offset can be located by any strategy.

    Attributes:
        lib_path: Library that was analyzed.
        engine_version: Engine version metadata used during analysis.
        strategies_tried: List of strategy names that were attempted.
    """

    def __init__(
        self,
        lib_path: Path,
        engine_version: EngineVersion,
        strategies_tried: list[str],
    ) -> None:
        self.lib_path = lib_path
        self.engine_version = engine_version
        self.strategies_tried = strategies_tried
        tried = ", ".join(strategies_tried) if strategies_tried else "none"
        super().__init__(
            f"No SSL pinning offset found in '{lib_path.name}' "
            f"after trying: {tried}. "
            "Add a pattern entry to data/patterns.yaml or an offset entry "
            "to data/version_map.yaml for this engine version."
        )


# ---------------------------------------------------------------------------
# Data transfer objects
# ---------------------------------------------------------------------------

@dataclass
class SslOffset:
    """A located SSL pinning hook point within libflutter.so.

    Attributes:
        symbol: Name or description of the target function.
        virtual_address: ELF virtual address of the function entry point.
        file_offset: Raw byte offset from the start of the file.
        method: Detection method — ``"symbol"``, ``"xref"``,
            ``"pattern"``, or ``"version_map"``.
        arch: ABI/architecture of the binary (e.g. ``"arm64-v8a"``).
        bypass_return: Integer value the Frida NativeCallback should return
            to signal «verification OK» for this specific function
            (``0`` = ``ssl_verify_ok`` for ``ssl_verify_peer_cert``;
             ``1`` = ``true`` / success for ``ssl_crypto_x509_…`` etc.).
        return_type: Frida ``NativeCallback`` return-type string
            (e.g. ``"int"`` or ``"void"``).
        arg_types: Frida ``NativeCallback`` argument type list
            (e.g. ``["pointer", "pointer"]``).
    """

    symbol: str
    virtual_address: int
    file_offset: int
    method: str
    arch: str
    bypass_return: int = 0
    return_type: str = "int"
    arg_types: list[str] = field(default_factory=lambda: ["pointer", "pointer"])


@dataclass
class AnalysisResult:
    """Full output of a :class:`BinaryAnalyzer` run.

    Attributes:
        offsets: Sorted list of located :class:`SslOffset` instances.
        strategies_used: Names of strategies that produced at least one result.
        arch: Architecture of the analyzed binary.
    """

    offsets: list[SslOffset]
    strategies_used: list[str]
    arch: str


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class BinaryAnalyzer:
    """Locate SSL pinning–related offsets within ``libflutter.so``.

    The analyzer can be used in two ways:

    **Standalone (stateless) mode** — call :meth:`find_ssl_offsets` directly::

        analyzer = BinaryAnalyzer()
        offsets = analyzer.find_ssl_offsets(lib_path, engine_version)

    **Bound mode** — instantiate with the target binary and engine version for
    a more ergonomic API::

        analyzer = BinaryAnalyzer(lib_path, engine_version)
        result = analyzer.analyze()

    Both modes run the same three-strategy cascade.
    """

    def __init__(
        self,
        lib_path: Path | None = None,
        engine_version: EngineVersion | None = None,
    ) -> None:
        """Initialise the analyzer, optionally binding it to a specific target.

        Args:
            lib_path: Path to the ``libflutter.so`` to analyze.  When supplied,
                :meth:`analyze` can be called without arguments.
            engine_version: Detected engine version metadata.  Required for
                version-specific pattern filtering and version-map lookup.
        """
        self._lib_path: Path | None = lib_path
        self._engine_version: EngineVersion | None = engine_version
        self._patterns: list[dict[str, str]] = self._load_patterns()
        self._version_map_offsets: dict[str, list[dict]] = self._load_version_map_offsets()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        lib_path: Path | None = None,
        engine_version: EngineVersion | None = None,
        arch: str | None = None,
        raise_on_empty: bool = False,
    ) -> AnalysisResult:
        """Run the full three-strategy cascade and return an :class:`AnalysisResult`.

        Args:
            lib_path: Override for the bound ``lib_path``; required if no
                path was supplied at construction time.
            engine_version: Override for the bound ``engine_version``.
            arch: ABI string for pattern filtering.  Inferred from the parent
                directory name if ``None``.
            raise_on_empty: If ``True``, raises :class:`OffsetNotFoundError`
                when no offsets are found.

        Returns:
            :class:`AnalysisResult` with all located offsets and strategy metadata.

        Raises:
            ValueError: If no ``lib_path`` is available (neither bound nor passed).
            BinaryParseError: If LIEF cannot parse the ELF binary.
            OffsetNotFoundError: If ``raise_on_empty=True`` and no offsets found.
        """
        effective_path = lib_path or self._lib_path
        if effective_path is None:
            raise ValueError(
                "lib_path must be supplied either at construction or at call time."
            )
        effective_ev = engine_version or self._engine_version
        if effective_ev is None:
            from fluttersec.core.version_detector import EngineVersion
            effective_ev = EngineVersion(
                version_string=None,
                build_id=None,
                engine_hash=None,
                detection_method="unknown",
                sections_found=[],
            )

        offsets = self.find_ssl_offsets(effective_path, effective_ev, arch=arch)

        strategies_used: list[str] = list({o.method for o in offsets})

        if raise_on_empty and not offsets:
            tried = ["symbol", "xref", "pattern", "version_map"]
            raise OffsetNotFoundError(effective_path, effective_ev, tried)

        return AnalysisResult(
            offsets=offsets,
            strategies_used=strategies_used,
            arch=arch or effective_path.parent.name,
        )

    def find_ssl_offsets(
        self,
        lib_path: Path,
        engine_version: EngineVersion,
        arch: str | None = None,
    ) -> list[SslOffset]:
        """Locate SSL pinning offsets using a four-strategy cascade.

        Strategies run in order and results are de-duplicated by virtual address
        and merged into a single sorted list:

        1. **Symbol scan** — ELF symbol table lookup (only works on unstripped
           builds).
        2. **String XREF scan** — Locates the ``"ssl_client"`` string literal
           in ``.rodata`` and traces ARM64 ADRP+ADD instruction pairs in
           ``.text`` back to the function entry point.  Architecture-resilient
           because it uses the *meaning* of the code, not its byte encoding.
        3. **Pattern scan** — Byte-sequence sliding-window scan with wildcard
           support.  Filtered by arch and engine version prefix.
        4. **Version-map lookup** — Pre-computed offsets from
           ``data/version_map.yaml``, keyed by engine hash / Build-ID.  Only
           runs when strategies 1-3 all return nothing.

        Args:
            lib_path: Path to ``libflutter.so``.
            engine_version: Detected engine version (used for pattern filtering
                and version-map lookup).
            arch: ABI string.  Inferred from parent directory name when ``None``.

        Returns:
            Sorted list of unique :class:`SslOffset` instances.

        Raises:
            BinaryParseError: If LIEF cannot parse *lib_path*.
            FileNotFoundError: If *lib_path* does not exist.
        """
        if not lib_path.exists():
            raise FileNotFoundError(f"Library not found: {lib_path}")

        if arch is None:
            arch = lib_path.parent.name  # e.g. "arm64-v8a"

        log.info("Analyzing binary for SSL offsets (arch=%s): %s", arch, lib_path)

        binary = self._parse_binary(lib_path)

        seen_vas: set[int] = set()
        results: list[SslOffset] = []
        strategies_tried: list[str] = []

        # ── Strategy 1: Symbol scan ────────────────────────────────────────
        strategies_tried.append("symbol")
        for offset in self._symbol_scan(binary, arch):
            if offset.virtual_address not in seen_vas:
                results.append(offset)
                seen_vas.add(offset.virtual_address)

        # ── Strategy 2: String XREF scan ──────────────────────────────────
        # Resilient against byte-pattern obfuscation: finds the 'ssl_client'
        # string literal in .rodata then traces ADRP+ADD XREFs in .text back
        # to the parent function entry point.  arm64-v8a only.
        strategies_tried.append("xref")
        for offset in self._xref_scan(binary, arch):
            if offset.virtual_address not in seen_vas:
                results.append(offset)
                seen_vas.add(offset.virtual_address)

        # ── Strategy 3: Pattern scan ───────────────────────────────────────
        strategies_tried.append("pattern")
        for offset in self._pattern_scan(binary, arch, engine_version):
            if offset.virtual_address not in seen_vas:
                results.append(offset)
                seen_vas.add(offset.virtual_address)

        # ── Strategy 4: Version-map offset lookup ──────────────────────────
        strategies_tried.append("version_map")
        if not results:
            # Only run the fallback if all scanning strategies found nothing.
            # This avoids inflating results with potentially stale static data.
            for offset in self._version_map_lookup(engine_version, arch):
                if offset.virtual_address not in seen_vas:
                    results.append(offset)
                    seen_vas.add(offset.virtual_address)

        results.sort(key=lambda o: o.virtual_address)
        log.info(
            "SSL offsets found: %d (strategies: %s)",
            len(results),
            ", ".join(strategies_tried),
        )
        return results

    # ------------------------------------------------------------------
    # Strategy 1 — symbol table scan
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_binary(lib_path: Path) -> lief.ELF.Binary:
        """Parse *lib_path* with LIEF, raising :class:`BinaryParseError` on failure.

        Args:
            lib_path: Path to the ELF binary.

        Returns:
            Parsed :class:`lief.ELF.Binary`.

        Raises:
            BinaryParseError: If LIEF returns ``None`` or raises.
        """
        try:
            binary = lief.parse(str(lib_path))
        except Exception as exc:
            raise BinaryParseError(lib_path, str(exc)) from exc
        if binary is None or not isinstance(binary, lief.ELF.Binary):
            raise BinaryParseError(lib_path, "LIEF returned None or non-ELF object")
        return binary

    @staticmethod
    def _symbol_scan(binary: lief.ELF.Binary, arch: str) -> list[SslOffset]:
        """Search the ELF symbol table for known SSL function names.

        Compatible with LIEF ≥ 0.13 and ≥ 0.14 (unified ``.symbols`` API).
        Each matched symbol is enriched with bypass metadata from
        :data:`_SSL_SYMBOL_METADATA` so the Frida template can emit the
        correct ``NativeCallback`` signature and return value.

        Args:
            binary: Parsed LIEF ELF binary.
            arch: ABI string to embed in result metadata.

        Returns:
            List of :class:`SslOffset` for each matched symbol with non-zero VA.
        """
        offsets: list[SslOffset] = []

        # LIEF ≥ 0.14 unified the symbol table under `.symbols`.
        try:
            all_symbols = list(binary.symbols)
        except AttributeError:
            all_symbols = list(binary.dynamic_symbols) + list(
                getattr(binary, "static_symbols", [])
            )

        for sym in all_symbols:
            name: str = sym.name
            if not name:
                continue
            for target in _SSL_SYMBOLS:
                if target in name:
                    va: int = sym.value
                    if va == 0:
                        continue
                    file_off = BinaryAnalyzer._va_to_file_offset(binary, va)
                    # Resolve per-symbol Frida hook metadata, falling back to defaults.
                    meta = _SSL_SYMBOL_METADATA.get(target) or _SSL_SYMBOL_METADATA.get(name)
                    if meta is None:
                        meta = _SSL_SYMBOL_METADATA["_default"]
                    offsets.append(
                        SslOffset(
                            symbol=name,
                            virtual_address=va,
                            file_offset=file_off,
                            method="symbol",
                            arch=arch,
                            bypass_return=meta["bypass_return"],
                            return_type=meta["return_type"],
                            arg_types=list(meta["arg_types"]),
                        )
                    )
                    log.debug("Symbol match: %s @ VA=0x%x  file_off=0x%x", name, va, file_off)
                    break  # avoid double-matching the same symbol against multiple targets

        return offsets

    # ------------------------------------------------------------------
    # Strategy 2 — string XREF scan (ARM64 ADRP+ADD cross-reference)
    # ------------------------------------------------------------------

    #: The needle string BoringSSL embeds in its TLS alert table.
    #: Present in every Flutter Engine release regardless of obfuscation.
    _XREF_NEEDLE: bytes = b"ssl_client"

    #: ARM64 sections to search for the needle string (in priority order).
    _XREF_SEARCH_SECTIONS: tuple[str, ...] = (".rodata", ".data.rel.ro", ".data")

    #: Maximum bytes to walk backwards from an XREF site when hunting for
    #: the function prologue.  1 024 instructions × 4 bytes = 4 096 bytes.
    _XREF_MAX_PROLOGUE_SCAN: int = 4096

    def find_offset_via_xref(
        self,
        lib_path: Path,
        arch: str | None = None,
    ) -> list[SslOffset]:
        """Public entry-point for the string XREF detection strategy.

        Parses *lib_path* with LIEF, locates the ``"ssl_client"`` byte string
        in ``.rodata``, then traces every ARM64 ADRP+ADD instruction pair in
        ``.text`` that references that string.  For each reference site the
        method walks backwards to the nearest ``STP X29, X30, [SP, #-N]!``
        prologue, which marks the function entry point.

        This is the preferred strategy when byte-pattern matching fails due to
        Flutter Engine obfuscation, because it relies on the *semantics* of the
        code (string references) rather than the exact byte encoding.

        .. note::
            Only ``arm64-v8a`` binaries are supported by the static ADRP
            decoder.  For other architectures the method returns ``[]`` without
            error; the remaining strategies continue normally.

        Args:
            lib_path: Path to ``libflutter.so``.
            arch: ABI string.  Inferred from the parent directory name if
                ``None``.

        Returns:
            List of :class:`SslOffset` instances, one per discovered XREF
            site.  May be empty if the needle string is absent, no ADRP+ADD
            pair is found, or the function prologue cannot be located.

        Raises:
            BinaryParseError: If LIEF cannot parse *lib_path*.
            FileNotFoundError: If *lib_path* does not exist.
        """
        if not lib_path.exists():
            raise FileNotFoundError(f"Library not found: {lib_path}")
        if arch is None:
            arch = lib_path.parent.name
        binary = self._parse_binary(lib_path)
        return self._xref_scan(binary, arch)

    def _xref_scan(
        self,
        binary: lief.ELF.Binary,
        arch: str,
    ) -> list[SslOffset]:
        """Run the full string XREF pipeline on a pre-parsed binary.

        Broken out from :meth:`find_offset_via_xref` so :meth:`find_ssl_offsets`
        can call it without re-parsing the binary.

        Args:
            binary: Parsed LIEF ELF binary.
            arch: ABI string used for filtering and result metadata.

        Returns:
            List of :class:`SslOffset` found via XREF analysis.  Returns ``[]``
            immediately for any non-arm64-v8a architecture.
        """
        if arch != "arm64-v8a":
            log.debug(
                "XREF scan: skipped for arch=%s (only arm64-v8a is supported).", arch
            )
            return []

        # Step 1: Locate the needle string in a read-only data section.
        string_va = self._find_string_va(binary, self._XREF_NEEDLE)
        if string_va is None:
            log.debug(
                "XREF scan: needle %r not found in any data section.",
                self._XREF_NEEDLE.decode(),
            )
            return []
        log.debug(
            "XREF scan: needle %r found at VA=0x%x.",
            self._XREF_NEEDLE.decode(),
            string_va,
        )

        # Step 2: Find every ADRP+ADD instruction pair that loads string_va.
        xref_vas = self._find_adrp_add_xrefs(binary, string_va)
        if not xref_vas:
            log.debug(
                "XREF scan: no ADRP+ADD references to VA=0x%x found in .text.",
                string_va,
            )
            return []
        log.debug("XREF scan: found %d ADRP+ADD reference(s).", len(xref_vas))

        # Step 3: Walk backwards from each XREF site to the function prologue.
        offsets: list[SslOffset] = []
        seen_prologues: set[int] = set()
        for xref_va in xref_vas:
            prologue_va = self._find_function_start(
                binary, xref_va, self._XREF_MAX_PROLOGUE_SCAN
            )
            if prologue_va is None:
                log.debug(
                    "XREF scan: could not find prologue for xref at VA=0x%x.",
                    xref_va,
                )
                continue
            if prologue_va in seen_prologues:
                continue  # Multiple xref sites in the same function — deduplicate.
            seen_prologues.add(prologue_va)

            file_off = self._va_to_file_offset(binary, prologue_va)
            offsets.append(
                SslOffset(
                    symbol="ssl_crypto_x509_session_verify_cert_chain [xref:ssl_client]",
                    virtual_address=prologue_va,
                    file_offset=file_off,
                    method="xref",
                    arch=arch,
                    bypass_return=1,       # bool: chain verified OK
                    return_type="int",
                    arg_types=["pointer", "int"],
                )
            )
            log.info(
                "XREF hit: ssl_crypto_x509_session_verify_cert_chain  "
                "VA=0x%x  file_off=0x%x  (xref_site=0x%x)",
                prologue_va,
                file_off,
                xref_va,
            )

        return offsets

    # -- ARM64 instruction decoders ----------------------------------------

    @staticmethod
    def _find_string_va(binary: lief.ELF.Binary, needle: bytes) -> int | None:
        """Scan read-only data sections for *needle* and return its VA.

        Checks ``.rodata``, ``.data.rel.ro``, and ``.data`` in that order.
        Returns the VA of the *first* occurrence, or ``None`` if absent.

        Args:
            binary: Parsed LIEF ELF binary.
            needle: Byte string to search for (e.g. ``b"ssl_client"``).

        Returns:
            ELF virtual address of the start of *needle*, or ``None``.
        """
        for section_name in BinaryAnalyzer._XREF_SEARCH_SECTIONS:
            section = binary.get_section(section_name)
            if section is None:
                continue
            content = bytes(section.content)
            idx = content.find(needle)
            if idx != -1:
                va = section.virtual_address + idx
                log.debug(
                    "_find_string_va: %r found in %s at idx=%d  VA=0x%x",
                    needle.decode(errors="replace"),
                    section_name,
                    idx,
                    va,
                )
                return va
        return None

    @staticmethod
    def _decode_adrp_target(instr: int, pc: int) -> int | None:
        """Decode an ARM64 ADRP instruction and return the target *page* VA.

        ADRP (Address of Page) loads the base address of a 4 KB page into a
        register using a PC-relative, page-aligned immediate::

            target_page = ALIGN_DOWN(PC, 4096) + sign_extend(imm21) << 12

        Encoding layout (ARMv8-A reference, C6.2.10)::

            [31]    = 1          (marks ADRP vs ADR)
            [30:29] = immlo      (low 2 bits of the 21-bit immediate)
            [28:24] = 10000      (ADRP opcode)
            [23:5]  = immhi      (high 19 bits)
            [4:0]   = Rd

        Args:
            instr: 32-bit instruction word (little-endian).
            pc: Virtual address of this instruction.

        Returns:
            Target page VA, or ``None`` if *instr* is not an ADRP instruction.
        """
        if (instr & 0x9F000000) != 0x90000000:
            return None
        immlo: int = (instr >> 29) & 0x3
        immhi: int = (instr >> 5) & 0x7FFFF
        raw_imm: int = (immhi << 2) | immlo          # 21-bit concatenation
        scaled: int = raw_imm << 12                  # scaled to page boundary
        # Sign-extend from 33 bits (21 + 12 shift).
        if scaled & (1 << 32):
            scaled -= 1 << 33
        return (pc & ~0xFFF) + scaled

    @staticmethod
    def _decode_add_imm12(instr: int) -> int | None:
        """Decode an ARM64 ``ADD Xd, Xn, #imm12`` instruction and return imm12.

        This handles the 64-bit register variant with shift=0.  The ADRP+ADD
        pair is the standard compiler idiom for loading a page-relative
        address into a register on AArch64.

        Encoding layout (ARMv8-A reference, C6.2.4)::

            [31:23] = 100100010  (ADD 64-bit, shift=0)
            [21:10] = imm12
            [9:5]   = Rn
            [4:0]   = Rd

        Args:
            instr: 32-bit instruction word.

        Returns:
            The unsigned 12-bit immediate, or ``None`` if *instr* is not a
            matching ``ADD`` instruction.
        """
        # Mask out imm12, Rn, Rd — only check the fixed opcode bits.
        # 0xFF800000 covers [31:23]; expected = 0x91000000 (shift=0, 64-bit).
        if (instr & 0xFF800000) != 0x91000000:
            return None
        return (instr >> 10) & 0xFFF

    def _find_adrp_add_xrefs(
        self,
        binary: lief.ELF.Binary,
        string_va: int,
    ) -> list[int]:
        """Enumerate ``.text`` instruction addresses that load *string_va* via ADRP+ADD.

        Iterates over the ``.text`` section four bytes at a time (ARM64 uses
        fixed-width 32-bit instructions).  For each ADRP whose target page
        equals ``string_va & ~0xFFF``, the immediately following ADD is checked
        for the matching low-12-bit offset.  A confirmed pair is recorded as an
        XREF site.

        Args:
            binary: Parsed LIEF ELF binary.
            string_va: Virtual address of the target string (from
                :meth:`_find_string_va`).

        Returns:
            List of VAs (one per XREF site, pointing at the ADRP instruction).
        """
        text = binary.get_section(".text")
        if text is None:
            log.debug("_find_adrp_add_xrefs: no .text section.")
            return []

        content: bytes = bytes(text.content)
        text_va: int = text.virtual_address
        target_page: int = string_va & ~0xFFF
        target_off12: int = string_va & 0xFFF

        xrefs: list[int] = []
        # Each ARM64 instruction is 4 bytes; stop 4 bytes early to safely
        # peek at the following ADD instruction.
        for i in range(0, len(content) - 7, 4):
            instr1 = int.from_bytes(content[i : i + 4], "little")
            pc = text_va + i
            adrp_page = self._decode_adrp_target(instr1, pc)
            if adrp_page != target_page:
                continue
            instr2 = int.from_bytes(content[i + 4 : i + 8], "little")
            add_off = self._decode_add_imm12(instr2)
            if add_off == target_off12:
                xrefs.append(pc)
                log.debug(
                    "_find_adrp_add_xrefs: XREF at VA=0x%x  "
                    "(ADRP page=0x%x  ADD off=0x%x)",
                    pc,
                    adrp_page,
                    add_off,
                )
        return xrefs

    @staticmethod
    def _find_function_start(
        binary: lief.ELF.Binary,
        xref_va: int,
        max_scan_bytes: int = 4096,
    ) -> int | None:
        """Walk backwards from *xref_va* to find the nearest ARM64 function prologue.

        Looks for the ``STP X29, X30, [SP, #-N]!`` (pre-indexed store pair)
        instruction that opens an ABI-compliant stack frame on AArch64::

            Little-endian bytes:  FD  7B  ??  A9
            32-bit mask:          0xFF00FFFF
            Expected pattern:     0xA9007BFD

        The ``??`` byte encodes the signed 7-bit ``imm7`` field (stack frame
        size) which varies per function.  Any value is accepted.

        Args:
            binary: Parsed LIEF ELF binary.
            xref_va: VA of the ADRP instruction that references the target
                string.
            max_scan_bytes: Maximum bytes to walk backwards before giving up
                (default 4 096 = 1 024 ARM64 instructions).

        Returns:
            VA of the function entry-point instruction, or ``None`` if no
            prologue is found within *max_scan_bytes*.
        """
        text = binary.get_section(".text")
        if text is None:
            return None

        content: bytes = bytes(text.content)
        text_va: int = text.virtual_address
        start_idx: int = xref_va - text_va

        if start_idx < 0 or start_idx >= len(content):
            return None

        # Walk backwards 4 bytes at a time.
        low = max(0, start_idx - max_scan_bytes)
        for i in range(start_idx, low - 1, -4):
            word = int.from_bytes(content[i : i + 4], "little")
            # STP X29, X30, [SP, #-N]!  — any frame size.
            if (word & 0xFF00FFFF) == 0xA9007BFD:
                return text_va + i
        return None

    # ------------------------------------------------------------------
    # Strategy 3 — byte-pattern scan
    # ------------------------------------------------------------------

    # Minimum number of non-wildcard (concrete) bytes a pattern must contain
    # before it is considered specific enough to scan.  Patterns below this
    # threshold are far too generic and will produce hundreds of false positives
    # across .text (e.g. a plain ARM64 function-prologue pattern).
    _MIN_CONCRETE_BYTES: int = 6

    def _pattern_scan(
        self,
        binary: lief.ELF.Binary,
        arch: str,
        engine_version: EngineVersion,
    ) -> list[SslOffset]:
        """Scan the ``.text`` section for known SSL-bypass byte patterns.

        Patterns are filtered by architecture and (optionally) Flutter version
        prefix before scanning.  Each ``??`` token in the pattern string becomes
        a regex ``.`` that matches exactly one byte.

        Each pattern entry in ``patterns.yaml`` may supply:

        * ``max_matches`` (int, default ``1``) — stop after this many hits.
          SSL functions appear exactly once; a generic prologue pattern that
          matches hundreds of functions should still only contribute one
          candidate (the first hit), not hundreds of false-positive patches.
        * ``bypass_return`` (int, default ``0``) — value the Frida hook returns.
        * ``return_type`` (str, default ``"int"``) — Frida NativeCallback type.
        * ``arg_types`` (list[str], default ``["pointer","pointer"]``) — args.

        Args:
            binary: Parsed LIEF ELF binary.
            arch: ABI string for filtering and result metadata.
            engine_version: Used for version-specific pattern filtering.

        Returns:
            List of :class:`SslOffset` for each pattern match found.
        """
        offsets: list[SslOffset] = []

        text_section = binary.get_section(".text")
        if text_section is None:
            log.warning("No .text section in binary — skipping pattern scan.")
            return offsets

        section_content: bytes = bytes(text_section.content)
        if not section_content:
            log.warning(".text section is empty — skipping pattern scan.")
            return offsets

        section_va: int = text_section.virtual_address
        log.debug(
            "Pattern scan: .text  VA=0x%x  size=%d bytes  patterns=%d",
            section_va,
            len(section_content),
            len(self._patterns),
        )

        for pat_entry in self._patterns:
            pat_arch: str = pat_entry.get("arch", "*")
            if pat_arch != "*" and pat_arch != arch:
                continue

            pat_version: str = pat_entry.get("version", "*")
            if (
                pat_version != "*"
                and engine_version.version_string is not None
                and not engine_version.version_string.startswith(pat_version)
            ):
                continue

            symbol: str = pat_entry.get("symbol", "unknown_ssl_fn")
            pattern_hex: str = pat_entry.get("pattern", "")

            # ── Concrete-byte guard ───────────────────────────────────────────
            # Count the number of fixed (non-wildcard) bytes in the pattern.
            # Patterns with too few concrete bytes are dangerously generic and
            # will match common function prologues hundreds of times.
            tokens = pattern_hex.strip().split()
            concrete_count = sum(1 for t in tokens if t != "??")
            if concrete_count < self._MIN_CONCRETE_BYTES:
                log.warning(
                    "Pattern '%s' has only %d concrete byte(s) — skipping "
                    "(threshold: %d). Add more discriminating bytes to patterns.yaml.",
                    symbol,
                    concrete_count,
                    self._MIN_CONCRETE_BYTES,
                )
                continue

            compiled = self._compile_pattern(pattern_hex)
            if compiled is None:
                continue

            # ── Per-pattern Frida hook metadata ──────────────────────────────
            max_matches: int = int(pat_entry.get("max_matches", 1))
            bypass_return: int = int(pat_entry.get("bypass_return", 0))
            return_type: str = str(pat_entry.get("return_type", "int"))
            raw_arg_types = pat_entry.get("arg_types", ["pointer", "pointer"])
            arg_types: list[str] = list(raw_arg_types)

            # ── Bounded match iteration ───────────────────────────────────────
            match_count = 0
            total_hits = 0
            for match in compiled.finditer(section_content):
                total_hits += 1
                if match_count < max_matches:
                    rel_offset = match.start()
                    va = section_va + rel_offset
                    file_off = self._va_to_file_offset(binary, va)
                    offsets.append(
                        SslOffset(
                            symbol=symbol,
                            virtual_address=va,
                            file_offset=file_off,
                            method="pattern",
                            arch=arch,
                            bypass_return=bypass_return,
                            return_type=return_type,
                            arg_types=arg_types,
                        )
                    )
                    log.debug(
                        "Pattern match: %-50s  VA=0x%x  file_off=0x%x  (arch=%s)",
                        symbol,
                        va,
                        file_off,
                        arch,
                    )
                    match_count += 1

            if total_hits > max_matches:
                log.warning(
                    "Pattern '%s' matched %d time(s) in .text but max_matches=%d; "
                    "keeping first %d. Consider tightening the pattern in patterns.yaml.",
                    symbol,
                    total_hits,
                    max_matches,
                    max_matches,
                )

        return offsets

    @staticmethod
    def _compile_pattern(pattern_hex: str) -> re.Pattern[bytes] | None:
        """Convert a hex-string pattern (with ``??`` wildcards) to a regex.

        Each space-separated token is either a two-digit hex byte or the
        wildcard ``"??"`` which matches any single byte.

        Args:
            pattern_hex: Space-separated hex token string, e.g.
                ``"FD 7B ?? A9 FD 03 00 91"``.

        Returns:
            Compiled :class:`re.Pattern[bytes]`, or ``None`` if the input is
            empty, malformed, or contains an invalid token.

        Example::

            pat = BinaryAnalyzer._compile_pattern("55 8B ?? C3")
            assert pat.search(b"\\x55\\x8b\\x42\\xc3") is not None
        """
        if not pattern_hex or not pattern_hex.strip():
            return None

        parts: list[bytes] = []
        for token in pattern_hex.strip().split():
            if token == "??":
                parts.append(b".")           # regex dot — matches any one byte
            else:
                try:
                    byte_val = bytes.fromhex(token)
                    parts.append(re.escape(byte_val))
                except ValueError:
                    log.warning("Invalid pattern token %r — skipping entire pattern.", token)
                    return None

        try:
            return re.compile(b"".join(parts), re.DOTALL)
        except re.error as exc:
            log.warning("Pattern compile error: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Strategy 3 — version-map offset lookup
    # ------------------------------------------------------------------

    def _version_map_lookup(
        self,
        engine_version: EngineVersion,
        arch: str,
    ) -> list[SslOffset]:
        """Look up pre-computed SSL offsets from the version-map YAML.

        The lookup key is the engine's 40-character hash (``engine_hash``),
        falling back to the GNU Build-ID (``build_id``) if the hash is absent.

        The ``offsets`` block of ``data/version_map.yaml`` has the structure::

            offsets:
              "<40-char-hash>":
                - symbol: ssl_verify_peer_cert
                  arch: arm64-v8a
                  virtual_address: 0x512ab80
                  file_offset: 0x112ab80

        Args:
            engine_version: Engine version object supplying the lookup key.
            arch: ABI string for filtering and result metadata.

        Returns:
            List of :class:`SslOffset` from the map entry, or empty list if
            no matching entry is found.
        """
        lookup_key = engine_version.engine_hash or engine_version.build_id
        if not lookup_key:
            log.debug("Version-map lookup skipped: no engine hash or Build-ID available.")
            return []

        entries = self._version_map_offsets.get(lookup_key, [])
        if not entries:
            log.debug("Version-map lookup: no entry for key=%s", lookup_key[:12] + "…")
            return []

        offsets: list[SslOffset] = []
        for entry in entries:
            entry_arch = entry.get("arch", "*")
            if entry_arch != "*" and entry_arch != arch:
                continue
            symbol = entry.get("symbol", "unknown_ssl_fn")
            va = int(entry.get("virtual_address", 0))
            file_off = int(entry.get("file_offset", 0))
            if va == 0 and file_off == 0:
                continue
            offsets.append(
                SslOffset(
                    symbol=symbol,
                    virtual_address=va,
                    file_offset=file_off,
                    method="version_map",
                    arch=arch,
                )
            )
            log.debug(
                "Version-map hit: %-50s  VA=0x%x  file_off=0x%x", symbol, va, file_off
            )

        if offsets:
            log.info(
                "Version-map lookup returned %d offset(s) for key %s…",
                len(offsets),
                lookup_key[:12],
            )
        return offsets

    # ------------------------------------------------------------------
    # YAML loaders
    # ------------------------------------------------------------------

    @staticmethod
    def _load_patterns() -> list[dict[str, str]]:
        """Load SSL pinning byte patterns from ``data/patterns.yaml``.

        Returns:
            List of pattern entry dicts.  Empty list if file is missing or
            malformed.
        """
        if not _PATTERNS_PATH.exists():
            log.warning("patterns.yaml not found at %s", _PATTERNS_PATH)
            return []
        try:
            with _PATTERNS_PATH.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            return list(data.get("patterns", []))
        except Exception as exc:
            log.warning("Failed to load patterns.yaml: %s", exc)
            return []

    @staticmethod
    def _load_version_map_offsets() -> dict[str, list[dict]]:
        """Load pre-computed SSL offsets from the ``offsets`` block of version_map.yaml.

        The ``offsets`` block maps engine-hash strings to lists of offset dicts.
        This is separate from the top-level Build-ID → version-string entries.

        Returns:
            Dict mapping engine hash strings to lists of offset entry dicts.
        """
        if not _VERSION_MAP_PATH.exists():
            log.debug("version_map.yaml not found at %s", _VERSION_MAP_PATH)
            return {}
        try:
            with _VERSION_MAP_PATH.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            raw = data.get("offsets", {}) or {}
            return {str(k): list(v) for k, v in raw.items() if isinstance(v, list)}
        except Exception as exc:
            log.warning("Failed to load version_map.yaml offsets block: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # VA → file offset helper
    # ------------------------------------------------------------------

    @staticmethod
    def _va_to_file_offset(binary: lief.ELF.Binary, va: int) -> int:
        """Convert an ELF virtual address to its raw file byte offset.

        Iterates over all loadable (``PT_LOAD``) segments to find the one
        that contains *va* and computes the file offset as::

            file_offset = segment.file_offset + (va - segment.virtual_address)

        Args:
            binary: Parsed LIEF ELF binary.
            va: Virtual address to convert.

        Returns:
            File offset in bytes from the start of the file.  Returns ``0``
            if *va* does not fall within any loadable segment (e.g. for purely
            virtual addresses or stripped binaries with no segment headers).
        """
        for seg in binary.segments:
            seg_va: int = seg.virtual_address
            seg_size: int = seg.virtual_size or seg.file_size
            if seg_va <= va < seg_va + seg_size:
                return seg.file_offset + (va - seg_va)
        return 0
