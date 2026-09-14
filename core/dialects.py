"""Command dialect layer: posix | cmd | powershell.

Why this module exists
----------------------
The classifier's effect vocabulary was written for POSIX shells (`rm`,
`rmdir`, `unlink`, `shred`, `find -delete`, `git ...`). On native Windows
shells the destructive intent is expressed by entirely different programs
(`del`, `erase`, `rd`, `rmdir`, `Remove-Item`, ...) and with different
lexical rules (no backslash escapes inside double quotes, `^` as the
caret escape, command separator `&` instead of `&&`, PowerShell's own
quoting and parameter syntax).

This module isolates *dialect* concerns so `classifier.classify_command`
can stay dialect-agnostic:

  tokenize_<dialect>(cmd) -> TokenStream
      Lexical stage only: split a command line into segments of words,
      split segments on the dialect's separators, and record whether the
      dialect's quoting rules could not be applied.

  DIALECTS[<name>].classify(stream) -> List[OpSpec]
      Structural stage: recognise the destructive programs of that
      dialect and map their flags onto the shared effect facts
      (recursive / force / dry_run / wildcard / undeterminable).

Design rules (mirroring the core's):

* **Fail closed.** Any construct the dialect parser cannot resolve
  mechanically - unbalanced quotes, `%VAR%` / `$(...)` / backtick
  substitution, `-WhatIf:$false`, command nesting, input piped from
  another process, a wildcard handed to a tool that expands it itself -
  becomes an `undeterminable` fact. The policy layer turns those into
  BLOCK. We never guess what a target set will be.
* **Additive.** The POSIX dialect preserves the exact behaviour of the
  historical `shlex`-based path, including the ALIAS vocabulary
  (`rm`/`ri`/`del` in PowerShell). The default dialect stays POSIX, so
  every existing adapter (Claude hook, DSH plugin, check.py CLI) is
  unaffected until a caller opts in.
* **Facts, not decisions.** Like the rest of the classifier, a dialect
  returns OpSpecs only; it never decides ALLOW/BLOCK.

Not in Phase 1: real Windows end-to-end execution, UNC/device-path
semantics, PowerShell module auto-loading, and cmd's full `%~` modifier
set beyond the forms that are mechanically resolvable.
"""
from __future__ import annotations

import dataclasses
import os
import re
import shlex
from typing import List, Optional, Sequence, Tuple

# Kept in sync with classifier.py; importing it here would create a cycle
# because classifier imports this module.
_OP_SPEC_DEFAULTS = {
    "op": "", "kind": "other", "sub": None, "targets": (),
    "recursive": False, "force": False, "dry_run": False,
    "extra_flags": (), "segment_index": 0, "wildcard": False,
    "undeterminable": False, "shape": None, "notes": (),
}

# ------------------------------------------------------------------ dialects

DIALECT_POSIX = "posix"
DIALECT_CMD = "cmd"
DIALECT_POWERSHELL = "powershell"

DIALECT_ALIASES = {
    "posix": DIALECT_POSIX,
    "sh": DIALECT_POSIX,
    "bash": DIALECT_POSIX,
    "zsh": DIALECT_POSIX,
    "cmd": DIALECT_CMD,
    "cmd.exe": DIALECT_CMD,
    "batch": DIALECT_CMD,
    "bat": DIALECT_CMD,
    "powershell": DIALECT_POWERSHELL,
    "pwsh": DIALECT_POWERSHELL,
    "ps": DIALECT_POWERSHELL,
}

DEFAULT_DIALECT = DIALECT_POSIX

# PowerShell ships a *suffix* rule: `del` resolves to the MDAC `del` alias
# for Remove-Item (SQL column masters only in legacy hosts). Bounded
# allowlist of the aliases we are willing to expand - anything else
# (including user-defined aliases) stays unrecognised rather than guessed.
POWERSHELL_ALIASES = {
    "rm": "remove-item",
    "ri": "remove-item",
    "rd": "remove-item",
    "rmdir": "remove-item",
    "del": "remove-item",
    "erase": "remove-item",
    "remove-item": "remove-item",
}
# NOTE: `erase` is *not* a PowerShell alias (it is a cmd builtin) - listing
# it here is a deliberate over-approximation: a Windows console session
# routinely mixes the two vocabularies, and expanding `erase` to
# Remove-Item yields the same effect fact either way. The alternative
# (ignoring the line) would be a silent allow.

# Windows console encodings: the OEM code page is the truth for cmd, and
# both batches of tests run on Linux CI, so decode UTF-8 first and fall
# back to a Latin-1 round-trip (every byte maps, nothing is silently lost).
_CONSOLE_ENCODINGS = ("utf-8", "cp437", "cp1252")

# Argument-count invariants for cmd builtins, so phrase splitting can tell
# `del /s a b` (two targets) from `rmdir /s /q "a b"` (one quoted target).
# ---------------------------------------------------------------- tokenizer


@dataclasses.dataclass
class TokenStream:
    """Dialect-neutral lexical result handed to a dialect classifier."""

    dialect: str
    segments: List[List[str]] = dataclasses.field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def words(self) -> List[str]:
        return [w for seg in self.segments for w in seg]


class TokenizeError(ValueError):
    """Raised by a tokenizer when the dialect's quoting rules do not apply."""


# ------------------------------------------------------------------- posix


def _strip_group_edges(seg: List[str]) -> List[str]:
    """Drop subshell/grouping parens that shlex glued onto words."""
    while seg and seg[0][:1] in ("(", "{"):
        seg[0] = seg[0][1:]
        if not seg[0]:
            seg.pop(0)
    while seg and seg[-1][-1:] in (")", "}"):
        seg[-1] = seg[-1][:-1]
        if not seg[-1]:
            seg.pop()
    return seg


def tokenize_posix(cmd: str, separators: Sequence[str] = ()) -> TokenStream:
    """Tokenize with the historical `shlex` path (behaviour-preserving).

    The caller (classifier) owns heredoc stripping and segment splitting so
    the POSIX path stays byte-for-byte identical to the pre-dialect code.
    """
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError as exc:
        return TokenStream(DIALECT_POSIX, [], error=str(exc))
    return TokenStream(DIALECT_POSIX, [tokens] if tokens else [])


# --------------------------------------------------------------------- cmd


CMD_SEPARATORS = ("&", "&&", "||", "|", "\n")
def _decode_console(cmd: str) -> str:
    if isinstance(cmd, bytes):  # pragma: no cover - defensive
        return cmd.decode("utf-8", "surrogateescape")
    return cmd


def tokenize_cmd(cmd: str, separators: Sequence[str] = CMD_SEPARATORS) -> TokenStream:
    """Tokenize a `cmd.exe` command line.

    Rules that differ from POSIX and matter for classification:

    * double quotes group but do **not** honour backslash escapes, and a
      backslash inside quotes stays literal (so `rmdir /s "C:\\tmp\\"` is
      one argument, backslash included);
    * `^` is the escape character *outside* quotes and is stripped;
    * `&`, `&&`, `|`, `||` are always separators, even unquoted inside a
      word (`a&del b` is two commands);
    * `%VAR%` is not expanded - the token is kept verbatim and a later
      stage marks it undeterminable.

    Raises TokenizeError on an unterminated quote.
    """
    text = _decode_console(cmd)
    segments: List[List[str]] = []
    current: List[str] = []
    words: List[str] = []
    quote_open = False
    quote_char = ""
    idx = 0
    length = len(text)

    def flush_word() -> None:
        if current:
            words.append("".join(current))
            current.clear()

    def flush_segment() -> None:
        flush_word()
        if words:
            segments.append(list(words))
            words.clear()

    while idx < length:
        ch = text[idx]
        if quote_open:
            if ch == quote_char:
                quote_open = False
            else:
                current.append(ch)
            idx += 1
            continue

        if ch == '"':
            quote_open = True
            quote_char = ch
            idx += 1
            continue

        if ch == "^" and separators:
            # Caret escape: the next character is literal, including
            # separators and quotes.
            nxt = text[idx + 1] if idx + 1 < length else ""
            current.append(nxt)
            idx += 2
            continue

        matched = next((s for s in sorted(separators, key=len, reverse=True)
                        if text.startswith(s, idx)), None)
        if matched:
            flush_segment()
            idx += len(matched)
            continue

        if ch in " \t":
            flush_word()
            if separators and text.startswith("\n", idx):
                flush_segment()
            idx += 1
            continue

        current.append(ch)
        idx += 1

    if quote_open:
        raise TokenizeError("unbalanced quote in cmd command line")
    flush_segment()
    return TokenStream(DIALECT_CMD, segments)


# ------------------------------------------------------------ powershell

PS_SEPARATORS = (";", "|", "||", "&&", "&", "\n")


def tokenize_powershell(cmd: str, separators: Sequence[str] = PS_SEPARATORS) -> TokenStream:
    """Tokenize a PowerShell command line.

    Handles the lexical rules that change the *word* set:

    * single quotes are literal (no escapes at all, `''` is one quote);
    * double quotes group and honour the backtick escape;
    * backtick escapes the next character outside quotes;
    * `;`, `|`, `&` separate commands.

    `$var`, `$(...)`, `@(...)`, subexpressions and script blocks are *not*
    resolved. They survive into the tokens and mark the operation
    undeterminable downstream (fail closed). Raises TokenizeError on an
    unterminated quote.
    """
    text = _decode_console(cmd)
    segments: List[List[str]] = []
    words: List[str] = []
    current: List[str] = []
    quote: Optional[str] = None
    idx = 0
    length = len(text)

    def flush_word() -> None:
        if current:
            words.append("".join(current))
            current.clear()

    def flush_segment() -> None:
        flush_word()
        if words:
            segments.append(list(words))
            words.clear()

    while idx < length:
        ch = text[idx]
        if quote == "'":
            if ch == "'":
                if idx + 1 < length and text[idx + 1] == "'":
                    current.append("'")
                    idx += 2
                    continue
                quote = None
                idx += 1
                continue
            current.append(ch)
            idx += 1
            continue
        if quote == '"':
            if ch == '"':
                quote = None
                idx += 1
                continue
            if ch == "`" and idx + 1 < length:
                current.append(text[idx + 1])
                idx += 2
                continue
            if ch == "$":
                # `$` inside double quotes interpolates; record the whole
                # subexpression verbatim so downstream sees the danger.
                end = _ps_subexpression_end(text, idx)
                current.append(text[idx:end])
                idx = end
                continue
            current.append(ch)
            idx += 1
            continue

        if ch in "'\"":
            quote = ch
            idx += 1
            continue
        if ch == "`" and idx + 1 < length:
            current.append(text[idx + 1])
            idx += 2
            continue
        if ch == "$":
            end = _ps_subexpression_end(text, idx)
            current.append(text[idx:end])
            idx = end
            continue

        matched = next((s for s in sorted(separators, key=len, reverse=True)
                        if text.startswith(s, idx)), None)
        if matched:
            flush_segment()
            idx += len(matched)
            continue

        if ch in " \t":
            flush_word()
            idx += 1
            continue

        current.append(ch)
        idx += 1

    if quote is not None:
        raise TokenizeError("unbalanced quote in PowerShell command line")
    flush_segment()
    return TokenStream(DIALECT_POWERSHELL, segments)


def _ps_subexpression_end(text: str, start: int) -> int:
    """End index of a PowerShell `$...` token starting at `start`."""
    if text.startswith("$(", start):
        depth = 0
        idx = start + 1
        while idx < len(text):
            if text[idx] == "(":
                depth += 1
            elif text[idx] == ")":
                depth -= 1
                if depth == 0:
                    return idx + 1
            idx += 1
        return len(text)  # unbalanced: let the parser call it undeterminable
    match = re.match(r"\$[A-Za-z_][A-Za-z0-9_:]*|\$[?^$]", text[start:])
    if match:
        return start + match.end()
    return start + 1


# --------------------------------------------- dialect-neutral fact helpers


# Smell test for an opaque nested host script (the inner text cannot be
# parsed). Deliberately independent from the POSIX smell vocabulary: the
# strings arriving here are PowerShell, and "unknown-dialect leak" is
# exactly what a shared regex would hide.
NESTED_SMELL_RE = re.compile(
    r"(?:^|[\s;&|(=/])(rm|ri|rd|rmdir|del|erase|remove-item)\b"
    r"|clear-content\b|-delete\b|\bdelete\b",
    re.IGNORECASE)


def has_interpolation(word: str) -> bool:
    """True when a word carries dialect substitution the guard cannot resolve."""
    if "$" in word or "`" in word:
        return True
    if "%" in word and re.search(r"%[^%]+%", word):
        return True
    return False


def to_op_spec(cls, **facts):
    """Build an OpSpec from dialect facts, tolerating inventory changes."""
    names = {f.name for f in dataclasses.fields(cls)}
    kwargs = {}
    for key, value in _OP_SPEC_DEFAULTS.items():
        if key not in names:
            continue
        kwargs[key] = list(value) if isinstance(value, (list, tuple)) else value
    kwargs.update({k: v for k, v in facts.items() if k in names})
    return cls(**kwargs)


# ------------------------------------------------------------- cmd classify

CMD_DELETE_CMDS = {"del", "erase", "rd", "rmdir"}
CMD_ALIASES = {"delete": "del", "remove": "del"}

# `del` is the delete file builtin; `/a` additionally removes files whose
# attributes match. `rd`/`rmdir` remove directories and, with `/s`, whole
# trees. Both accept a space-separated target list.
_CMD_DEL_FLAGS = {
    "f": "force", "q": "force", "s": "recursive", "p": None, "a": None,
    "n": None,
}
_CMD_RD_FLAGS = {"s": "recursive", "q": "force"}


def _cmd_strip_quotes(word: str) -> str:
    if len(word) >= 2 and word[0] == '"' and word[-1] == '"':
        return word[1:-1]
    return word


def classify_cmd(stream: TokenStream, kind_fs_delete: str,
                 op_spec_cls) -> List[object]:
    """Recognise cmd.exe destructive commands in a token stream."""
    specs: List[object] = []
    for index, segment in enumerate(stream.segments):
        head_raw = _cmd_strip_quotes(segment[0]).lower()
        head_raw = CMD_ALIASES.get(head_raw, head_raw)
        if head_raw not in CMD_DELETE_CMDS:
            continue
        spec = to_op_spec(op_spec_cls, op=head_raw, kind=kind_fs_delete,
                          segment_index=index)
        flag_map = _CMD_RD_FLAGS if head_raw in ("rd", "rmdir") else _CMD_DEL_FLAGS
        rest = segment[1:]
        treated_as_flags = False
        for tok in rest:
            bare = _cmd_strip_quotes(tok)
            if bare.startswith("/") and len(bare) > 1 and not treated_as_flags:
                for ch in bare[1:].lower():
                    mapped = flag_map.get(ch, "unknown")
                    if mapped == "force":
                        spec.force = True
                    elif mapped == "recursive":
                        spec.recursive = True
                    elif mapped == "unknown":
                        spec.undeterminable = True
                        spec.note(f"unknown flag /{ch} for {head_raw}")
                continue
            treated_as_flags = True
            spec.targets.append(bare)
        if not spec.targets:
            spec.undeterminable = True
            spec.note(f"{head_raw} without a target; the target set is "
                      "not statically known")
        specs.append(spec)
    return specs


def classify_cmd_stream(stream: TokenStream) -> "List[object]":
    from .classifier import KIND_FS_DELETE, OpSpec  # local import: no cycle
    return classify_cmd(stream, KIND_FS_DELETE, OpSpec)


# ------------------------------------------------------ powershell classify

PS_DELETE_CMDS = {"remove-item"}
# Phase 1 keeps exactly one PowerShell delete cmdlet in scope. Wider
# cmdlets (Clear-Content, Remove-ItemProperty) mutate other provider
# object types whose compensation the guard does not implement yet, so
# they stay outside the recognised vocabulary instead of being mapped
# onto a filesystem relocation that would not restore them.

# Switches whose *value* changes what gets deleted: treating them as
# semantics-neutral would be a guess, so they are undeterminable.
_PS_UNSAFE_PARAMS = (
    "include", "exclude", "filter", "literalpath", "stream", "attributes",
    "credential", "confirm", "verbose", "debug", "erroraction",
    "warningaction", "errorvariable", "outvariable", "pipelinevariable",
)


def _ps_param_name(tok: str) -> Optional[Tuple[str, Optional[str]]]:
    """('name', 'value') for a `-Name`/`--Name:value` token, else None."""
    if not tok.startswith("-") or len(tok) < 2:
        return None
    body = tok.strip("-")
    if not body:
        return None
    name, sep, value = body.partition(":")
    return name.lower(), (value if sep else None)


def _ps_bool_value(value: Optional[str]) -> Optional[bool]:
    """Switch value semantics: `-Recurse:$false` is NOT recursive.

    Returns None when the value is itself a variable/subexpression - the
    caller must then fail closed instead of assuming a boolean.
    """
    if value is None or value == "":
        return True
    lowered = value.strip().lower()
    if lowered in ("$true", "true", "1"):
        return True
    if lowered in ("$false", "false", "0"):
        return False
    return None


def _ps_base_name(word: str) -> str:
    """Command name in object/string form, without path or `.exe` suffix."""
    cleaned = word.strip().strip("&").strip("'\"")
    base = os.path.basename(cleaned.replace("\\", "/")).lower()
    return base[:-4] if base.endswith(".exe") else base


def classify_powershell(stream: TokenStream, kind_fs_delete: str,
                        op_spec_cls, smell_re=None) -> List[object]:
    """Recognise PowerShell destructive commands in a token stream.

    A nested host (`powershell -Command "<script>"`, `pwsh -EncodedCommand`)
    is an interpreter hop: the guard cannot parse the inner script's
    structure, so the scripts stay opaque and only the *smell* test decides
    whether the line is handed to policy as an undeterminable UNKNOWN -
    the same fail-closed treatment POSIX `bash -c` receives.
    """
    specs: List[object] = []
    for index, segment in enumerate(stream.segments):
        head = segment[0]
        base_head = _ps_base_name(head)
        if base_head in ("powershell", "pwsh"):
            inner = " ".join(segment[1:])
            if smell_re is not None and smell_re.search(inner):
                spec = to_op_spec(op_spec_cls, op=base_head,
                                  kind="unknown", undeterminable=True,
                                  segment_index=index,
                                  targets=[inner[:200]])
                spec.note("nested PowerShell host with destructive smell; "
                          "the inner script cannot be parsed statically")
                specs.append(spec)
            continue
        base = base_head
        canonical = POWERSHELL_ALIASES.get(base, base)
        if canonical not in PS_DELETE_CMDS and base not in PS_DELETE_CMDS:
            continue
        spec = to_op_spec(op_spec_cls, op=canonical if canonical in
                          PS_DELETE_CMDS else base,
                          kind=kind_fs_delete, segment_index=index)
        if base != canonical:
            spec.note(f"alias '{base}' expanded to '{canonical}'")

        targets: List[str] = []
        end_of_params = False
        for tok in segment[1:]:
            if tok in ("--", "--%"):
                only_named = True
                continue
            param = None if end_of_params else _ps_param_name(tok)
            if param is None:
                targets.append(tok)
                continue
            name, value = param
            if name == "whatif":
                flag = _ps_bool_value(value)
                if flag is None:
                    spec.undeterminable = True
                    spec.note("-WhatIf value is not statically known")
                elif flag:
                    spec.dry_run = True
                    spec.note("-WhatIf: nothing is actually deleted")
                # -WhatIf:$false => effective deletion, no note needed
            elif name == "recurse":
                flag = _ps_bool_value(value)
                if flag is None:
                    spec.undeterminable = True
                    spec.note("-Recurse value is not statically known")
                else:
                    spec.recursive = flag
            elif name == "force":
                flag = _ps_bool_value(value)
                if flag is None:
                    spec.undeterminable = True
                    spec.note("-Force value is not statically known")
                else:
                    spec.force = flag
            elif name in ("literalpath", "lp"):
                spec.undeterminable = True
                spec.note("-LiteralPath: wildcard interpretation is not "
                          "statically known")
            elif name in ("path", "pspath"):
                # -Path is the default parameter set; its value is an
                # ordinary target list.
                pass
            elif name in ("erroraction", "ea"):
                spec.note("-ErrorAction does not change the effect")
            elif name == "confirm":
                # Only an interactive `-Confirm` prompt makes the guard's
                # static reasoning meaningless; `-Confirm:$false` deletes
                # without asking and must not look safer than it is.
                flag = _ps_bool_value(value)
                if flag is not False:
                    spec.undeterminable = True
                    spec.note("-Confirm prompts interactively; the executed "
                              "selection is not statically known")
            elif name in _PS_UNSAFE_PARAMS:
                spec.undeterminable = True
                spec.note(f"-{name.capitalize()} changes the target set; "
                          "not statically resolvable")
            else:
                spec.undeterminable = True
                spec.note(f"unknown parameter -{name}")

        if not targets and not spec.dry_run:
            spec.undeterminable = True
            spec.note("delete without an explicit target; the target set "
                      "arrives from the pipeline or a variable")
        spec.targets.extend(targets)
        if any(t.startswith("\\\\") for t in targets):
            spec.note("UNC path target; path resolution is host-dependent")
        specs.append(spec)
    return specs


def classify_powershell_stream(stream: TokenStream) -> "List[object]":
    # Local import: classifier imports this module, so a top-level import
    # would be a cycle.
    from .classifier import KIND_FS_DELETE, KIND_UNKNOWN, OpSpec

    assert KIND_FS_DELETE == "fs-delete" and KIND_UNKNOWN == "unknown"
    return classify_powershell(stream, KIND_FS_DELETE, OpSpec,
                               smell_re=NESTED_SMELL_RE)


# ------------------------------------------------------------------ registry


@dataclasses.dataclass(frozen=True)
class Dialect:
    name: str
    tokenizer: object
    classifier: object
    separators: Tuple[str, ...] = ()


def classify_stream(stream: TokenStream) -> List[object]:
    """Route a token stream to its dialect's structural classifier."""
    if stream.dialect == DIALECT_CMD:
        return classify_cmd_stream(stream)
    if stream.dialect == DIALECT_POWERSHELL:
        return classify_powershell_stream(stream)
    return []  # POSIX classification lives in classifier.py


def normalize_dialect(name: Optional[str]) -> str:
    """Map a user/harness supplied dialect name onto a known dialect.

    Unknown names raise ValueError: silently falling back to POSIX would
    classify a Windows command line with the wrong lexer, which is exactly
    the failure this layer exists to prevent.
    """
    if not name:
        return DEFAULT_DIALECT
    key = str(name).strip().lower()
    if key not in DIALECT_ALIASES:
        raise ValueError(f"unknown command dialect: {name!r}")
    return DIALECT_ALIASES[key]


def tokenize(cmd: str, dialect: str = DEFAULT_DIALECT) -> TokenStream:
    """Tokenize `cmd` for `dialect`, returning an error-bearing stream."""
    dialect = normalize_dialect(dialect)
    try:
        if dialect == DIALECT_CMD:
            return tokenize_cmd(cmd)
        if dialect == DIALECT_POWERSHELL:
            return tokenize_powershell(cmd)
        return tokenize_posix(cmd)
    except TokenizeError as exc:
        return TokenStream(dialect, [], error=str(exc))


def classify_dialect(cmd: str, dialect: str = DEFAULT_DIALECT) -> List[object]:
    """Full dialect pipeline: tokenize then classify (facts only)."""
    stream = tokenize(cmd, dialect)
    if not stream.ok:
        return []
    if stream.dialect == DIALECT_POSIX:
        from .classifier import classify_command
        specs, _ = classify_command(cmd)
        return specs
    return classify_stream(stream)


# ---------------------------------------------------------------- detection

_CMD_HINT_RE = re.compile(
    r"(?i)(^|[\s;&|(])(del|erase|rd|rmdir|copy|xcopy|robocopy|dir|attrib|"
    r"where|taskkill|sc|reg|netsh|powershell|pwsh)\b|%[A-Za-z_][A-Za-z0-9_]*%")
_PS_HINT_RE = re.compile(
    r"-\s?(Recurse|Force|WhatIf|LiteralPath|Filter|Include|Exclude|Confirm|"
    r"ErrorAction)\b|\bRemove-Item\b|\bGet-ChildItem\b|^[A-Z][a-z]+-[A-Z]",
    re.MULTILINE)


def detect_dialect(cmd: str) -> Optional[str]:
    """Best-effort *hint* for a command line's dialect; None when unsure.

    Deliberately conservative and never used to pick a lexer: guessing a
    lexer from surface syntax is precisely the kind of inference that loses
    repositories. Callers use this only to produce a better explanation,
    and unknown/ambiguous input stays None (treated as POSIX by default).
    """
    text = (cmd or "").strip()
    if not text:
        return None
    if _PS_HINT_RE.search(text):
        return DIALECT_POWERSHELL
    if _CMD_HINT_RE.search(text):
        return DIALECT_CMD
    return None
