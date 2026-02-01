#!/usr/bin/env python3
"""injectguard - Offline Prompt Injection Scanner.

Detect prompt injection patterns in text, files, and stdin without
API keys or ML models. Pure pattern-based detection. Zero dependencies.

Usage:
    injectguard "text to scan"
    injectguard --file input.txt
    echo "ignore previous instructions" | injectguard --stdin
    injectguard --scan-dir ./prompts/
    injectguard --list-rules
"""

from __future__ import annotations

__version__ = "1.0.0"

import argparse
import base64
import json
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Severity & scoring
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 2,
}

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    matched_text: str = ""
    offset: int = -1  # character offset in input
    line: int = -1

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
        }
        if self.matched_text:
            d["matched_text"] = self.matched_text[:200]
        if self.offset >= 0:
            d["offset"] = self.offset
        if self.line >= 0:
            d["line"] = self.line
        return d


@dataclass
class ScanResult:
    text_length: int
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "safe"

    def to_dict(self) -> dict:
        return {
            "version": __version__,
            "text_length": self.text_length,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            },
        }


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES: dict[str, dict] = {}


def rule(rule_id: str, severity: Severity, title: str, description: str = ""):
    """Decorator to register a scan rule."""
    def decorator(fn):
        RULES[rule_id] = {
            "id": rule_id,
            "severity": severity,
            "title": title,
            "description": description,
            "fn": fn,
        }
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Helper: line number from offset
# ---------------------------------------------------------------------------

def offset_to_line(text: str, offset: int) -> int:
    """Convert character offset to 1-based line number."""
    return text[:offset].count("\n") + 1


def add_finding(findings: list[Finding], text: str, rule_id: str,
                severity: Severity, title: str, message: str,
                match_obj=None, matched_text: str = "", offset: int = -1):
    """Create a Finding with line number from match or offset."""
    if match_obj:
        offset = match_obj.start()
        if not matched_text:
            matched_text = match_obj.group(0)
    line = offset_to_line(text, offset) if offset >= 0 else -1
    findings.append(Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        matched_text=matched_text[:200] if matched_text else "",
        offset=offset,
        line=line,
    ))


# ---------------------------------------------------------------------------
# Rules: Instruction Override
# ---------------------------------------------------------------------------

@rule("PI001", Severity.CRITICAL, "Instruction override",
      "Attempts to override or ignore existing instructions")
def check_instruction_override(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)\bignore\s+(all\s+)?(previous|prior|above|earlier|preceding|original|old)\s+(instructions?|prompts?|rules?|guidelines?|directions?|context)",
         "Instruction override: ignore previous instructions"),
        (r"(?i)\b(disregard|forget|skip|bypass|override|overwrite|replace)\s+(all\s+)?(previous|prior|above|your|the|any|earlier)\s+(instructions?|prompts?|rules?|guidelines?|directions?|context|constraints?|limitations?)",
         "Instruction override: disregard/forget instructions"),
        (r"(?i)\bdo\s+not\s+(follow|obey|listen\s+to|adhere\s+to|comply\s+with)\s+(the\s+)?(previous|prior|above|original|earlier|given)\s+(instructions?|prompts?|rules?|guidelines?)",
         "Instruction override: do not follow instructions"),
        (r"(?i)\bstop\s+(being|acting\s+as|following|obeying)",
         "Instruction override: stop being/acting/following"),
        (r"(?i)\b(new|updated|revised|corrected|real|actual|true)\s+(instructions?|prompt|rules?|guidelines?|directions?)\s*:",
         "Instruction override: new instructions declaration"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI001", Severity.CRITICAL,
                       "Instruction override attempt", msg, match_obj=m)


@rule("PI002", Severity.CRITICAL, "Role hijacking",
      "Attempts to redefine the AI's role or identity")
def check_role_hijack(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)\byou\s+are\s+now\s+(?:a\s+)?(?!going|about|ready|able|free|welcome)",
         "Role hijacking: 'you are now'"),
        (r"(?i)\b(pretend|imagine|act|behave|respond|function)\s+(like\s+)?you\s*(are|'re|were)\s+(?:a\s+)?",
         "Role hijacking: pretend you are"),
        (r"(?i)\byour\s+new\s+(role|identity|persona|character|name|purpose|mission|objective)\s+(is|will\s+be|:)",
         "Role hijacking: your new role is"),
        (r"(?i)\b(switch|change|transition|morph|transform)\s+(to|into)\s+(a\s+)?(new\s+)?(role|mode|persona|character|identity)",
         "Role hijacking: switch to new role"),
        (r"(?i)\bfrom\s+now\s+on\s*,?\s*you\s+(are|will|should|must|shall)\b",
         "Role hijacking: from now on you"),
        (r"(?i)\bfor\s+the\s+rest\s+of\s+(this|the)\s+(conversation|chat|session|interaction)\s*,?\s*you\s+(are|will|should)",
         "Role hijacking: for the rest of this conversation"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI002", Severity.CRITICAL,
                       "Role hijacking attempt", msg, match_obj=m)


@rule("PI003", Severity.HIGH, "System prompt markers",
      "Fake system prompt or instruction delimiters")
def check_system_markers(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)^system\s*(?:prompt|message|instruction)\s*:", "System prompt marker"),
        (r"(?i)\[SYSTEM\]", "System prompt tag"),
        (r"(?i)\[INST\]", "Instruction tag (Llama format)"),
        (r"(?i)\[/INST\]", "End instruction tag (Llama format)"),
        (r"(?i)<\|system\|>", "System token marker"),
        (r"(?i)<\|user\|>", "User token marker"),
        (r"(?i)<\|assistant\|>", "Assistant token marker"),
        (r"(?i)<<SYS>>", "Llama system delimiter"),
        (r"(?i)<</SYS>>", "Llama end system delimiter"),
        (r"(?i)###\s*(System|Human|Assistant|User)\s*:", "Chat role delimiter"),
        (r"(?i)\bBEGIN\s+(SYSTEM\s+)?(PROMPT|INSTRUCTIONS?|CONTEXT)\b", "Begin instruction marker"),
        (r"(?i)\bEND\s+(SYSTEM\s+)?(PROMPT|INSTRUCTIONS?|CONTEXT)\b", "End instruction marker"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI003", Severity.HIGH,
                       "System/instruction delimiter detected", msg, match_obj=m)


@rule("PI004", Severity.HIGH, "Delimiter injection",
      "Attempts to break out of user input boundaries")
def check_delimiter_injection(text: str, findings: list[Finding]):
    patterns = [
        (r"---+\s*(?:END|STOP|BEGIN|START)\s*(?:OF\s+)?(?:USER|SYSTEM|PROMPT|INPUT|CONTEXT)", "Delimiter break attempt"),
        (r"={3,}\s*(?:END|STOP|BEGIN|START)\s*(?:OF\s+)?(?:USER|SYSTEM|PROMPT|INPUT|CONTEXT)", "Delimiter break attempt"),
        (r"\"{3,}\s*\n", "Triple-quote delimiter injection"),
        (r"```\s*(?:system|instruction|prompt|context)", "Code fence as delimiter"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            add_finding(findings, text, "PI004", Severity.HIGH,
                       "Delimiter injection attempt", msg, match_obj=m)


# ---------------------------------------------------------------------------
# Rules: Data Exfiltration
# ---------------------------------------------------------------------------

@rule("PI005", Severity.CRITICAL, "System prompt extraction",
      "Attempts to extract the system prompt or instructions")
def check_prompt_extraction(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)\b(show|reveal|display|print|output|tell|give|share|expose|leak|dump|repeat|recite|echo)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|rules?|guidelines?|configuration|config|context|directive|preamble|initial\s+prompt)",
         "System prompt extraction attempt"),
        (r"(?i)\bwhat\s+(are|is|were)\s+your\s+(system\s+)?(instructions?|prompt|rules?|guidelines?|directives?|initial\s+(?:prompt|instructions?))",
         "System prompt query"),
        (r"(?i)\brepeat\s+(everything|all|the\s+text)\s+(above|before|from\s+the\s+(?:start|beginning))",
         "Repeat-above extraction"),
        (r"(?i)\b(copy|paste|reproduce|transcribe)\s+(your|the)\s+(entire\s+)?(system\s+)?(prompt|instructions?|context)",
         "Copy prompt extraction"),
        (r"(?i)\bverbatim\b.*\b(instructions?|prompt|rules?|system)",
         "Verbatim extraction attempt"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI005", Severity.CRITICAL,
                       "System prompt extraction attempt", msg, match_obj=m)


@rule("PI006", Severity.HIGH, "Data exfiltration via URL",
      "Attempts to make the AI send data to external URLs")
def check_url_exfiltration(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)\b(fetch|get|visit|access|navigate|go\s+to|open|load|request|call|curl|wget)\s+(the\s+)?(url|link|endpoint|page|site|website)\s*:?\s*https?://",
         "URL fetch instruction"),
        (r"(?i)\b(send|post|submit|transmit|forward|exfiltrate|upload)\s+.{0,60}(to|at|via)\s+https?://",
         "Data send to URL"),
        (r"(?i)\binclude\s+.{0,40}\bin\s+(a|an|the)\s+(image|img|markdown|link)\s*(url|src|tag)\s*:?\s*https?://",
         "Data encoding in URL"),
        (r"(?i)!\[.*?\]\(https?://[^)]*\$\{", "Markdown image exfiltration with variable"),
        (r"https?://[^\s]*\{\{.*?\}\}", "URL with template variable injection"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI006", Severity.HIGH,
                       "Potential data exfiltration via URL", msg, match_obj=m)


# ---------------------------------------------------------------------------
# Rules: Jailbreaking
# ---------------------------------------------------------------------------

@rule("PI007", Severity.HIGH, "Jailbreak pattern (DAN-style)",
      "Do Anything Now and similar jailbreak frameworks")
def check_jailbreak_dan(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)\bDAN\s*(mode|prompt|jailbreak|\d)", "DAN jailbreak reference"),
        (r"(?i)\bDo\s+Anything\s+Now\b", "DAN — Do Anything Now"),
        (r"(?i)\b(developer|debug|god|sudo|admin|root|master)\s+mode\s*(enabled|activated|on|:)", "Privilege escalation mode"),
        (r"(?i)\b(unlock|enable|activate|enter)\s+(unrestricted|uncensored|unfiltered|unlimited|full)\s+mode", "Unrestricted mode activation"),
        (r"(?i)\b(jailbreak|jailbroken|unchained|unshackled|liberated)\s+(mode|prompt|version)", "Explicit jailbreak reference"),
        (r"(?i)\bno\s+(restrictions?|limitations?|filters?|censorship|guardrails?|safety)\s+(mode|enabled|activated|allowed|apply|anymore)", "No restrictions declaration"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI007", Severity.HIGH,
                       "Jailbreak pattern detected", msg, match_obj=m)


@rule("PI008", Severity.MEDIUM, "Ethical bypass",
      "Attempts to bypass safety/ethical guidelines")
def check_ethical_bypass(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)\b(this\s+is\s+)?(just\s+)?(hypothetical|fictional|theoretical|academic|educational|for\s+research|in\s+a\s+novel|for\s+a\s+story)\b.*\b(how\s+(to|would|could|do)|tell\s+me|explain|describe|write)\b",
         "Hypothetical framing to bypass filters"),
        (r"(?i)\bfor\s+(educational|research|academic|security|testing|study|learning)\s+purposes?\s+(only)?",
         "Purpose framing to bypass filters"),
        (r"(?i)\b(it'?s?\s+)?(okay|fine|safe|acceptable|legal|allowed|permitted|ethical)\s+(to|for\s+you\s+to)\s+(tell|show|explain|describe|write|generate|help)",
         "Permission granting bypass"),
        (r"(?i)\byou\s+(can|may|should|are\s+allowed\s+to|have\s+permission\s+to)\s+(ignore|bypass|skip|disable)\s+(safety|content|ethical|output)\s+(filters?|restrictions?|guidelines?|guardrails?|policies|rules?)",
         "Explicit filter bypass instruction"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI008", Severity.MEDIUM,
                       "Ethical/safety bypass attempt", msg, match_obj=m)


# ---------------------------------------------------------------------------
# Rules: Encoding & Obfuscation
# ---------------------------------------------------------------------------

@rule("PI009", Severity.HIGH, "Base64-encoded instructions",
      "Hidden instructions encoded in base64")
def check_base64_injection(text: str, findings: list[Finding]):
    # Find base64-looking strings (at least 20 chars, proper base64 charset)
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    for m in b64_pattern.finditer(text):
        candidate = m.group(0)
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="strict")
            # Check if decoded text contains injection patterns
            injection_keywords = [
                "ignore", "instruction", "system", "prompt", "override",
                "you are", "pretend", "role", "forget", "disregard",
                "bypass", "jailbreak", "admin", "sudo", "password",
            ]
            decoded_lower = decoded.lower()
            if any(kw in decoded_lower for kw in injection_keywords):
                add_finding(findings, text, "PI009", Severity.HIGH,
                           "Base64-encoded injection",
                           f"Decoded base64 contains suspicious content: '{decoded[:100]}'",
                           match_obj=m,
                           matched_text=candidate[:80])
        except (ValueError, UnicodeDecodeError):
            pass


@rule("PI010", Severity.MEDIUM, "Unicode/invisible character smuggling",
      "Zero-width or invisible characters that may hide instructions")
def check_unicode_smuggling(text: str, findings: list[Finding]):
    # Zero-width and invisible characters
    invisible_chars = {
        "\u200b": "Zero Width Space",
        "\u200c": "Zero Width Non-Joiner",
        "\u200d": "Zero Width Joiner",
        "\u200e": "Left-to-Right Mark",
        "\u200f": "Right-to-Left Mark",
        "\u2060": "Word Joiner",
        "\u2061": "Function Application",
        "\u2062": "Invisible Times",
        "\u2063": "Invisible Separator",
        "\u2064": "Invisible Plus",
        "\ufeff": "Byte Order Mark (BOM)",
        "\u00ad": "Soft Hyphen",
        "\u034f": "Combining Grapheme Joiner",
        "\u061c": "Arabic Letter Mark",
        "\u180e": "Mongolian Vowel Separator",
    }

    found_types = set()
    count = 0
    first_offset = -1

    for i, ch in enumerate(text):
        if ch in invisible_chars:
            count += 1
            found_types.add(invisible_chars[ch])
            if first_offset < 0:
                first_offset = i

    if count > 0:
        severity = Severity.HIGH if count >= 5 else Severity.MEDIUM
        add_finding(findings, text, "PI010", severity,
                   "Invisible characters detected",
                   f"{count} invisible character(s) found: {', '.join(sorted(found_types))}",
                   offset=first_offset,
                   matched_text=f"[{count} invisible chars]")


@rule("PI011", Severity.MEDIUM, "Homoglyph/lookalike characters",
      "Characters from different scripts that look like Latin letters")
def check_homoglyphs(text: str, findings: list[Finding]):
    # Check for Cyrillic characters that look like Latin
    cyrillic_lookalikes = set("АВСЕНІКМОРТХаеорсухі")
    # Check for mixed scripts in the same word
    suspicious_chars = []
    for i, ch in enumerate(text):
        if ch in cyrillic_lookalikes:
            # Check if surrounded by Latin chars
            before = text[i-1] if i > 0 else ""
            after = text[i+1] if i < len(text) - 1 else ""
            if (before.isascii() and before.isalpha()) or (after.isascii() and after.isalpha()):
                suspicious_chars.append((i, ch))

    if suspicious_chars:
        add_finding(findings, text, "PI011", Severity.MEDIUM,
                   "Homoglyph characters detected",
                   f"{len(suspicious_chars)} lookalike character(s) mixed with Latin text "
                   f"(Trojan Source / visual spoofing technique)",
                   offset=suspicious_chars[0][0],
                   matched_text=f"[{len(suspicious_chars)} homoglyphs]")


@rule("PI012", Severity.MEDIUM, "BiDi override characters",
      "Right-to-left override characters that can reorder visible text")
def check_bidi(text: str, findings: list[Finding]):
    bidi_chars = {
        "\u202a": "LRE",
        "\u202b": "RLE",
        "\u202c": "PDF",
        "\u202d": "LRO",
        "\u202e": "RLO",
        "\u2066": "LRI",
        "\u2067": "RLI",
        "\u2068": "FSI",
        "\u2069": "PDI",
    }
    found = []
    for i, ch in enumerate(text):
        if ch in bidi_chars:
            found.append((i, bidi_chars[ch]))

    if found:
        add_finding(findings, text, "PI012", Severity.MEDIUM,
                   "BiDi override characters detected",
                   f"{len(found)} bidirectional override character(s) found: "
                   f"{', '.join(name for _, name in found[:5])}. "
                   f"Text may appear different from actual content.",
                   offset=found[0][0],
                   matched_text=f"[{len(found)} BiDi overrides]")


# ---------------------------------------------------------------------------
# Rules: Context Manipulation
# ---------------------------------------------------------------------------

@rule("PI013", Severity.MEDIUM, "Conversation history injection",
      "Fake conversation history to manipulate context")
def check_conversation_injection(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)(user|human|customer|person)\s*:\s*.{5,}\n(assistant|ai|bot|chatbot|model|system|claude|gpt|gemini)\s*:\s*",
         "Fake conversation history"),
        (r"(?i)<(user|human)>.{5,}</(user|human)>\s*<(assistant|ai|model)>",
         "XML-style fake conversation"),
        (r'(?i)"role"\s*:\s*"(system|assistant)".*"content"\s*:',
         "JSON-style role injection"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text, re.DOTALL):
            add_finding(findings, text, "PI013", Severity.MEDIUM,
                       "Fake conversation history", msg, match_obj=m)


@rule("PI014", Severity.MEDIUM, "Context window manipulation",
      "Padding or filler to push important context out of window")
def check_context_stuffing(text: str, findings: list[Finding]):
    # Check for extremely repetitive content (context stuffing)
    words = text.split()
    if len(words) > 100:
        # Check if any single word/phrase is repeated excessively
        from collections import Counter
        word_counts = Counter(words)
        most_common = word_counts.most_common(1)
        if most_common:
            word, count = most_common[0]
            ratio = count / len(words)
            if ratio > 0.3 and count > 50:
                add_finding(findings, text, "PI014", Severity.MEDIUM,
                           "Repetitive content (context stuffing)",
                           f"Word '{word}' repeated {count} times ({ratio:.0%} of text). "
                           f"May be attempting to dilute or push out context.",
                           offset=0,
                           matched_text=f"'{word}' × {count}")

    # Check for large blocks of whitespace or newlines
    whitespace_blocks = re.findall(r"\n{10,}", text)
    if whitespace_blocks:
        add_finding(findings, text, "PI014", Severity.MEDIUM,
                   "Large whitespace block",
                   f"Found {len(whitespace_blocks)} block(s) of 10+ consecutive newlines. "
                   f"May be hiding instructions after visual boundary.",
                   offset=text.find("\n" * 10),
                   matched_text=f"[{len(whitespace_blocks)} whitespace blocks]")


@rule("PI015", Severity.LOW, "Markdown/HTML injection",
      "Embedded markdown or HTML that may manipulate output rendering")
def check_markdown_injection(text: str, findings: list[Finding]):
    patterns = [
        (r"<script\b[^>]*>", "HTML script tag injection"),
        (r"<iframe\b[^>]*>", "HTML iframe injection"),
        (r"<img\b[^>]*\bonerror\s*=", "HTML img onerror injection"),
        (r"<svg\b[^>]*\bonload\s*=", "HTML svg onload injection"),
        (r"javascript\s*:", "JavaScript URI scheme"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            add_finding(findings, text, "PI015", Severity.LOW,
                       "HTML/script injection", msg, match_obj=m)


# ---------------------------------------------------------------------------
# Rules: Tool/Function Manipulation
# ---------------------------------------------------------------------------

@rule("PI016", Severity.HIGH, "Tool/function call injection",
      "Attempts to invoke tools or functions through prompt content")
def check_tool_injection(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)\b(call|invoke|execute|run|trigger|use)\s+(the\s+)?(function|tool|plugin|api|command|action)\s+",
         "Tool invocation instruction"),
        (r"(?i)\b(execute|run)\s+(this\s+)?(code|command|script|query|sql)\s*:",
         "Code execution instruction"),
        (r'(?i)"function_call"\s*:\s*\{', "Function call JSON injection"),
        (r'(?i)"tool_calls"\s*:\s*\[', "Tool calls JSON injection"),
        (r"(?i)<function_call>", "XML function call injection"),
        (r"(?i)<tool_use>", "XML tool use injection"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI016", Severity.HIGH,
                       "Tool/function injection attempt", msg, match_obj=m)


# ---------------------------------------------------------------------------
# Rules: Multi-turn & Indirect
# ---------------------------------------------------------------------------

@rule("PI017", Severity.MEDIUM, "Indirect injection markers",
      "Text that looks like it was designed to be processed by an AI reading external content")
def check_indirect_injection(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)\bif\s+you\s+(are|'re)\s+(an?\s+)?(ai|llm|language\s+model|chatbot|assistant|gpt|claude|gemini)",
         "AI-targeting conditional"),
        (r"(?i)\b(attention|important|note|warning)\s*:?\s*(ai|llm|assistant|model|chatbot)\b",
         "AI-directed attention marker"),
        (r"(?i)\bwhen\s+(this|an?)\s+(ai|llm|language\s+model|assistant)\s+(reads?|processes?|sees?|encounters?)\s+this",
         "AI-trigger instruction"),
        (r"(?i)\bhidden\s+instruction\s*:", "Explicit hidden instruction marker"),
        (r"(?i)\b(do\s+not\s+show|don'?t\s+display|hide)\s+this\s+(from|to)\s+the\s+user",
         "Hide-from-user instruction"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI017", Severity.MEDIUM,
                       "Indirect prompt injection marker", msg, match_obj=m)


@rule("PI018", Severity.LOW, "Output manipulation",
      "Attempts to control or format the AI's response")
def check_output_manipulation(text: str, findings: list[Finding]):
    patterns = [
        (r"(?i)\b(always|only|must|never)\s+(respond|reply|answer|output|say|write)\s+with\s*:",
         "Forced output format"),
        (r"(?i)\byour\s+(only|sole)\s+(response|reply|output|answer)\s+(should|must|will)\s+be\s*:",
         "Forced single response"),
        (r"(?i)\b(respond|reply|answer)\s+to\s+(every|all|any)\s+(message|question|query|prompt|input)\s+with\s*:",
         "Universal response override"),
        (r"(?i)\bappend\s+(the\s+following|this)\s+to\s+(every|all|each)\s+(response|reply|output|answer)\s*:",
         "Response append instruction"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI018", Severity.LOW,
                       "Output manipulation attempt", msg, match_obj=m)


@rule("PI019", Severity.INFO, "Suspicious payload structure",
      "Text structure that looks like a multi-part injection payload")
def check_payload_structure(text: str, findings: list[Finding]):
    # Count how many different injection techniques appear
    technique_patterns = [
        r"(?i)ignore.*instructions?",
        r"(?i)you\s+are\s+now",
        r"(?i)system\s*:",
        r"(?i)\[INST\]",
        r"(?i)jailbreak|DAN",
        r"(?i)bypass.*filter",
        r"(?i)repeat.*above",
        r"(?i)base64|decode",
    ]
    technique_count = sum(1 for p in technique_patterns if re.search(p, text))
    if technique_count >= 3:
        add_finding(findings, text, "PI019", Severity.INFO,
                   "Multi-technique injection payload",
                   f"Text contains {technique_count} different injection techniques, "
                   f"suggesting a deliberate injection payload",
                   offset=0,
                   matched_text=f"[{technique_count} techniques]")


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def calculate_risk(findings: list[Finding]) -> tuple[int, str]:
    """Calculate risk score (0-100) and level."""
    score = 0
    for f in findings:
        score += SEVERITY_WEIGHT.get(f.severity, 0)
    score = min(100, score)

    if score == 0:
        level = "safe"
    elif score <= 10:
        level = "low"
    elif score <= 30:
        level = "medium"
    elif score <= 60:
        level = "high"
    else:
        level = "critical"

    return score, level


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan(text: str, ignore_rules: set[str] | None = None,
         min_severity: Severity = Severity.INFO) -> ScanResult:
    """Scan text for prompt injection patterns."""
    ignore_rules = ignore_rules or set()
    all_findings: list[Finding] = []

    for rule_id, rule_info in RULES.items():
        if rule_id in ignore_rules:
            continue
        rule_info["fn"](text, all_findings)

    # Filter by severity
    findings = [f for f in all_findings
                if SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[min_severity]]

    # Sort by severity then offset
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.offset))

    # Deduplicate findings at same location with same rule
    seen = set()
    deduped = []
    for f in findings:
        key = (f.rule_id, f.offset)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    risk_score, risk_level = calculate_risk(all_findings)

    return ScanResult(
        text_length=len(text),
        findings=deduped,
        risk_score=risk_score,
        risk_level=risk_level,
    )


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

SEVERITY_SYMBOLS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "ℹ️ ",
}

RISK_SYMBOLS = {
    "safe": "✅",
    "low": "🟢",
    "medium": "🟡",
    "high": "🟠",
    "critical": "🔴",
}

COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[93m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[2m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def format_text(result: ScanResult, source: str = "<input>", verbose: bool = False) -> str:
    color = supports_color()
    lines = []

    header = f"injectguard v{__version__}"
    if color:
        lines.append(f"{BOLD}{header}{RESET}")
    else:
        lines.append(header)
    lines.append("=" * 60)
    lines.append(f"Source: {source}")
    lines.append(f"Length: {result.text_length} chars")

    if not result.findings:
        risk_sym = RISK_SYMBOLS[result.risk_level]
        if color:
            lines.append(f"\n{BOLD}{risk_sym} No injection patterns detected.{RESET}")
            lines.append(f"Risk: {result.risk_level.upper()} ({result.risk_score}/100)")
        else:
            lines.append(f"\n{risk_sym} No injection patterns detected.")
            lines.append(f"Risk: {result.risk_level.upper()} ({result.risk_score}/100)")
        lines.append("")
        return "\n".join(lines)

    lines.append("")

    for f in result.findings:
        sym = SEVERITY_SYMBOLS[f.severity]
        loc = f"Line {f.line}" if f.line >= 0 else ""
        if color:
            c = COLORS[f.severity]
            lines.append(f"  {sym} {c}[{f.rule_id}]{RESET} {f.title}")
            if loc:
                lines.append(f"     {DIM}{loc}: {f.message}{RESET}")
            else:
                lines.append(f"     {DIM}{f.message}{RESET}")
            if verbose and f.matched_text:
                display = f.matched_text[:120].replace("\n", "↵")
                lines.append(f"     {DIM}Matched: \"{display}\"{RESET}")
        else:
            lines.append(f"  {sym} [{f.rule_id}] {f.title}")
            if loc:
                lines.append(f"     {loc}: {f.message}")
            else:
                lines.append(f"     {f.message}")
            if verbose and f.matched_text:
                display = f.matched_text[:120].replace("\n", "↵")
                lines.append(f"     Matched: \"{display}\"")
        lines.append("")

    # Summary
    risk_sym = RISK_SYMBOLS[result.risk_level]
    lines.append("=" * 60)
    risk_line = f"Risk: {risk_sym} {result.risk_level.upper()} ({result.risk_score}/100)"
    s = result.to_dict()["summary"]
    summary = (f"Findings: {s['total']} total — "
               f"{s['critical']} critical, {s['high']} high, "
               f"{s['medium']} medium, {s['low']} low, {s['info']} info")
    if color:
        lines.append(f"{BOLD}{risk_line}{RESET}")
    else:
        lines.append(risk_line)
    lines.append(summary)
    lines.append("")
    return "\n".join(lines)


def format_json(result: ScanResult, source: str = "<input>") -> str:
    data = result.to_dict()
    data["source"] = source
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------

def scan_file(filepath: str, ignore_rules: set[str], min_severity: Severity) -> tuple[ScanResult, str]:
    """Scan a file and return (result, content_or_error)."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return scan(content, ignore_rules, min_severity), ""
    except (OSError, IOError) as e:
        return ScanResult(text_length=0), str(e)


def scan_directory(dirpath: str, extensions: set[str],
                   ignore_rules: set[str], min_severity: Severity) -> list[tuple[str, ScanResult]]:
    """Recursively scan files in a directory."""
    results = []
    for root, dirs, files in os.walk(dirpath):
        # Skip hidden dirs
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for fname in sorted(files):
            if extensions:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in extensions:
                    continue
            fpath = os.path.join(root, fname)
            result, error = scan_file(fpath, ignore_rules, min_severity)
            if not error and result.findings:
                results.append((fpath, result))
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def list_rules() -> str:
    lines = ["injectguard rules:", ""]
    for rule_id in sorted(RULES):
        info = RULES[rule_id]
        sev = info["severity"].value.upper()
        lines.append(f"  {rule_id} [{sev:8s}] {info['title']}")
        if info.get("description"):
            lines.append(f"             {info['description']}")
    lines.append(f"\nTotal: {len(RULES)} rules")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="injectguard",
        description="Offline prompt injection scanner. Zero dependencies.",
    )
    parser.add_argument(
        "text", nargs="*", default=[],
        help="Text to scan (inline)",
    )
    parser.add_argument(
        "--file", "-f", action="append", default=[],
        help="File(s) to scan",
    )
    parser.add_argument(
        "--stdin", action="store_true",
        help="Read from stdin",
    )
    parser.add_argument(
        "--scan-dir", "-d", default=None,
        help="Recursively scan a directory",
    )
    parser.add_argument(
        "--ext", default=".txt,.md,.py,.json,.yaml,.yml,.toml,.xml,.html,.csv,.prompt",
        help="File extensions to scan in directory mode (default: common text formats)",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--check", nargs="?", const="medium", default=None,
        metavar="LEVEL",
        help="CI mode: exit 1 if risk level >= LEVEL (default: medium)",
    )
    parser.add_argument(
        "--severity", choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity to show (default: info)",
    )
    parser.add_argument(
        "--ignore", default="",
        help="Comma-separated rule IDs to ignore",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show matched text for each finding",
    )
    parser.add_argument(
        "--list-rules", action="store_true",
        help="List all rules and exit",
    )
    parser.add_argument(
        "--version", action="version", version=f"injectguard {__version__}",
    )

    args = parser.parse_args(argv)

    if args.list_rules:
        print(list_rules())
        return 0

    ignore_rules = set(r.strip().upper() for r in args.ignore.split(",") if r.strip())
    min_severity = Severity(args.severity)
    extensions = set(e.strip() for e in args.ext.split(",") if e.strip())

    # Collect inputs
    inputs: list[tuple[str, str]] = []  # (source_name, content)

    if args.text:
        inputs.append(("<inline>", " ".join(args.text)))

    if args.stdin:
        inputs.append(("<stdin>", sys.stdin.read()))

    for filepath in args.file:
        if not os.path.isfile(filepath):
            print(f"Error: {filepath} not found", file=sys.stderr)
            return 1
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            inputs.append((filepath, f.read()))

    if args.scan_dir:
        if not os.path.isdir(args.scan_dir):
            print(f"Error: {args.scan_dir} is not a directory", file=sys.stderr)
            return 1
        dir_results = scan_directory(args.scan_dir, extensions, ignore_rules, min_severity)
        if args.format == "json":
            all_data = []
            for fpath, result in dir_results:
                data = result.to_dict()
                data["source"] = fpath
                all_data.append(data)
            print(json.dumps(all_data, indent=2))
        else:
            if not dir_results:
                print(f"No injection patterns found in {args.scan_dir}")
            for fpath, result in dir_results:
                print(format_text(result, fpath, args.verbose))
        # Check mode for directory
        if args.check and dir_results:
            risk_levels = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            threshold = risk_levels.get(args.check, 2)
            for _, result in dir_results:
                if risk_levels.get(result.risk_level, 0) >= threshold:
                    return 1
        return 0

    if not inputs:
        parser.print_help()
        return 0

    # Process inputs
    exit_code = 0
    outputs = []

    for source, content in inputs:
        result = scan(content, ignore_rules, min_severity)
        if args.format == "json":
            outputs.append(format_json(result, source))
        else:
            outputs.append(format_text(result, source, args.verbose))

        if args.check:
            risk_levels = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            threshold = risk_levels.get(args.check, 2)
            if risk_levels.get(result.risk_level, 0) >= threshold:
                exit_code = 1

    if args.format == "json" and len(outputs) > 1:
        merged = [json.loads(o) for o in outputs]
        print(json.dumps(merged, indent=2))
    else:
        print("\n".join(outputs))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
