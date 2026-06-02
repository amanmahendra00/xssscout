from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import esprima

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Source / sink pattern sets
# ---------------------------------------------------------------------------

SOURCE_PATTERNS: set[str] = {
    "location",
    "location.hash",
    "location.search",
    "location.href",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.name",
    "localStorage",
    "sessionStorage",
    "URLSearchParams",
    "postMessage",
    # FIX: added additional DOM sources missing from original
    "document.cookie",
    "history.state",
    "opener",
    "top.location",
}

SINK_PATTERNS: set[str] = {
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",        # FIX: was missing
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "insertAdjacentHTML",
    "dangerouslySetInnerHTML",
    "$.html",                  # FIX: original had "$ .html" with a space (never matches)
    "jQuery.html",
    "srcdoc",                  # FIX: iframe srcdoc is a sink
    "location.href",           # FIX: javascript: URL assignment
}


@dataclass(slots=True)
class DomSignal:
    sink: str
    source: str
    confidence: str
    taint_path: str
    notes: str = ""


@dataclass(slots=True)
class BasicBlock:
    id: int
    label: str
    succ: set[int] = field(default_factory=set)


class JsTaintAnalyzer:
    """
    Lightweight static taint analyser built on esprima AST traversal.

    Changes vs original:
    FIX 1: `_extract_scripts` — Vue/Angular template extraction was producing
           fragments that esprima couldn't parse, causing silent failures.
           Now wraps template expressions in an IIFE before parsing.
    FIX 2: `_is_sink_call` — "$ .html" (with space) never matched anything.
           Fixed to "$.html".
    FIX 3: `_record_sink` — was called even when taint was empty *or* when the
           source was a constant literal.  Now filters out literal/empty taint.
    FIX 4: `analyze` — esprima import error was silently swallowed.  Added
           explicit error logging when parsing completely fails.
    FIX 5: Added `__slots__`-compatible reset that clears all mutable state.
    FIX 6: `_walk` SequenceExpression and SpreadElement were not handled,
           causing missed taint propagation through comma-expressions.
    """

    def __init__(self) -> None:
        self.taint: dict[str, set[str]] = {}
        self.flows: list[DomSignal] = []
        self.fn_returns: dict[str, set[str]] = {}
        self.cfg_blocks: list[BasicBlock] = []
        self.sink_graph: dict[str, set[str]] = {}

    def analyze(self, js_text: str) -> list[dict[str, str]]:
        self._reset()
        for script, flavor in self._extract_scripts(js_text):
            ast = self._parse_with_fallbacks(script, flavor)
            if ast is None:
                continue
            try:
                self._walk(ast, scope="global")
            except Exception as exc:
                logger.debug("taint walk error: %s", exc)
        return [f.__dict__ for f in self.flows]

    def _reset(self) -> None:
        self.taint.clear()
        self.flows.clear()
        self.fn_returns.clear()
        self.cfg_blocks.clear()
        self.sink_graph.clear()

    def _extract_scripts(self, text: str) -> list[tuple[str, str]]:
        parts: list[tuple[str, str]] = []

        # Standard <script> blocks
        for s in re.findall(r"<script[^>]*>([\s\S]*?)</script>", text, flags=re.IGNORECASE):
            stripped = s.strip()
            if stripped:
                parts.append((stripped, "module"))

        # FIX 1: wrap Angular/Vue expressions in IIFE so esprima can parse them
        for tpl in re.findall(r"\{\{([^}]+)\}\}", text):
            wrapped = f"(function(){{ return {tpl.strip()}; }})()"
            parts.append((wrapped, "script"))

        # Angular event bindings: (click)="doSomething($event)"
        for ev in re.findall(r'\([^)]+\)\s*=\s*"([^"]+)"', text):
            wrapped = f"(function(){{ {ev.strip()} }})()"
            parts.append((wrapped, "script"))

        if not parts:
            # treat the whole text as a JS module (e.g. a .js response)
            parts.append((text, "module"))

        return parts

    def _strip_typescript(self, text: str) -> str:
        text = re.sub(r"\binterface\s+\w+\s*\{[\s\S]*?\}", "", text)
        text = re.sub(r"\btype\s+\w+\s*=\s*[^;]+;", "", text)
        text = re.sub(r"(:\s*[A-Za-z_][\w<>,\[\]\s|&?.:]*)", "", text)
        text = re.sub(r"\s+as\s+[A-Za-z_][\w<>,\[\]\s|&?.:]*", "", text)
        return text

    def _parse_with_fallbacks(self, script: str, flavor: str) -> Any | None:
        candidates = [script, self._strip_typescript(script)]
        for candidate in candidates:
            for mode in ("module", "script"):
                try:
                    fn = esprima.parseModule if mode == "module" else esprima.parseScript
                    return fn(candidate, tolerant=True, jsx=True)
                except Exception:
                    continue
        # FIX 4: log when ALL parse attempts fail
        logger.debug("esprima: all parse fallbacks failed for script fragment (len=%d)", len(script))
        return None

    def _new_block(self, label: str) -> int:
        bid = len(self.cfg_blocks)
        self.cfg_blocks.append(BasicBlock(id=bid, label=label))
        return bid

    def _walk(  # noqa: C901
        self,
        node: Any,
        scope: str,
        fn_params: dict[str, set[str]] | None = None,
        block_id: int | None = None,
    ) -> set[str]:
        if node is None:
            return set()
        if isinstance(node, list):
            res: set[str] = set()
            for item in node:
                res |= self._walk(item, scope, fn_params, block_id)
            return res

        ntype = getattr(node, "type", None)
        if not ntype:
            return set()

        if block_id is None:
            block_id = self._new_block(f"{scope}:{ntype}")

        if ntype == "Program":
            return self._walk(node.body, scope, fn_params, block_id)

        if ntype == "VariableDeclaration":
            for decl in node.declarations:
                name = getattr(getattr(decl, "id", None), "name", None)
                if name:
                    init_taint = self._walk(getattr(decl, "init", None), scope, fn_params, block_id)
                    self.taint[name] = init_taint
            return set()

        if ntype == "AssignmentExpression":
            ta = self._walk(node.right, scope, fn_params, block_id)
            target = self._member_name(node.left)
            if target:
                self.taint[target] = ta
            if self._is_sink_target(node.left):
                self._record_sink(self._member_name(node.left) or "assignment_sink", ta)
            return ta

        if ntype == "ExpressionStatement":
            return self._walk(node.expression, scope, fn_params, block_id)

        if ntype == "Identifier":
            if fn_params and node.name in fn_params:
                return fn_params[node.name]
            return self.taint.get(node.name, set())

        if ntype == "Literal":
            return set()     # constants are never tainted

        if ntype == "MemberExpression":
            name = self._member_name(node)
            if name in SOURCE_PATTERNS:
                return {name}
            return self.taint.get(name or "", set())

        if ntype == "CallExpression":
            callee    = self._member_name(node.callee)
            arg_taint = self._walk(node.arguments, scope, fn_params, block_id)

            if (callee == "addEventListener"
                    and len(node.arguments) >= 1
                    and getattr(node.arguments[0], "value", None) == "message"):
                self.taint["message-event"] = {"postMessage"}

            if callee == "URLSearchParams":
                return arg_taint or {"URLSearchParams"}

            if callee in self.fn_returns:
                return self.fn_returns[callee] | arg_taint

            if self._is_sink_call(callee):
                self._record_sink(callee or "unknown-call-sink", arg_taint)

            if callee and callee.endswith(".getItem"):
                ns = callee.split(".")[0]
                return {ns}

            return arg_taint

        if ntype in {"ArrowFunctionExpression", "FunctionExpression", "FunctionDeclaration"}:
            name = getattr(getattr(node, "id", None), "name", None) or scope
            params = {
                p.name: {f"arg:{name}:{p.name}"}
                for p in getattr(node, "params", [])
                if getattr(p, "type", "") == "Identifier"
            }
            returns = self._walk(getattr(node, "body", None), scope=name, fn_params=params, block_id=block_id)
            if name and returns:
                self.fn_returns[name] = returns
            return set()

        if ntype in {"IfStatement", "ConditionalExpression"}:
            cond = self._new_block(f"{scope}:cond")
            self.cfg_blocks[block_id].succ.add(cond)
            cons = self._new_block(f"{scope}:true")
            alt  = self._new_block(f"{scope}:false")
            self.cfg_blocks[cond].succ.update({cons, alt})
            left  = self._walk(getattr(node, "consequent", None), scope, fn_params, cons)
            right = self._walk(getattr(node, "alternate",  None), scope, fn_params, alt)
            return left | right

        if ntype in {"ReturnStatement", "AwaitExpression", "UnaryExpression", "UpdateExpression"}:
            return self._walk(getattr(node, "argument", None), scope, fn_params, block_id)

        if ntype in {"BinaryExpression", "LogicalExpression"}:
            return (
                self._walk(node.left,  scope, fn_params, block_id)
                | self._walk(node.right, scope, fn_params, block_id)
            )

        if ntype == "TemplateLiteral":
            return self._walk(node.expressions, scope, fn_params, block_id)

        # FIX 6: SequenceExpression (comma operator)
        if ntype == "SequenceExpression":
            return self._walk(node.expressions, scope, fn_params, block_id)

        # FIX 6: SpreadElement
        if ntype == "SpreadElement":
            return self._walk(getattr(node, "argument", None), scope, fn_params, block_id)

        if ntype == "JSXExpressionContainer":
            return self._walk(getattr(node, "expression", None), scope, fn_params, block_id)

        if ntype == "JSXAttribute":
            attr_name = getattr(getattr(node, "name", None), "name", "")
            if attr_name == "dangerouslySetInnerHTML":
                ta = self._walk(getattr(node, "value", None), scope, fn_params, block_id)
                self._record_sink("dangerouslySetInnerHTML", ta)
                return ta

        if ntype == "ObjectExpression":
            ta2: set[str] = set()
            for p in node.properties:
                ta2 |= self._walk(getattr(p, "value", None), scope, fn_params, block_id)
            return ta2

        if ntype in {"ArrayExpression", "BlockStatement"}:
            return self._walk(
                getattr(node, "elements", None) or getattr(node, "body", None),
                scope, fn_params, block_id,
            )

        if ntype == "SwitchStatement":
            ta3: set[str] = set()
            for case in getattr(node, "cases", []):
                ta3 |= self._walk(getattr(case, "consequent", None), scope, fn_params, block_id)
            return ta3

        if ntype in {"TryStatement", "CatchClause"}:
            ta4: set[str] = set()
            for attr in ("block", "handler", "finalizer", "body"):
                ta4 |= self._walk(getattr(node, attr, None), scope, fn_params, block_id)
            return ta4

        # Generic fallthrough — visit all known child attributes
        ta5: set[str] = set()
        for attr in (
            "body", "expression", "argument", "left", "right",
            "test", "consequent", "alternate", "declarations",
            "init", "arguments", "callee",
        ):
            if hasattr(node, attr):
                ta5 |= self._walk(getattr(node, attr), scope, fn_params, block_id)
        return ta5

    def _member_name(self, node: Any) -> str | None:
        if node is None:
            return None
        t = getattr(node, "type", None)
        if t == "Identifier":
            return node.name
        if t == "ThisExpression":
            return "this"
        if t == "MemberExpression":
            obj  = self._member_name(node.object)
            prop = (
                self._member_name(node.property)
                if not getattr(node, "computed", False)
                else getattr(getattr(node, "property", None), "value", None)
            )
            if obj and prop:
                return f"{obj}.{prop}"
        if t == "Literal":
            return str(node.value)
        return None

    def _is_sink_call(self, callee: str | None) -> bool:
        if not callee:
            return False
        # FIX 2: "$ .html" → "$.html"
        return callee in SINK_PATTERNS or callee.endswith(".html") or callee.endswith(".html()")

    def _is_sink_target(self, node: Any) -> bool:
        name = self._member_name(node) or ""
        return any(
            name.endswith(sfx)
            for sfx in (".innerHTML", ".outerHTML", ".insertAdjacentHTML",
                        ".dangerouslySetInnerHTML", ".srcdoc", ".href")
        )

    def _record_sink(self, sink: str, taint: set[str]) -> None:
        # FIX 3: filter out empty taint and pure constants
        real_taint = {s for s in taint if s and not s.startswith("arg:")}
        if not real_taint:
            return
        for src in real_taint:
            self.sink_graph.setdefault(sink, set()).add(src)
        source = sorted(real_taint)[0]
        self.flows.append(DomSignal(
            sink=sink,
            source=source,
            confidence="high-static",
            taint_path=f"{source} -> dataflow -> {sink}",
            notes=f"cfg_blocks={len(self.cfg_blocks)}",
        ))


def quick_dom_pattern_scan(js_text: str) -> list[dict[str, str]]:
    """
    Entry point for scanning HTML/JS text for taint flows.
    Returns a list of serialisable DomSignal dicts.
    """
    try:
        return JsTaintAnalyzer().analyze(js_text)
    except Exception as exc:
        logger.warning("quick_dom_pattern_scan failed: %s", exc)
        return []
