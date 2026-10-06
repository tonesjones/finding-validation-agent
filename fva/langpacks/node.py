"""Node.js / npm language pack."""
from __future__ import annotations

import json
import re
from pathlib import Path

from fva.langpacks.base import DeclaredDependency, InstalledPackage
from fva.schemas import Surface as S


_IMPORT_RE = re.compile(
    r"""(?:\bimport\s+(?:[\w*{}\s,$]+?\s+from\s+)?|\bexport\s+[\w*{}\s,$]+?\s+from\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)(['"`])([^'"`\n]+)\1""")
_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json")
# namespace members that call other members by name or return a new namespace
_INDIRECT = frozenset({"chain", "mixin", "runInContext"})
_PAIRS = {"(": ")", "[": "]", "{": "}"}
_MAX_SCAN = 20000


def _split(text: str, start: int, close: str) -> tuple[list[str], int] | None:
    """(top-level comma-separated parts, index of the matching `close`) from text[start:]; None when unbalanced
    or opaque (template expressions, unterminated strings or comments)."""
    parts, stack, mark, i = [], [close], start, start
    end = min(len(text), start + _MAX_SCAN)
    while i < end:
        c = text[i]
        if c in "'\"`":
            j = i + 1
            while j < end and text[j] != c:
                if c == "`" and text.startswith("${", j):
                    return None
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if text.startswith(("//", "/*"), i):
            j = text.find("\n" if text[i + 1] == "/" else "*/", i + 2)
            if j < 0:
                return None
            i = j + (1 if text[i + 1] == "/" else 2)
            continue
        if c in _PAIRS:
            stack.append(_PAIRS[c])
        elif c in ")]}":
            if c != stack.pop():
                return None
            if not stack:
                parts = [p.strip() for p in parts + [text[mark:i]]]
                if parts[-1] == "":
                    parts.pop()  # trailing comma or no arguments
                return (parts, i) if "" not in parts else None
        elif c == "," and len(stack) == 1:
            parts.append(text[mark:i])
            mark = i + 1
        i += 1
    return None


def _call_args(text: str, pos: int) -> list[str] | None:
    """Argument sources when text[pos:] is a direct call `( ... )`; None for anything else."""
    m = re.match(r"\s*\(", text[pos:pos + 200])
    split = _split(text, pos + m.end(), ")") if m else None
    return split[0] if split else None


def _object_keys(src: str) -> dict[str, str] | None:
    """{key: value source} of a plain object literal; None for spreads, computed or accessor keys, or a non-literal."""
    split = _split(src, 1, "}") if src.startswith("{") else None
    if not split or split[1] != len(src) - 1:
        return None
    out = {}
    for part in split[0]:
        part = re.sub(r"^(?:\s*(?://[^\n]*|/\*.*?\*/))*\s*", "", part, flags=re.S)  # leading comments
        if not part:
            continue
        if m := re.match(r"""(?:([\w$]+)|(['"])([\w$-]+)\2)\s*:""", part):
            out[m.group(1) or m.group(3)] = part[m.end():].strip()
        elif re.fullmatch(r"[\w$]+", part):
            out[part] = part  # shorthand: the value is a variable of the same name
        elif m := re.match(r"([\w$]+)\s*\(", part):
            out[m.group(1)] = part  # method shorthand
        else:
            return None
    return out


class NodePack:
    name = "node"
    ecosystem = "npm"
    path_rules = (
        ("**/node_modules/*", S.dependency),
        ("test/*", S.test),
        ("tests/*", S.test),
        ("**/__tests__/*", S.test),
        ("**/cypress/*", S.test),
        ("**/e2e/*", S.test),
        ("**/*.spec.ts", S.test),
        ("**/*.spec.js", S.test),
        ("**/*.test.ts", S.test),
        ("**/*.test.js", S.test),
        ("**/*.spec.tsx", S.test),
        ("**/*.test.tsx", S.test),
    )
    source_suffixes = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
    manifest_files = ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")

    def parse_manifest(self, path: Path) -> list[DeclaredDependency]:
        if path.name != "package.json":
            raise NotImplementedError(f"{path.name} parsing not built yet")
        data = json.loads(path.read_text(encoding="utf-8"))
        out = []
        for key, scope in (("dependencies", "runtime"), ("devDependencies", "dev"),
                           ("optionalDependencies", "optional"), ("peerDependencies", "peer")):
            for name, spec in (data.get(key) or {}).items():
                out.append(DeclaredDependency(name, spec, "npm", scope))
        return out

    def read_inventory(self, path: Path) -> list[InstalledPackage]:
        """package-lock.json / npm-shrinkwrap.json (lockfileVersion 2/3), or a node_modules directory."""
        path = Path(path)
        if path.is_dir():
            return self._walk_node_modules(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        pkgs = data.get("packages")
        if pkgs is None:
            raise NotImplementedError("lockfileVersion 1 not supported; regenerate with npm >= 7")
        out = []
        for key, meta in pkgs.items():
            if not key or "node_modules/" not in key or "version" not in meta or meta.get("link"):
                continue
            out.append(InstalledPackage(meta.get("name") or key.rsplit("node_modules/", 1)[-1], meta["version"],
                                        "npm", key, bool(meta.get("dev"))))
        return out

    def _walk_node_modules(self, nm: Path) -> list[InstalledPackage]:
        out = []
        for pj in nm.rglob("package.json"):
            rel = pj.parent.relative_to(nm.parent).as_posix()
            if not rel.rsplit("node_modules/", 1)[-1] or rel.count("/") > rel.count("node_modules/") + rel.count("@"):
                continue  # skip nested non-package dirs (tests, fixtures inside packages)
            try:
                meta = json.loads(pj.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            if meta.get("name") and meta.get("version"):
                out.append(InstalledPackage(meta["name"], meta["version"], "npm", rel))
        return out

    # ---- import graph -------------------------------------------------------------------
    def imports(self, text: str) -> list[tuple[str, int]]:
        """(specifier, 1-based line) for static/dynamic imports, re-exports and require()."""
        out = []
        for m in _IMPORT_RE.finditer(text):
            out.append((m.group(2), text.count("\n", 0, m.start()) + 1))
        return out

    @staticmethod
    def package_of(spec: str) -> str | None:
        """Bare specifier -> package name ('@scope/pkg/sub' -> '@scope/pkg'); None for relative/builtin."""
        if spec.startswith((".", "/")) or spec.startswith("node:"):
            return None
        parts = spec.split("/")
        return "/".join(parts[:2]) if spec.startswith("@") else parts[0]

    # ---- call sites -----------------------------------------------------------------------
    def call_sites(self, text: str, package: str, functions: frozenset[str]) -> tuple[list[tuple[str, int]], list[int]]:
        """([(function, line)] uses of `package`'s named functions, [lines whose use can't be resolved]).

        Conservative: any use of the package this cannot name (computed access, the namespace passed as a value,
        wrapper/chain calls, dynamic import, re-export) is reported as unresolved, never as "not called".
        """
        sites, unresolved, spans = [], [], []
        line_of = lambda pos: text.count("\n", 0, pos) + 1  # noqa: E731
        pkg = re.escape(package)
        spec = rf"""(?P<q>['"`]){pkg}(?:/fp)?(?:\.js)?(?P=q)"""
        namespaces = set()

        def named(body: str, pos: int, sep: str):
            for part in body.split(","):
                part = part.strip()
                if not part:
                    continue
                if part.startswith("..."):
                    unresolved.append(line_of(pos))
                    continue
                imported, _, local = (p.strip() for p in part.partition(sep))
                if imported in functions:
                    sites.append((imported, line_of(pos)))
                elif imported == "default" and local:
                    namespaces.add(local)

        for m in re.finditer(rf"""\bimport\s+([\w$]+)?\s*,?\s*(?:\*\s*as\s+([\w$]+))?\s*(?:\{{([^}}]*)\}})?\s*from\s*{spec}""",
                             text):
            namespaces.update(n for n in m.group(1, 2) if n and n != "type")  # `import type {...}` binds nothing
            if m.group(3):
                named(m.group(3), m.start(), " as ")
            spans.append(m.span())
        for m in re.finditer(rf"""\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*{spec}\s*\)""", text):
            namespaces.add(m.group(1))
            spans.append(m.span())
        for m in re.finditer(rf"""\b(?:const|let|var)\s*\{{([^}}]*)\}}\s*=\s*require\s*\(\s*{spec}\s*\)""", text):
            named(m.group(1), m.start(), ":")
            spans.append(m.span())
        for m in re.finditer(rf"""\brequire\s*\(\s*{spec}\s*\)\s*\??\.\s*([\w$]+)""", text):
            if m.group(m.lastindex) in functions:
                sites.append((m.group(m.lastindex), line_of(m.start())))
            spans.append(m.span())
        for m in _IMPORT_RE.finditer(text):  # per-method modules; any other form not matched above is unresolved
            s = m.group(2).removesuffix(".js")
            fn = s.rsplit("/", 1)[-1]
            if s.startswith(package + "/") and fn in functions:
                sites.append((fn, line_of(m.start())))
            elif s.startswith(package + "/") and fn.startswith("_"):  # internal helper module
                unresolved.append(line_of(m.start()))
            elif s in (package, package + "/fp") and not any(a <= m.start(2) < b for a, b in spans):
                unresolved.append(line_of(m.start()))
        for name in sorted(namespaces):
            for m in re.finditer(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", text):
                if any(a <= m.start() < b for a, b in spans):
                    continue
                member = re.match(r"\s*\??\.\s*([\w$]+)", text[m.end():])
                if member and member.group(1) in functions:
                    sites.append((member.group(1), line_of(m.start())))
                elif not member or member.group(1) in _INDIRECT:
                    unresolved.append(line_of(m.start()))
        return sorted(set(sites)), sorted(set(unresolved))

    def option_calls(self, text: str, package: str) -> tuple[list[tuple[int, dict[str, str]]], list[int]]:
        """([(line, {option: value source})] direct `fn(input, {options})` or lodash.template calls,
        [lines whose use can't be resolved]).

        Conservative: options that are not an object literal of plain keys (a variable, spread, computed key), any
        other use of the binding (`fn.defaults`, passing `fn` as a value) and any other import form are unresolved.
        """
        calls, unresolved, spans, names = [], [], [], set()
        line_of = lambda pos: text.count("\n", 0, pos) + 1  # noqa: E731
        if package == "lodash":
            names.update({"_", "lodash"})  # browser globals, including files with no local import
            # Defaults can be assigned, mutated, aliased or passed to a mutator in another shipped file.
            # Any reference is conservatively opaque; do not attempt to prove it read-only.
            unresolved.extend(line_of(m.start()) for m in re.finditer(r"\btemplateSettings\b", text))
        spec = rf"""(?P<q>['"`]){re.escape(package)}(?P=q)"""
        for pattern in (rf"""\bimport\s+([\w$]+)\s*(?:,\s*\{{[^}}]*\}}\s*)?from\s*{spec}""",
                        rf"""\bimport\s+\*\s*as\s+([\w$]+)\s+from\s*{spec}""",
                        rf"""\bimport\s+([\w$]+)\s*=\s*require\s*\(\s*{spec}\s*\)""",
                        rf"""\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*{spec}\s*\)(?!\s*[(.?\[])"""):
            for m in re.finditer(pattern, text):
                if m.group(1) != "type":
                    names.add(m.group(1))
                    spans.append(m.span())
        for m in _IMPORT_RE.finditer(text):
            if package == "lodash" and m.group(2).startswith(package + "/"):
                unresolved.append(line_of(m.start()))  # per-method/fp imports cannot be followed here
            if m.group(2) == package and not any(a <= m.start(2) < b for a, b in spans):
                unresolved.append(line_of(m.start()))
            elif m.group(2) == package and re.search(r"\{[^}]*\}", text[m.start():m.start(2)]):
                unresolved.append(line_of(m.start()))  # named imports such as `{ defaults }`
        for name in sorted(names):
            for m in re.finditer(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", text):
                if any(a <= m.start() < b for a, b in spans):
                    continue
                pos = m.end()
                if package == "lodash":
                    member = re.match(r"\s*\??\.\s*([\w$]+)", text[pos:])
                    if member and member.group(1) == "template":
                        pos += member.end()
                    elif member and member.group(1) not in _INDIRECT:
                        continue
                    else:
                        unresolved.append(line_of(m.start()))
                        continue
                args = _call_args(text, pos)
                if package == "lodash" and args is not None and any(arg.startswith("...") for arg in args):
                    args = None  # spread arguments can change the options position
                options = None
                if args is not None and len(args) == 1:
                    options = {}
                elif args is not None and len(args) == 2:
                    options = _object_keys(args[1])
                if options is None:
                    unresolved.append(line_of(m.start()))
                else:
                    calls.append((line_of(m.start()), options))
        return calls, sorted(set(unresolved))

    @staticmethod
    def dependents(lockfile: Path, name: str) -> list[str] | None:
        """Installed packages (lockfile keys) that declare a dependency on `name`; None if the lockfile can't say."""
        try:
            pkgs = json.loads(Path(lockfile).read_text(encoding="utf-8")).get("packages")
        except (OSError, ValueError):
            return None
        if not isinstance(pkgs, dict):
            return None
        out = [key for key, meta in pkgs.items() if key and any(
            name in (meta.get(k) or {}) for k in ("dependencies", "optionalDependencies", "peerDependencies"))]
        return sorted(out)

    def resolve_local(self, spec: str, from_file: str, files: set[str]) -> str | None:
        if not spec.startswith("."):
            return None
        base = Path(from_file).parent.joinpath(spec).as_posix()
        norm = []
        for part in base.split("/"):
            if part == "..":
                if norm:
                    norm.pop()
            elif part not in ("", "."):
                norm.append(part)
        base = "/".join(norm)
        for cand in (base, *(base + e for e in _EXTS), *(f"{base}/index{e}" for e in _EXTS)):
            if cand in files:
                return cand
        if base.endswith(".js"):  # TS projects import './x.js' that resolves to ./x.ts
            return self.resolve_local(spec[:-3], from_file, files)
        return None
