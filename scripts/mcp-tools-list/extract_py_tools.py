#!/usr/bin/env python3
"""
extract_py_tools.py — read MCP tool definitions out of Python source, statically.

Nothing in the source repository is imported or run: files are parsed with `ast` and the
constant expressions a tool definition is built from are folded (string literals, f-strings,
`+` / implicit concatenation, module constants, `Enum` members and their `.value`, `textwrap.dedent`,
`'\\n'.join([...])`). Recognised definitions:

  - a function decorated with `@<x>.tool(...)` / `@<x>.tool` (FastMCP, MCPServer, `@app.tool()`):
    name = `name=` or the function name; description = `description=` or the docstring;
    input schema = the function's parameters, as the Python MCP SDK derives it from the signature
    (`Annotated[T, Field(...)]`, `x: T = Field(...)`, defaults, `Optional`, `Literal`, `list[...]`).
  - `<x>.tool(name=...)(<obj>.<method>)` registrations (handler classes): the method is found by name.

The schema is a reconstruction of what pydantic writes (`title` per property, `required`,
`default`, `anyOf` for Optional, `enum` for Literal / Enum). Parameters named `self` / `cls` or typed
`Context` are left out, as the SDK leaves them out. Nested pydantic models are inlined from their
class body (the SDK puts them under `$defs`); the descriptions are the same text either way.

Expressions the folder cannot evaluate are replaced by the source's `substitutions` entry for
that exact expression text (documented runtime defaults), or else recorded in
`_extraction.unresolved` and rendered as the empty string.

  python3 -I extract_py_tools.py --root <checkout> [--subst '<expr>=<value>' ...] <file>...
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path


class Unresolved(Exception):
    pass


def title_of(name: str) -> str:
    return name.replace("_", " ").title() if "_" in name else name[:1].upper() + name[1:]


_MODULES: dict[Path, "Folder"] = {}


def folder_for(path: Path, subst: dict[str, str]) -> "Folder":
    if path not in _MODULES:
        src = path.read_text(encoding="utf-8")
        _MODULES[path] = Folder(ast.parse(src), subst, src, path)
    return _MODULES[path]


class Folder:
    def __init__(self, module: ast.Module, subst: dict[str, str], src: str, path: Path | None = None):
        self.module = module
        self.subst = subst
        self.src = src
        self.path = path
        self.imports: dict[str, tuple[Path, str]] = {}
        self.consts: dict[str, ast.AST] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        self.functions: dict[str, ast.AST] = {}
        self.unresolved: list[str] = []
        if path is not None:
            for node in module.body:
                if not isinstance(node, ast.ImportFrom):
                    continue
                parts = node.module.split(".") if node.module else []
                if node.level:
                    base = path.parent
                    for _ in range(node.level - 1):
                        base = base.parent
                else:
                    # absolute import of the server's own package: find the ancestor holding parts[0]
                    base = next((a for a in path.parents if parts and (a / parts[0]).is_dir()), None)
                    if base is None:
                        continue
                target = base.joinpath(*parts)
                cand = target.with_suffix(".py")
                if not cand.exists():
                    cand = target / "__init__.py"
                if cand.exists():
                    for alias in node.names:
                        self.imports[alias.asname or alias.name] = (cand, alias.name)
        for node in ast.walk(module):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                self.consts.setdefault(node.targets[0].id, node.value)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                self.consts.setdefault(node.target.id, node.value)
            elif isinstance(node, ast.ClassDef):
                self.classes.setdefault(node.name, node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)

    def resolve_name(self, name: str):
        """(folder, assigned value node) for a module-level name, following relative/own-package imports."""
        if name in self.consts:
            return self, self.consts[name]
        if name in self.imports:
            tpath, tname = self.imports[name]
            return folder_for(tpath, self.subst).resolve_name(tname)
        return self, None

    def resolve_class(self, name: str):
        if name in self.classes:
            return self, self.classes[name]
        if name in self.imports:
            tpath, tname = self.imports[name]
            return folder_for(tpath, self.subst).resolve_class(tname)
        return self, None

    def text(self, node: ast.AST) -> str:
        if not hasattr(node, "lineno"):
            return ast.unparse(node)
        return ast.get_source_segment(self.src, node) or ast.unparse(node)

    def fold(self, node: ast.AST, depth: int = 0):
        if depth > 40:
            raise Unresolved(self.text(node))
        seg = self.text(node)
        if seg in self.subst:
            # a documented runtime default, written as a Python expression folded in this module
            expr = ast.parse(self.subst[seg], mode="eval").body
            for n in ast.walk(expr):  # no positions: they would index into this module's source
                for attr in ("lineno", "end_lineno", "col_offset", "end_col_offset"):
                    if hasattr(n, attr):
                        delattr(n, attr)
            return self.fold(expr, depth + 1)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.JoinedStr):
            out = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    out.append(str(v.value))
                elif isinstance(v, ast.FormattedValue):
                    out.append(str(self.fold_or_note(v.value, depth + 1)))
            return "".join(out)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.fold(node.left, depth + 1) + self.fold(node.right, depth + 1)
        if isinstance(node, ast.Name):
            if node.id in self.consts:
                return self.fold(self.consts[node.id], depth + 1)
            if node.id in ("True", "False", "None"):
                return {"True": True, "False": False, "None": None}[node.id]
            if node.id in self.imports:
                tpath, tname = self.imports[node.id]
                other = folder_for(tpath, self.subst)
                if tname in other.consts:
                    return other.fold(other.consts[tname], depth + 1)
                if tname in other.imports:
                    return other.fold(ast.Name(id=tname, ctx=ast.Load()), depth + 1)
            raise Unresolved(seg)
        if isinstance(node, ast.Attribute):
            # Enum member: Cls.MEMBER.value / Cls.MEMBER
            if node.attr == "value" and isinstance(node.value, ast.Attribute):
                return self.enum_member(node.value, depth)
            if isinstance(node.value, ast.Name) and self.resolve_class(node.value.id)[1] is not None:
                return self.enum_member(node, depth)
            raise Unresolved(seg)
        if isinstance(node, (ast.List, ast.Tuple)):
            return [self.fold(e, depth + 1) for e in node.elts]
        if isinstance(node, ast.Dict):
            return {self.fold(k, depth + 1): self.fold(v, depth + 1) for k, v in zip(node.keys, node.values) if k is not None}
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "join" and len(node.args) == 1:
                sep = self.fold(f.value, depth + 1)
                items = self.fold(node.args[0], depth + 1)
                return sep.join(str(i) for i in items)
            if (isinstance(f, ast.Attribute) and f.attr in ("dedent", "cleandoc")) or (isinstance(f, ast.Name) and f.id in ("dedent", "cleandoc")):
                import inspect
                import textwrap
                s = self.fold(node.args[0], depth + 1)
                return textwrap.dedent(s) if (getattr(f, "attr", None) or getattr(f, "id", None)) == "dedent" else inspect.cleandoc(s)
            if isinstance(f, ast.Attribute) and f.attr in ("strip", "lstrip", "rstrip") and not node.args:
                return getattr(self.fold(f.value, depth + 1), f.attr)()
            if isinstance(f, ast.Attribute) and f.attr == "format":
                raise Unresolved(seg)
        if isinstance(node, ast.Subscript):
            target = self.fold(node.value, depth + 1)
            key = self.fold(node.slice, depth + 1)
            return target[key]
        raise Unresolved(seg)

    def fold_or_note(self, node: ast.AST, depth: int = 0):
        try:
            return self.fold(node, depth)
        except (Unresolved, KeyError, TypeError, IndexError) as e:
            self.unresolved.append(str(e) if isinstance(e, Unresolved) else self.text(node))
            return ""

    def enum_member(self, node: ast.Attribute, depth: int):
        if isinstance(node.value, ast.Name):
            owner, cls = self.resolve_class(node.value.id)
            for stmt in (cls.body if cls is not None else []):
                if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == node.attr for t in stmt.targets):
                    return owner.fold(stmt.value, depth + 1)
        raise Unresolved(self.text(node))

    # ------------------------------------------------------------- types -> JSON Schema

    def enum_values(self, cls: ast.ClassDef):
        vals = []
        for stmt in cls.body:
            if isinstance(stmt, ast.Assign):
                try:
                    vals.append(self.fold(stmt.value))
                except Unresolved:
                    pass
        return vals

    def is_enum(self, cls: ast.ClassDef) -> bool:
        return any(self.text(b).split(".")[-1] in ("Enum", "StrEnum", "IntEnum") for b in cls.bases)

    def is_model(self, cls: ast.ClassDef) -> bool:
        return any(self.text(b).split(".")[-1] in ("BaseModel",) or self.text(b) in self.classes for b in cls.bases) and not self.is_enum(cls)

    def type_schema(self, ann: ast.AST, depth: int = 0) -> dict:
        if depth > 12:
            return {}
        if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
            try:
                ann = ast.parse(ann.value, mode="eval").body
            except SyntaxError:
                return {}
        if isinstance(ann, ast.Constant) and ann.value is None:
            return {"type": "null"}
        if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
            parts = self.flatten_union(ann)
            return self.union_schema(parts, depth)
        name = self.text(ann.value if isinstance(ann, ast.Subscript) else ann).split(".")[-1]
        if isinstance(ann, ast.Subscript):
            args = ann.slice.elts if isinstance(ann.slice, ast.Tuple) else [ann.slice]
            if name == "Annotated":
                return self.type_schema(args[0], depth + 1)
            if name == "Optional":
                return self.union_schema([args[0], ast.Constant(None)], depth)
            if name == "Union":
                return self.union_schema(args, depth)
            if name in ("list", "List", "Sequence", "set", "Set", "tuple", "Tuple"):
                return {"items": self.type_schema(args[0], depth + 1), "type": "array"}
            if name in ("dict", "Dict", "Mapping"):
                return {"additionalProperties": self.type_schema(args[-1], depth + 1), "type": "object"}
            if name == "Literal":
                vals = [self.fold_or_note(a) for a in args]
                t = "string" if all(isinstance(v, str) for v in vals) else None
                return {"enum": vals, **({"type": t} if t else {})}
        simple = {"str": {"type": "string"}, "int": {"type": "integer"}, "float": {"type": "number"},
                  "bool": {"type": "boolean"}, "dict": {"type": "object", "additionalProperties": True},
                  "Dict": {"type": "object", "additionalProperties": True}, "list": {"items": {}, "type": "array"},
                  "List": {"items": {}, "type": "array"}, "Any": {}, "AnyUrl": {"format": "uri", "minLength": 1, "type": "string"},
                  "HttpUrl": {"format": "uri", "maxLength": 2083, "minLength": 1, "type": "string"},
                  "Path": {"format": "path", "type": "string"}, "datetime": {"format": "date-time", "type": "string"},
                  "date": {"format": "date", "type": "string"}}
        if name in simple:
            return dict(simple[name])
        if name in self.classes:
            cls = self.classes[name]
            if self.is_enum(cls):
                vals = self.enum_values(cls)
                return {"enum": vals, "title": name, "type": "string" if all(isinstance(v, str) for v in vals) else "integer"}
            if self.is_model(cls) and depth < 6:
                return self.model_schema(cls, depth + 1)
        return {}

    def flatten_union(self, node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self.flatten_union(node.left) + self.flatten_union(node.right)
        return [node]

    def union_schema(self, parts, depth):
        schemas = [self.type_schema(p, depth + 1) for p in parts]
        return {"anyOf": schemas}

    def field_kwargs(self, call: ast.Call) -> tuple[dict, bool, object]:
        """(schema extras, has_default, default) from Field(...)."""
        extras: dict = {}
        has_default = False
        default = None
        if call.args:
            a0 = call.args[0]
            if not (isinstance(a0, ast.Constant) and a0.value is Ellipsis):
                has_default, default = True, self.fold_or_note(a0)
        for kw in call.keywords:
            if kw.arg == "description":
                extras["description"] = self.fold_or_note(kw.value)
            elif kw.arg == "default":
                if not (isinstance(kw.value, ast.Constant) and kw.value.value is Ellipsis):
                    has_default, default = True, self.fold_or_note(kw.value)
            elif kw.arg == "default_factory":
                has_default, default = True, None
            elif kw.arg in ("ge", "le", "gt", "lt", "min_length", "max_length", "title", "examples", "pattern"):
                key = {"ge": "minimum", "le": "maximum", "gt": "exclusiveMinimum", "lt": "exclusiveMaximum",
                       "min_length": "minLength", "max_length": "maxLength"}.get(kw.arg, kw.arg)
                extras[key] = self.fold_or_note(kw.value)
        return extras, has_default, default

    def param_schema(self, name: str, ann: ast.AST | None, default_node: ast.AST | None) -> tuple[dict, bool]:
        schema = self.type_schema(ann) if ann is not None else {}
        extras: dict = {}
        has_default = default_node is not None
        default = None
        if isinstance(ann, ast.Subscript) and self.text(ann.value).split(".")[-1] == "Annotated":
            for meta in (ann.slice.elts[1:] if isinstance(ann.slice, ast.Tuple) else []):
                if isinstance(meta, ast.Call) and self.text(meta.func).split(".")[-1] == "Field":
                    e, hd, d = self.field_kwargs(meta)
                    extras.update(e)
                    if hd:
                        has_default, default = True, d
                elif isinstance(meta, ast.Constant) and isinstance(meta.value, str):
                    extras.setdefault("description", meta.value)
        owner = self
        if isinstance(default_node, ast.Name):
            # PARAM = Field(...) declared once (in this module or one it imports), used as a default
            owner, const = self.resolve_name(default_node.id)
            if isinstance(const, ast.Call):
                default_node = const
            else:
                owner = self
        if default_node is not None:
            if isinstance(default_node, ast.Call) and owner.text(default_node.func).split(".")[-1] == "Field":
                e, hd, d = owner.field_kwargs(default_node)
                extras.update(e)
                has_default, default = hd, d
            else:
                default = self.fold_or_note(default_node)
        out = {**schema, **extras}
        if has_default:
            out["default"] = default
        out["title"] = extras.get("title", title_of(name))
        return dict(sorted(out.items())), not has_default

    def model_schema(self, cls: ast.ClassDef, depth: int = 0) -> dict:
        props, required = {}, []
        for stmt in cls.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                s, req = self.param_schema(stmt.target.id, stmt.annotation, stmt.value)
                props[stmt.target.id] = s
                if req:
                    required.append(stmt.target.id)
        doc = ast.get_docstring(cls)
        return {"properties": props, **({"required": required} if required else {}), "title": cls.name,
                "type": "object", **({"description": doc} if doc else {})}

    def function_schema(self, fn) -> dict:
        args = fn.args
        positional = args.posonlyargs + args.args
        defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
        pairs = list(zip(positional, defaults)) + list(zip(args.kwonlyargs, args.kw_defaults))
        props, required = {}, []
        for arg, default in pairs:
            if arg.arg in ("self", "cls"):
                continue
            if arg.annotation is not None and re.search(r"\bContext\b", self.text(arg.annotation)):
                continue
            if arg.arg in ("ctx", "context") and arg.annotation is None:
                continue
            s, req = self.param_schema(arg.arg, arg.annotation, default)
            props[arg.arg] = s
            if req:
                required.append(arg.arg)
        return {"properties": props, **({"required": required} if required else {}),
                "title": f"{fn.name}Arguments", "type": "object"}


def tool_kwargs(call: ast.Call) -> dict[str, ast.AST]:
    return {kw.arg: kw.value for kw in call.keywords if kw.arg}


def annotations_of(folder: Folder, node: ast.AST | None):
    if node is None:
        return None
    if isinstance(node, ast.Name) and node.id in folder.consts:
        node = folder.consts[node.id]
    if isinstance(node, ast.Call) and folder.text(node.func).split(".")[-1] == "ToolAnnotations":
        out = {}
        for kw in node.keywords:
            key = re.sub(r"_([a-z])", lambda m: m.group(1).upper(), kw.arg or "")
            try:
                out[key] = folder.fold(kw.value)
            except Unresolved:
                pass
        return out or None
    return None


def emit(folder: Folder, fn, call: ast.Call | None, rel: str, shape: str) -> dict:
    folder.unresolved = []
    kw = tool_kwargs(call) if call is not None else {}
    name = folder.fold_or_note(kw["name"]) if "name" in kw else fn.name
    if "description" in kw:
        description = folder.fold_or_note(kw["description"])
    else:
        description = ast.get_docstring(fn, clean=False) or ""
    tool = {"name": name}
    title = None
    if "title" in kw:
        title = folder.fold_or_note(kw["title"])
    if title:
        tool["title"] = title
    tool["description"] = description
    tool["inputSchema"] = folder.function_schema(fn)
    ann = annotations_of(folder, kw.get("annotations"))
    if ann:
        tool["annotations"] = ann
    tool["_extraction"] = {"path": rel, "line": (call or fn).lineno, "shape": shape, "unresolved": list(folder.unresolved)}
    return tool


def discover(path: Path, root: Path, subst: dict[str, str]) -> list[dict]:
    folder = folder_for(path, subst)
    module = folder.module
    rel = str(path.relative_to(root))
    out = []
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                call = dec if isinstance(dec, ast.Call) else None
                target = dec.func if call is not None else dec
                if isinstance(target, ast.Attribute) and target.attr == "tool":
                    out.append(emit(folder, node, call, rel, "decorator"))
                    break
        # types.Tool(name=..., description=..., inputSchema={...}) — low-level Server list_tools handlers
        if isinstance(node, ast.Call) and folder.text(node.func).split(".")[-1] == "Tool":
            kw = tool_kwargs(node)
            if "name" in kw and "inputSchema" in kw:
                folder.unresolved = []
                tool = {"name": folder.fold_or_note(kw["name"])}
                if "description" in kw:
                    tool["description"] = folder.fold_or_note(kw["description"])
                schema_node = kw["inputSchema"]
                if (isinstance(schema_node, ast.Call) and isinstance(schema_node.func, ast.Attribute)
                        and schema_node.func.attr in ("model_json_schema", "schema") and isinstance(schema_node.func.value, ast.Name)
                        and schema_node.func.value.id in folder.classes):
                    tool["inputSchema"] = folder.model_schema(folder.classes[schema_node.func.value.id])
                else:
                    tool["inputSchema"] = folder.fold_or_note(schema_node)
                tool["_extraction"] = {"path": rel, "line": node.lineno, "shape": "Tool-call", "unresolved": list(folder.unresolved)}
                out.append(tool)
        # x.tool(name=...)(self.method)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Call):
            inner = node.func
            if isinstance(inner.func, ast.Attribute) and inner.func.attr == "tool" and node.args:
                ref = node.args[0]
                mname = ref.attr if isinstance(ref, ast.Attribute) else ref.id if isinstance(ref, ast.Name) else None
                fn = folder.functions.get(mname) if mname else None
                if fn is not None:
                    out.append(emit(folder, fn, inner, rel, "registration-call"))
    return out


def main(argv: list[str]) -> int:
    root = Path(argv[argv.index("--root") + 1]).resolve()
    subst = {}
    files = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--root":
            i += 2
            continue
        if a == "--subst":
            k, _, v = argv[i + 1].partition("=")
            subst[k] = v
            i += 2
            continue
        files.append(a)
        i += 1
    tools = []
    for f in files:
        tools.extend(discover((root / f).resolve(), root, subst))
    sys.stdout.write(json.dumps(tools, indent=2, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
