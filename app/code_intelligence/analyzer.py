from __future__ import annotations

import ast
import sys
from collections import defaultdict
from pathlib import Path
from typing import Literal

from app.code_intelligence.contracts import (
    CodeArchitectureReport,
    CodeComponent,
    CodeRiskFinding,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
ROUTE_DECORATORS = {"delete", "get", "head", "options", "patch", "post", "put"}
EXECUTION_FUNCTIONS = {"startup", "shutdown", "correlation_worker"}
RISK_CALLS: dict[str, tuple[Literal["low", "medium", "high"], str]] = {
    "eval": ("high", "dynamic_execution"),
    "exec": ("high", "dynamic_execution"),
    "os.system": ("high", "shell_execution"),
    "subprocess.call": ("medium", "subprocess_execution"),
    "subprocess.Popen": ("medium", "subprocess_execution"),
    "subprocess.run": ("medium", "subprocess_execution"),
}


def _module_name(path: Path) -> str:
    return ".".join(path.relative_to(BACKEND_ROOT.parent).with_suffix("").parts)


def _domain(path: Path) -> str:
    relative = path.relative_to(BACKEND_ROOT)
    return relative.parts[0] if len(relative.parts) > 1 else "application"


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return _call_name(node)


def _route_path(node: ast.AST) -> str:
    if not isinstance(node, ast.Call) or not node.args:
        return ""
    first = node.args[0]
    return first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else ""


def _imports(tree: ast.AST) -> tuple[set[str], set[str]]:
    internal: set[str] = set()
    external: set[str] = set()
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        for name in names:
            if name == "app" or name.startswith("app."):
                internal.add(name)
            elif name.split(".", 1)[0] not in sys.stdlib_module_names:
                external.add(name.split(".", 1)[0])
    return internal, external


def _inspect_file(path: Path, *, include_private: bool) -> tuple[CodeComponent, list[CodeRiskFinding]]:
    source = path.read_text(encoding="utf-8-sig")
    module = _module_name(path)
    relative_path = path.relative_to(BACKEND_ROOT.parent).as_posix()
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        component = CodeComponent(
            module=module,
            path=relative_path,
            domain=_domain(path),
            lines=len(source.splitlines()),
            classes=[],
            functions=[],
            internal_imports=[],
            external_imports=[],
            routes=[],
            execution_points=[],
        )
        syntax_finding = CodeRiskFinding(
            severity="high",
            rule="syntax_error",
            module=module,
            path=relative_path,
            line=exc.lineno or 1,
            detail=exc.msg,
        )
        return component, [syntax_finding]
    classes: list[str] = []
    functions: list[str] = []
    routes: list[str] = []
    execution_points: list[str] = []
    risks: list[CodeRiskFinding] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and (include_private or not node.name.startswith("_")):
            classes.append(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if include_private or not node.name.startswith("_"):
                functions.append(node.name)
            for decorator in node.decorator_list:
                name = _decorator_name(decorator)
                method = name.rsplit(".", 1)[-1]
                if method in ROUTE_DECORATORS:
                    routes.append(f"{method.upper()} {_route_path(decorator) or '<dynamic>'}")
                if method == "on_event":
                    execution_points.append(f"event:{node.name}")
            if node.name in EXECUTION_FUNCTIONS:
                execution_points.append(f"function:{node.name}")
        if isinstance(node, ast.Call):
            call = _call_name(node.func)
            risk_definition = RISK_CALLS.get(call)
            if risk_definition:
                severity, rule = risk_definition
                risks.append(
                    CodeRiskFinding(
                        severity=severity,
                        rule=rule,
                        module=module,
                        path=relative_path,
                        line=node.lineno,
                        detail=f"Call to {call} requires execution-policy review.",
                    )
                )

    internal, external = _imports(tree)
    component = CodeComponent(
        module=module,
        path=relative_path,
        domain=_domain(path),
        lines=len(source.splitlines()),
        classes=sorted(set(classes)),
        functions=sorted(set(functions)),
        internal_imports=sorted(internal),
        external_imports=sorted(external),
        routes=sorted(set(routes)),
        execution_points=sorted(set(execution_points)),
    )
    return component, risks


def build_code_architecture_report(*, include_private: bool = False) -> CodeArchitectureReport:
    components: list[CodeComponent] = []
    risks: list[CodeRiskFinding] = []
    domains: dict[str, list[str]] = defaultdict(list)
    external_dependencies: set[str] = set()

    for path in sorted(BACKEND_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        component, file_risks = _inspect_file(path, include_private=include_private)
        components.append(component)
        risks.extend(file_risks)
        domains[component.domain].append(component.module)
        external_dependencies.update(component.external_imports)

    module_names = {component.module for component in components}
    dependency_graph: dict[str, list[str]] = {}
    for component in components:
        dependencies = {
            imported
            for imported in component.internal_imports
            if imported in module_names and imported != component.module
        }
        dependency_graph[component.module] = sorted(dependencies)

    return CodeArchitectureReport(
        scope="app",
        component_count=len(components),
        domain_count=len(domains),
        route_count=sum(len(component.routes) for component in components),
        execution_point_count=sum(len(component.execution_points) for component in components),
        internal_dependency_count=sum(len(items) for items in dependency_graph.values()),
        external_dependencies=sorted(external_dependencies),
        domains={domain: sorted(modules) for domain, modules in sorted(domains.items())},
        dependency_graph=dependency_graph,
        components=components,
        risks=sorted(risks, key=lambda item: (item.severity, item.module, item.line)),
        limitations=[
            "Static AST analysis does not resolve runtime dependency injection or dynamic imports.",
            "The analyzer never imports or executes target modules.",
            "The analysis scope is restricted to Python files under app/.",
        ],
    )
