import importlib
import pkgutil
from types import ModuleType
from typing import Iterable

from fastapi import FastAPI


def _iter_plugin_names() -> Iterable[str]:
    import app.plugins

    for module_info in pkgutil.iter_modules(app.plugins.__path__):
        if module_info.ispkg:
            yield module_info.name


def _import_plugin(name: str) -> ModuleType:
    return importlib.import_module(f"app.plugins.{name}.plugin")


def load_plugins(app: FastAPI, enabled: list[str] | None = None) -> list[str]:
    enabled_set = set(p.strip() for p in (enabled or []) if p.strip())
    discovered = list(_iter_plugin_names())
    to_load = discovered if not enabled_set else [p for p in discovered if p in enabled_set]

    loaded: list[str] = []
    for name in to_load:
        module = _import_plugin(name)
        router = getattr(module, "router", None)
        if router is not None:
            app.include_router(router)
        init = getattr(module, "init", None)
        if callable(init):
            init(app)
        loaded.append(name)

    return loaded

