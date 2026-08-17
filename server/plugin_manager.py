"""
Plugin Manager for GIAM-SAT v2.0.0
Allows third-party extensions via plugin architecture:
  - Custom collectors
  - Dashboard widgets
  - Alert integrations
  - Response actions

Plugins are Python files in server/plugins/ directory.
Each plugin defines a standard interface class.
"""

import os, sys, json, importlib, inspect
from abc import ABC, abstractmethod

PLUGIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
os.makedirs(PLUGIN_DIR, exist_ok=True)


class GiamSatPlugin(ABC):
    """Base class for GIAM-SAT plugins."""
    @abstractmethod
    def name(self) -> str: pass
    @abstractmethod
    def version(self) -> str: pass
    @abstractmethod
    def description(self) -> str: pass
    
    # Plugin types
    def get_web_routes(self) -> list: return []
    def get_dashboard_widgets(self) -> list: return []
    def get_response_actions(self) -> dict: return {}
    def on_startup(self): pass
    def on_shutdown(self): pass
    def on_alert(self, alert: dict): pass


class PluginManager:
    def __init__(self):
        self.plugins = {}
        self.routes = []
        self.widgets = []
        self.actions = {}
        self._discover()

    def _discover(self):
        for item in os.listdir(PLUGIN_DIR):
            if item.startswith("_") or not item.endswith(".py"):
                continue
            name = item[:-3]
            try:
                spec = importlib.util.spec_from_file_location(name, os.path.join(PLUGIN_DIR, item))
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for _, cls in inspect.getmembers(mod, inspect.isclass):
                    if issubclass(cls, GiamSatPlugin) and cls != GiamSatPlugin:
                        plugin = cls()
                        self.plugins[name] = plugin
                        self.routes.extend(plugin.get_web_routes())
                        self.widgets.extend(plugin.get_dashboard_widgets())
                        self.actions.update(plugin.get_response_actions())
                        print(f"[*] Plugin loaded: {plugin.name()} v{plugin.version()}")
            except Exception as e:
                print(f"[-] Failed to load plugin {name}: {e}")

    def get_all_plugins(self) -> list:
        return [{"id": k, "name": p.name(), "version": p.version(), "desc": p.description()} for k, p in self.plugins.items()]

    def on_startup_all(self):
        for p in self.plugins.values(): p.on_startup()
    def on_shutdown_all(self):
        for p in self.plugins.values(): p.on_shutdown()
    def on_alert_all(self, alert: dict):
        for p in self.plugins.values(): p.on_alert(alert)