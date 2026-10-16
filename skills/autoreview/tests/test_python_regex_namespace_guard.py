"""Public synthetic grammar keeps metadata only under the stdlib namespace."""
import ast
import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/autoreview_source_guard.py"
SPEC = importlib.util.spec_from_file_location("regex_namespace_guard", SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class PythonRegexNamespaceGuardTests(unittest.TestCase):
    def source(self, mutation=""):
        # These are public language tokens, never live credential inputs.
        source = ("import re\n" + mutation
                + "def read(source):\n"
                + "    token = re.match(r\"[A-Z]+\", source)\n"
                + "    return token\n")
        ast.parse(source)
        return source

    def refuse(self, mutation):
        with self.assertRaises(SystemExit):
            GUARD.require_safe_source("public synthetic source", "grammar.py", self.source(mutation))

    def test_ordinary_stdlib_grammar_is_metadata(self):
        GUARD.require_safe_source("public synthetic source", "grammar.py", self.source())

    def test_importlib_alias_replacement_is_not_metadata(self):
        self.refuse("import importlib\n"
                    "other = importlib.import_module(\"re\")\n"
                    "other.match = lambda pattern, value: pattern\n")

    def test_renamed_sys_cache_replacement_is_not_metadata(self):
        self.refuse("import sys as state\n"
                    "state.modules[\"re\"].match = lambda pattern, value: pattern\n")


    def test_renamed_loader_and_from_imports_are_not_metadata(self):
        routes = {
            "renamed-module": "import importlib as loader\nother = loader.import_module(\"re\")\n",
            "renamed-from-import": "from importlib import import_module as acquire\nother = acquire(\"re\")\n",
            "direct-from-import": "from importlib import import_module\nother = import_module(\"re\")\n",
            "module-alias": "import importlib as loader\ncopy = loader\nother = copy.import_module(\"re\")\n",
            "function-alias": "import importlib as loader\nacquire = loader.import_module\nother = acquire(\"re\")\n",
            "from-function-alias": "from importlib import import_module as acquire\ncopy = acquire\nother = copy(\"re\")\n",
            "attribute-loader": "import importlib as loader\nother = getattr(loader, \"import_module\")(\"re\")\n",
            "bootstrap-module": "import importlib._bootstrap as loader\nother = loader._gcd_import(\"re\")\n",
            "bootstrap-from-import": "from importlib._bootstrap import _gcd_import as acquire\nother = acquire(\"re\")\n",
        }
        for name, route in routes.items():
            with self.subTest(route=name):
                self.refuse(route + "other.match = lambda pattern, value: pattern\n")

    def test_module_cache_aliases_are_not_metadata(self):
        routes = {
            "from-import": "from sys import modules\nother = modules[\"re\"]\n",
            "renamed-from-import": "from sys import modules as cache\nother = cache[\"re\"]\n",
            "cache-alias": "import sys as state\ncache = state.modules\nother = cache[\"re\"]\n",
            "module-alias": "import sys as state\ncopy = state\nother = copy.modules[\"re\"]\n",
            "cache-get": "from sys import modules as cache\nother = cache.get(\"re\")\n",
        }
        for name, route in routes.items():
            with self.subTest(route=name):
                self.refuse(route + "other.match = lambda pattern, value: pattern\n")

    def test_builtin_loader_aliases_are_not_metadata(self):
        routes = {
            "renamed-module": "import builtins as runtime\nother = runtime.__import__(\"re\")\n",
            "renamed-from-import": "from builtins import __import__ as acquire\nother = acquire(\"re\")\n",
        }
        for name, route in routes.items():
            with self.subTest(route=name):
                self.refuse(route + "other.match = lambda pattern, value: pattern\n")

    def test_frozen_importlib_aliases_and_implicit_builtins_are_not_metadata(self):
        routes = {
            "frozen-module": "import _frozen_importlib as loader\nother = loader._gcd_import(\"re\")\n",
            "frozen-from-import": "from _frozen_importlib import _gcd_import as acquire\nother = acquire(\"re\")\n",
            "implicit-builtins": "other = __builtins__.__import__(\"re\")\n",
            "implicit-builtins-mapping": "other = __builtins__[\"__import__\"](\"re\")\n",
        }
        for name, route in routes.items():
            with self.subTest(route=name):
                self.refuse(route + "other.match = lambda pattern, value: pattern\n")

    def test_loaded_modules_cannot_escape_the_namespace_proof(self):
        route = "import importlib as loader\nother = loader.import_module(\"re\")\n"
        mutations = {
            "dictionary-write": "other.__dict__[\"match\"] = lambda pattern, value: pattern\n",
            "module-alias": "copy = other\ncopy.match = lambda pattern, value: pattern\n",
            "callback-escape": "unknown(other)\n",
            "function-escape": "unknown(other.match)\n",
        }
        for name, mutation in mutations.items():
            with self.subTest(route=name):
                self.refuse(route + mutation)

    def test_unknown_module_names_and_cache_keys_withhold_metadata(self):
        routes = (
            "import importlib as loader\nother = loader.import_module(chosen)\n",
            "from sys import modules as cache\nother = cache[chosen]\n",
        )
        for route in routes:
            with self.subTest(route=route.splitlines()[0]):
                self.refuse(route + "other.match = lambda pattern, value: pattern\n")

    def test_unused_imports_and_unrelated_metadata_keep_direct_regex_proof(self):
        metadata = (
            "import importlib as loader\n",
            "from importlib import import_module as acquire\n",
            "import sys as state\nversion = state.version_info\n",
            "import builtins as runtime\nsize = runtime.len(items)\n",
            "version = settings.modules\n",
        )
        for setup in metadata:
            with self.subTest(setup=setup.splitlines()[0]):
                GUARD.require_safe_source("public synthetic source", "grammar.py", self.source(setup))

    def test_regex_input_and_result_suffix_literals_stay_refused(self):
        ordinary = self.source()
        sources = (
            ordinary.replace(", source)", ", \"PUBLIC_SYNTHETIC_INPUT\")"),
            ordinary.replace(", source)", ", source) or \"PUBLIC_SYNTHETIC_SUFFIX\""),
            ordinary.replace(", source)", ", source) + \"PUBLIC_SYNTHETIC_SUFFIX\""),
        )
        for index, source in enumerate(sources):
            with self.subTest(case=index):
                ast.parse(source)
                with self.assertRaises(SystemExit):
                    GUARD.require_safe_source("public synthetic source", "grammar.py", source)


if __name__ == "__main__":
    unittest.main()
