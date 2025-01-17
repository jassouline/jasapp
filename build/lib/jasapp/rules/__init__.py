import pkgutil
import importlib
import inspect
from pathlib import Path
from jasapp.rules.base_rule import BaseRule


def discover_rules():
    """
    Discover and load all rules from the jasapp.rules package and its subpackages.
    """
    rules = {}
    package_dir = Path(__file__).parent  # Répertoire racine (jasapp/rules)

    # Parcours récursif des fichiers Python dans tous les sous-répertoires
    for file_path in package_dir.rglob("*.py"):
        if file_path.name == "__init__.py":  # Ignorer les fichiers __init__.py
            continue

        # Construire le nom du module complet en commençant par 'jasapp.rules'
        relative_path = file_path.relative_to(package_dir.parent)  # Relatif au package racine
        module_name = ".".join(relative_path.with_suffix("").parts)  # Convertir en module Python
        module_name = f"jasapp.{module_name}"  # Préfixer avec le chemin racine du package

        try:
            # Importer le module dynamiquement
            module = importlib.import_module(module_name)

            # Extraire les classes qui héritent de BaseRule
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BaseRule) and obj is not BaseRule:
                    rules[name] = obj
        except Exception as e:
            print(f"Error importing {module_name}: {e}")  # Debugging

    return rules


# Charger toutes les règles dynamiquement
all_rules = discover_rules()

# Rendre les règles disponibles globalement
globals().update(all_rules)
__all__ = list(all_rules.keys())
