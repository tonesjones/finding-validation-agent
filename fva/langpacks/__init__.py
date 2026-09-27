from fva.langpacks.base import DeclaredDependency, LanguagePack, glob_match
from fva.langpacks.node import NodePack

REGISTRY: dict[str, LanguagePack] = {"node": NodePack()}

__all__ = ["REGISTRY", "DeclaredDependency", "LanguagePack", "glob_match"]
