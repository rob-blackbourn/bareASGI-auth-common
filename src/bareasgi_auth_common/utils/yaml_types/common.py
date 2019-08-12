"""
Common code
"""

from typing import Type, Pattern, Callable, Any, Optional
import yaml


def add_custom_type(
        loader: Type[yaml.FullLoader],
        dumper: Type[yaml.Dumper],
        typ: Type,
        tag: str,
        representer: Callable[[yaml.Dumper, Any], yaml.ScalarNode],
        constructor: Callable[[yaml.Loader, yaml.ScalarNode], Optional[Any]],
        pattern: Pattern
) -> None:
    """Add a custom type"""
    dumper.add_representer(typ, representer)
    loader.add_constructor(tag, constructor)
    loader.add_implicit_resolver(tag, pattern, None)
