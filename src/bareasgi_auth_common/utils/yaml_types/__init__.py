"""Yaml types"""

import yaml


def initialise_types():
    from .time_handler import add_custom_type_time
    from .timedelta_handler import add_custom_type_timedelta
    add_custom_type_time(yaml.FullLoader, yaml.Dumper)
    add_custom_type_timedelta(yaml.FullLoader, yaml.Dumper)