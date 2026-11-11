import sys

from . import _old_python_message

_TOO_OLD = _old_python_message()
if _TOO_OLD is not None:        # normally sipar/__init__.py has stopped already; cli.py needs 3.12 syntax
    try:
        sys.stderr.write(_TOO_OLD + "\n")
    except Exception:                   # no stderr (`2>&-`: None), a closed or broken one: still exit 2
        pass
    sys.exit(2)

from .cli import main  # noqa: E402

sys.exit(main())
