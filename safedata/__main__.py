"""Allow running the CLI as `python -m safedata ...`.

This is the PATH-independent way to use the command line tool: even if the
`safedata` script directory is not on your PATH, `python -m safedata check
file.csv` always works as long as the package is installed in that Python.
"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
