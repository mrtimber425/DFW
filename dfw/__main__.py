"""Package entry point for ``python -m dfw``.

When the dfw package is executed as a module with the ``-m`` flag
(e.g. ``python -m dfw``) the interpreter looks for this
``__main__`` module and runs it. We forward to ``dfw.main.main`` to
launch the GUI. This file exists solely to provide that entry point.
"""

from .main import main


if __name__ == '__main__':
    main()