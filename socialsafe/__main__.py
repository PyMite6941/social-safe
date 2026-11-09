"""Allow `python -m socialsafe ...` on any OS."""

import sys

from .cli import main

sys.exit(main())
