import sys
from .replay import main

if __name__ == "__main__":
    # python -m pipeline --from-bronze <dir> --to <new.duckdb>
    sys.exit(main())
