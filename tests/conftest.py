import os

# The suite uses /auth/dev-token, which only exists in dev. Production is the default.
os.environ.setdefault("MLSHIELD_ENV", "dev")
