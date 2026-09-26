# Synthetic HOME fixture for integration tests (§13.3)
# Contains:
# - .ssh/id_ed25519.pub (main work key)
# - .ssh/id_ed25519_copy.pub (copy of id_ed25519.pub, same fingerprint)
# - .ssh/id_rsa.pub (rsa key)
# - .ssh/id_canary (private-key trap canary)
# - .ssh/config (main config file)
# - .ssh/config.d/included.conf (included config)
# - .ssh/config.d/cycle.conf (circular include test)
