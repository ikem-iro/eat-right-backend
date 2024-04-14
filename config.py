"""
Security configurations for the application.

This module contains the security-related configurations for the application,
including the secret key, algorithm, and access token expiration time.
"""

"""
Secret key used for generating and verifying tokens
"""
SECRET_KEY = "a0f087d8449cd0e3b2f27877d41bb02952ce4342893271a6dd0e620403b620e2"

"""
Algorithm used for generating and verifying tokens
"""
ALGORITHM = "HS256"

"""
# Number of minutes after which the access token will expire
"""
ACCESS_TOKEN_EXPIRE_MINUTES = 30