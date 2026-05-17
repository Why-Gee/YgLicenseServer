"""Pure business logic. No FastAPI types here.

Services take a `Session` (and other primitive deps) and return plain values
or raise the exceptions in `app.services.errors`. Routers translate those
exceptions to HTTP responses.
"""
