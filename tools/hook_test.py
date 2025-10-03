"""Small test file used to verify git hooks (pyflakes + secret scan)."""

def hello():
    """Return a short message used by the test commit."""
    return "ok"


if __name__ == "__main__":
    print(hello())
