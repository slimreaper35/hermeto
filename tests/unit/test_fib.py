import cachi2.fib as fib


def test_fibonacci_iterative() -> None:
    assert fib.fibonacci_iterative(1)


def test_fibonacci_recursive() -> None:
    assert fib.fibonacci_recursive(1)
