# Provides examples of using the Hypothesis module for fuzzy testing
# Running the python script normally will run the tests one by one and stop if it finds an errors without performing
# the remaining tests.
# If you run it using pytest, then all of the tests will be run even if one fails

from hypothesis import given, note, settings, infer
from hypothesis.strategies import text
from math import sqrt

from functions import not_kirby, get_sum_then_square_root


# using infer to auto-determine strategy based on the annotated types
@given(x=infer, y=infer)
def test_sum_then_square_root(x: int, y: int):
    test_sum = x + y
    if test_sum < 0:
        assert get_sum_then_square_root(x, y) is None
    else:
        assert get_sum_then_square_root(x, y) == sqrt(test_sum)


@given(text())
@settings(max_examples=1000)
def test_not_kirby(s: str):
    assert not_kirby(s)


if __name__ == "__main__":
    print("Running hypothesis for 'get_sum_then_square_root'...")
    test_sum_then_square_root()
    print("No problems found.")

    print("Running hypothesis for 'not_kirby'...")
    test_not_kirby()
    print("No problems were found.")
