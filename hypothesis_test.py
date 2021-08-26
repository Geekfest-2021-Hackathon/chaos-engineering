from hypothesis import given
from hypothesis.strategies import integers
from math import sqrt


@given(integers(), integers())
def test_sum_then_square_root(x, y):
    test_sum = x + y
    if test_sum < 0:
        assert get_sum_then_square_root(x, y) is None
    else:
        assert get_sum_then_square_root(x, y) == sqrt(test_sum)


def get_sum_then_square_root(x: int, y: int):
    """
    Performs the sum of x and y, then calculates the square root of the result

    :param x: first int
    :param y: second int
    :return: None
    """
    add = x + y

    # --- Uncomment this block to fix the error hypothesis generates ---
    # if add < 0:
    #     return None

    result = sqrt(add)
    return result


if __name__ == "__main__":
    print("Running hypothesis...")
    test_sum_then_square_root()
    print("No problems found.")
