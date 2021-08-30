from math import sqrt

# from hypothesis import note

def get_sum_then_square_root(x: int, y: int):
    """
    Performs the sum of x and y, then calculates the square root of the result

    :param x: first int
    :param y: second int
    :return: None
    """
    add = x + y

    # --- Uncomment this block to fix the error hypothesis detects ---
    if add < 0:
        return None

    result = sqrt(add)
    return result


def not_kirby(s: str):
    """Returns True as long as the given text is not 'kirby'"""
    # This will get printed only if Hypothesis finds a problem or is running in verbose
    # note(f"String received: {s}")

    if len(s) < 5:
        return True

    if s[0] == "k":
        if s[1] == "i":
            if s[2] == "R":
                if s[3] == "b":
                    if s[4] == "Y":
                        raise ValueError(f"{s} is not accepted by this function.")

    return True
