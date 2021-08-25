from inspect import signature
from math import sqrt
import atheris

with atheris.instrument_imports():
    import sys


def get_sum_then_square_root(x: int, y: int):
    """
    Performs the sum of x and y, then calculates the square root of the result

    :param x: first int
    :param y: second int
    :return: None
    """
    add = x + y
    print(f"{x} + {y} = {add}")
    result = sqrt(add)
    print(f"sqrt({add}) = {result}")


@atheris.instrument_func
def fuzzy_testing(data):
    """
    Performs fuzzy testing on the function get_sum_then_square_root.

    :param data: data provided for fuzzy testing
    :return: None
    """
    sig = signature(get_sum_then_square_root)
    args = []
    # Generate the correct amount and types of input parameters for the function
    for param in sig.parameters:
        if sig.parameters[param].annotation == int:
            fdp = atheris.FuzzedDataProvider(data)
            args.append(fdp.ConsumeInt(4))
    # Run the function with the generated data
    get_sum_then_square_root(*args)


atheris.Setup(sys.argv, fuzzy_testing)
atheris.Fuzz()
