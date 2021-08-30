"""
Sample using atheris to find bugs in a function via fuzzing.

- get_sum_then_square_root is the function being tested
- fuzzy_testing() is the fuzz target and takes the bytes generated by the fuzzer
- atheris.FuzzedDataProvider is used to consume the bytes and generate valid (int) args and scope the fuzzing


See https://github.com/google/atheris

"""

from inspect import signature
import atheris

with atheris.instrument_imports():
    import sys
    from math import sqrt


def get_sum_then_square_root(x: int, y: int) -> float:
    """
    Performs the sum of x and y, then calculates the square root of the result

    :param x: first int
    :param y: second int
    :return: result: float
    """
    add = x + y
    print(f"a. {x} + {y} = {add}")
    result = sqrt(add)
    print(f"b. sqrt({add}) = {result}")
    print("--")
    return result


@atheris.instrument_func
def fuzzy_testing(data):
    """
    Performs fuzzy testing on the function get_sum_then_square_root.

    :param data: data provided for fuzzy testing (generated bytes)
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


if __name__ == '__main__':
    atheris.Setup(sys.argv, fuzzy_testing)
    atheris.Fuzz()
