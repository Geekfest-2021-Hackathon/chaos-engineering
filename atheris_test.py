from inspect import signature
from math import sqrt
import atheris

with atheris.instrument_imports():
    import sys


def get_sum_then_square_root(x, y):
    add = x + y
    print(f"{x} + {y} = {add}")
    result = sqrt(add)
    print(f"sqrt({add}) = {result}")


@atheris.instrument_func
def fuzzy_testing(data):
    sig = signature(get_sum_then_square_root)
    args = []
    for param in sig.parameters:
        fdp = atheris.FuzzedDataProvider(data)
        args.append(fdp.ConsumeInt(4))

    get_sum_then_square_root(*args)


atheris.Setup(sys.argv, fuzzy_testing)
atheris.Fuzz()
