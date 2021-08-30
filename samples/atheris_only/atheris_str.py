"""Sample using atheris with string inputs """

import atheris
import sys


@atheris.instrument_func
def not_kirby(s: str):
    """Returns True as long as the given text is not 'kirby'"""
    if len(s) < 5:
        return True

    if s[0] == "k":
        if s[1] == "i":
            if s[2] == "R":
                if s[3] == "b":
                    if s[4] == "Y":
                        raise ValueError(f"{s} is not accepted by this function.")

    return True


@atheris.instrument_func
def test_one_input(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    random_str = fdp.ConsumeUnicodeNoSurrogates(30)  # turn bytes to str
    not_kirby(random_str)


if __name__ == '__main__':
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
