# Fuzz (atheris) + Hypothesis strategies. Seems to combine both fine, but way slower or not adapting enough,
# as it did not find a bug vs using atheris only

from hypothesis import given, strategies as st

import atheris


with atheris.instrument_imports():
    import sys
    import functions


@given(st.text())
def test_not_kirby(s):
    functions.not_kirby(s)


if __name__ == "__main__":
    # see https://github.com/google/oss-fuzz/blob/master/projects/ujson/hypothesis_structured_fuzzer.py
    atheris.Setup(sys.argv, atheris.instrument_func(test_not_kirby.hypothesis.fuzz_one_input))
    atheris.Fuzz()
