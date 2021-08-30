import atheris


with atheris.instrument_imports():
    import sys
    import functions


def test_atheris_only(data):
    fdp = atheris.FuzzedDataProvider(data)
    random_str = fdp.ConsumeUnicodeNoSurrogates(30)  # turn bytes to str
    functions.not_kirby(random_str)


if __name__ == "__main__":
    # see https://github.com/google/oss-fuzz/blob/master/projects/ujson/hypothesis_structured_fuzzer.py
    atheris.Setup(sys.argv, atheris.instrument_func(test_atheris_only))
    atheris.Fuzz()
