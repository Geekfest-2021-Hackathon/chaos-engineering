**Dev notes**

This document describes how to setup a dev environment and experiment with the samples in the repository.

It's also used to document any technical details or findings during the testing (that wouldn't necessarily fit in the main README).

# Dev environment

## Using Docker

Clone the repository and go to the root directory, then:

````shell
# build latest 'chaosdev' image
docker build -t chaosdev .

# Two ways to run it (auto-start api or not)
# 1. run it starting from bash terminal (do not start api, useful with api fuzzing samples)
docker run -it -v ${PWD}:/app/ chaosdev bash

# 2. run it normally (detached) to start the API. Can later connect to it with a bash terminal
docker run -d -v ${PWD}:/app/ -p 9060:9060 --rm --name chaosdev chaosdev

# connect to running container
docker exec -it chaosdev bash

# check logs
docker logs chaosdev -f

````

If behind proxy, try ``docker build --build-arg http_proxy=$env:http_proxy --build-arg https_proxy=$env:https_proxy -t chaosdev .`` or some equivalent syntax, depending on your terminal.

## Don't have Docker

You can still clone the repository and create a virtual environment, then run ``pip install -r requirements.txt``. Just note that atheris (libFuzzer specifically) is not available on Windows, which is why the docker setup is preferred.

TODO - include codeready workspaces method (all we'd need is clone + refer to Dockerfile to setup a new environment)

# Samples

After starting the container run ``cd /app/samples/`` to change into the samples directory, then go into the relevant sub-directory.

Note that the prompt won't show the current directory, you can always run ``pwd`` to see that.

[[_TOC_]]

## Application fuzzing

### Atheris only

**Objective**: Using [atheris](https://github.com/google/atheris) to find bugs in a function that performs calculations.

> Note that ``print()`` usage in functions can help debug and see what's being generated real time but considerably slows down the fuzzing and should be avoided for real testing.

#### First test

Run the fuzzer with ``python atheris_1.py``. A bug is quickly found:
````shell
chaos> cd /app/samples/atheris_only

chaos> python atheris_1.py
...
[TRUNCATED]
a. 41 + -86 = -45

 === Uncaught Python exception: ===
ValueError: math domain error
Traceback (most recent call last):
  File "/app/samples/atheris_only/atheris_1.py", line 57, in fuzzy_testing
    get_sum_then_square_root(*args)
  File "/app/samples/atheris_only/atheris_1.py", line 31, in get_sum_then_square_root
    result = sqrt(add)

==136== ERROR: libFuzzer: fuzz target exited
SUMMARY: libFuzzer: fuzz target exited

````
There is no protection against ``sqrt(x)`` when x is negative in the function, hence this bug. Note that crash files are created with the bytes that generated a failure.

#### Second test

Let's fix this bug in a 2nd version of the function by arbitrarily returning 0 if the sum is negative. To test more values, we can also consume more bytes to generate ints:
````text
fdp.ConsumeInt(4) -> fdp.ConsumeInt(sys.maxsize)
````

Test that now: ``python atheris_2.py``

````text
a. 55660619659510420046936220347702259438628078685139082548147873457543343381198720395289105517894609918530521506664363559285548274956453599403879961790796966215592017020801176266798909273854481939690470257980081566030644640481
2144496866640451638831288803463920633276135070684723399423936794953759731528241937524343649729511423 + 5566061965951042004693622034770225943862807868513908254814787345754334338119872039528910551789460991853052150666436355928554
82749564535994038799617907969662155920170208011762667989092738544819396904702579800815660306446404812144496866640451638831288803463920633276135070684723399423936794953759731528241937524343649729511423 = 111321239319020840093872
44069540451887725615737027816509629574691508668676239744079057821103578921983706104301332872711857109654991290719880775992358159393243118403404160235253359781854770896387938094051596016313206128928096242889937332809032776625776
06927841266552270141369446798847873589907519463056483875048687299459022846

 === Uncaught Python exception: ===
OverflowError: int too large to convert to float
Traceback (most recent call last):
  File "/app/samples/atheris_only/atheris_2.py", line 57, in fuzzy_testing
    get_sum_then_square_root(*args)
  File "/app/samples/atheris_only/atheris_2.py", line 34, in get_sum_then_square_root
    result = sqrt(add)

==35== ERROR: libFuzzer: fuzz target exited

````

A second bug was found due to the bigger inputs, `OverflowError: int too large to convert to float`

#### Third test

Let's add another patch to return the infinite value in this case. You can un-comment the print statements to see the values generated but the test will run a lot slower.

``python atheris_3.py``

This will run indefinitely (until a bug is found) with the current setup. We can add a stopping condition with a command line flag - atheris uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html#options) under the hood and all its options are available.

In this case we just want to fuzz for 60s max, we can use the `max_total_time` flag.

Resulting command: ``python atheris_3.py -max_total_time=60`` (try `-help=1` to see all options)

Output
````text
chaos> python atheris_3.py -max_total_time=60
INFO: Using built-in libfuzzer
WARNING: Failed to find function "__sanitizer_acquire_crash_state".
WARNING: Failed to find function "__sanitizer_print_stack_trace".
WARNING: Failed to find function "__sanitizer_set_death_callback".
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 37243835
INFO: Loaded 1 modules   (5 inline 8-bit counters): 5 [0x55e3b7d621e0, 0x55e3b7d621e5),
INFO: Loaded 1 PC tables (5 PCs): 5 [0x55e3b7d63410,0x55e3b7d63460),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 5 ft: 5 corp: 1/1b exec/s: 0 rss: 35Mb
#131072 pulse  cov: 5 ft: 5 corp: 1/1b lim: 1300 exec/s: 43690 rss: 35Mb
#262144 pulse  cov: 5 ft: 5 corp: 1/1b lim: 2611 exec/s: 37449 rss: 35Mb
#524288 pulse  cov: 5 ft: 5 corp: 1/1b lim: 4096 exec/s: 37449 rss: 35Mb
#1048576        pulse  cov: 5 ft: 5 corp: 1/1b lim: 4096 exec/s: 37449 rss: 35Mb
#2097152        pulse  cov: 5 ft: 5 corp: 1/1b lim: 4096 exec/s: 36157 rss: 36Mb
#2203807        DONE   cov: 5 ft: 5 corp: 1/1b lim: 4096 exec/s: 36127 rss: 36Mb
Done 2203807 runs in 61 second(s)

````

#### String test

One final test to see how well the coverage-guided fuzzing adapts to find bugs.

You can run ``python atheris_str.py`` and see how it very quickly finds the 'kiRbY' input that triggers the function to crash.

````text
chaos> python atheris_str.py
INFO: Using built-in libfuzzer
WARNING: Failed to find function "__sanitizer_acquire_crash_state".
WARNING: Failed to find function "__sanitizer_print_stack_trace".
WARNING: Failed to find function "__sanitizer_set_death_callback".
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2507196679
INFO: Loaded 1 modules   (10 inline 8-bit counters): 10 [0x556415c997a0, 0x556415c997aa),
INFO: Loaded 1 PC tables (10 PCs): 10 [0x556415c07700,0x556415c077a0),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 34Mb
#212    NEW    cov: 5 ft: 5 corp: 2/7b lim: 6 exec/s: 0 rss: 34Mb L: 6/6 MS: 5 ChangeByte-ShuffleBytes-InsertByte-InsertRepeatedBytes-InsertByte-
#3833   NEW    cov: 6 ft: 6 corp: 3/25b lim: 38 exec/s: 0 rss: 34Mb L: 18/18 MS: 1 InsertRepeatedBytes-
#3844   REDUCE cov: 6 ft: 6 corp: 3/17b lim: 38 exec/s: 0 rss: 34Mb L: 10/10 MS: 1 EraseBytes-
#3901   REDUCE cov: 6 ft: 6 corp: 3/14b lim: 38 exec/s: 0 rss: 34Mb L: 7/7 MS: 2 ShuffleBytes-EraseBytes-
#3935   REDUCE cov: 6 ft: 6 corp: 3/13b lim: 38 exec/s: 0 rss: 34Mb L: 6/6 MS: 4 ChangeBinInt-EraseBytes-ShuffleBytes-CrossOver-
#9599   NEW    cov: 7 ft: 7 corp: 4/27b lim: 92 exec/s: 0 rss: 34Mb L: 14/14 MS: 4 CrossOver-ChangeBit-CopyPart-ChangeBinInt-
#9645   REDUCE cov: 7 ft: 7 corp: 4/20b lim: 92 exec/s: 0 rss: 34Mb L: 7/7 MS: 1 EraseBytes-
#9985   REDUCE cov: 7 ft: 7 corp: 4/19b lim: 92 exec/s: 0 rss: 34Mb L: 6/6 MS: 5 EraseBytes-CrossOver-ShuffleBytes-CopyPart-EraseBytes-
#66397  REDUCE cov: 8 ft: 8 corp: 5/25b lim: 652 exec/s: 0 rss: 34Mb L: 6/6 MS: 2 ChangeBit-ChangeByte-
#96558  NEW    cov: 9 ft: 9 corp: 6/31b lim: 949 exec/s: 0 rss: 34Mb L: 6/6 MS: 1 CrossOver-

 === Uncaught Python exception: ===
ValueError: kiRbYk is not accepted by this function.
Traceback (most recent call last):
  File "/app/samples/atheris_only/atheris_str.py", line 27, in test_one_input
    not_kirby(random_str)
  File "/app/samples/atheris_only/atheris_str.py", line 18, in not_kirby
    raise ValueError(f"{s} is not accepted by this function.")

==43== ERROR: libFuzzer: fuzz target exited
````

The important bit here ``ValueError: kiRbYk is not accepted by this function.`` shows how a failing input was found without being explicitly checked in the tests.

A second example was included to show how we may test a function with multiple (string) inputs.

### Hypothesis

**Objective**: Using [hypothesis](https://hypothesis.readthedocs.io/) to find bugs by running tests with generated values following given strategies.

- Testing the same `get_sum_then_square_root` as previously, feeding it generated integers
- Also testing the ``not_kirby`` function that crashes if the input starts with `kiRbY`

These functions are written in a separate file for reuse: ``functions.py``

Since hypothesis integrates with pytest we can run all the ``test_xxx`` tests at once and catch all the failures.

#### First run

``pytest hypothesis_test.py``

````text
chaos> cd /app/samples/hypothesis

chaos> pytest hypothesis_test.py
======================================================================================================= test session starts =======================================================================================================
platform linux -- Python 3.9.2, pytest-6.2.4, py-1.10.0, pluggy-0.13.1
rootdir: /app/samples/hypothesis
plugins: hypothesis-6.17.1
collected 2 items
...
>       result = sqrt(add)
E       ValueError: math domain error

functions.py:20: ValueError
----------------------------------------------------------------------------------------------------------- Hypothesis ------------------------------------------------------------------------------------------------------------
Falsifying example: test_sum_then_square_root_bad(
    x=0, y=-1,
)
===================================================================================================== short test summary info =====================================================================================================
FAILED hypothesis_test.py::test_sum_then_square_root_bad - ValueError: math domain error
=================================================================================================== 1 failed, 1 passed in 3.74s ===================================================================================================

````

- We can see that the one of the tests failed, with the same ``ValueError`` that atheris detected. In addition, hypothesis tries to minimize the args to give the smallest values that reproduce the crash.
- Note that the string test passed, which means that even with 1000 examples (the default is 100) hypothesis couldn't find the ``kiRbY`` value that breaks the function.

#### Second run (bugfix)

Un-comment the 2 lines in ``functions.py`` to fix the negative sum error
````python
def get_sum_then_square_root(x, y):
    # --- Uncomment this block to fix the error hypothesis detects ---
    if add < 0:
        return None
````

Re-run the tests and they should all be passing now.
````text
chaos> pytest hypothesis_test.py
======================================================================================================= test session starts =======================================================================================================
platform linux -- Python 3.9.2, pytest-6.2.4, py-1.10.0, pluggy-0.13.1
rootdir: /app/samples/hypothesis
plugins: hypothesis-6.17.1
collected 2 items

hypothesis_test.py ..                                                                                                                                                                                                       [100%]

======================================================================================================== 2 passed in 2.33s ========================================================================================================
````

#### Automatically generating tests

Hypothesis has a [ghostwriting feature](https://hypothesis.readthedocs.io/en/latest/ghostwriter.html) that will automatically generate tests given some source code.

To generate code from the ``functions.py`` source file for example:
````shell
chaos> cd /app/samples/hypothesis/

chaos> hypothesis write functions
`````

An example output is saved in ``generated_test.py``. Note that not all the generated functions are useful/needed, this is still an approximation and there are multiple flags/functions to generate the tests - check docs for details.


### Combining hypothesis & atheris

Atheris seems to be more powerful, as it's tracking code coverage and trying to generate inputs to cover more code. It was able to find bugs that hypothesis couldn't. The interface is cumbersome however, as it simply generates bytes which usually have to be hand-converted to another data type.

Hypothesis gives a very powerful and readable interface to define strategies, combine them, and create complex test scenarios with very little code.

Luckily hypothesis can [integrate with external fuzzers](https://hypothesis.readthedocs.io/en/latest/details.html#use-with-external-fuzzers), atheris being one of them.

Check the ``/samples/combined/`` directory for a practical example.

````shell
chaos> cd /app/samples/combined

# run the sample combining both
chaos> python ht_fuzz_test.py

INFO: Instrumenting functions
INFO: Using built-in libfuzzer
WARNING: Failed to find function "__sanitizer_acquire_crash_state".
WARNING: Failed to find function "__sanitizer_print_stack_trace".
WARNING: Failed to find function "__sanitizer_set_death_callback".
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2438398044
INFO: Loaded 1 modules   (26 inline 8-bit counters): 26 [0x558957967680, 0x55895796769a),
INFO: Loaded 1 PC tables (26 PCs): 26 [0x5589577c8cb0,0x5589577c8e50),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 4 ft: 4 corp: 1/1b exec/s: 0 rss: 48Mb
#7      NEW    cov: 6 ft: 6 corp: 2/3b lim: 4 exec/s: 0 rss: 48Mb L: 2/2 MS: 5 InsertByte-CopyPart-CopyPart-ChangeBit-ChangeByte-
#10     REDUCE cov: 6 ft: 6 corp: 2/2b lim: 4 exec/s: 0 rss: 48Mb L: 1/1 MS: 3 CopyPart-ChangeByte-EraseBytes-
#3356   REDUCE cov: 8 ft: 8 corp: 3/33b lim: 33 exec/s: 0 rss: 48Mb L: 31/31 MS: 1 InsertRepeatedBytes-
#3681   REDUCE cov: 8 ft: 8 corp: 3/28b lim: 33 exec/s: 3681 rss: 48Mb L: 26/26 MS: 5 ChangeBit-ShuffleBytes-CrossOver-EraseBytes-EraseBytes-
#6305   REDUCE cov: 8 ft: 8 corp: 3/27b lim: 58 exec/s: 3152 rss: 48Mb L: 25/25 MS: 4 ChangeBinInt-ShuffleBytes-CopyPart-EraseBytes-
#8192   pulse  cov: 8 ft: 8 corp: 3/27b lim: 74 exec/s: 2730 rss: 48Mb
#16384  pulse  cov: 8 ft: 8 corp: 3/27b lim: 156 exec/s: 2340 rss: 48Mb
#16655  REDUCE cov: 8 ft: 8 corp: 3/26b lim: 156 exec/s: 2379 rss: 48Mb L: 24/24 MS: 5 CopyPart-CopyPart-CrossOver-EraseBytes-EraseBytes-
...
[TRUNCATED]
````
This seems to generally work combining both (as in the bytes get generated then turned to strings because of the strategy, and would probably work similarly with other strategies), and we can verify that by adding print statements.

However, even after letting it run for a while it's not finding the bad input. For comparison purposes the relevant 'atheris only' test (see ``fuzz_only.py``) finds the bad input within the few first seconds.

This (along with this [discussion](https://github.com/google/atheris/issues/20) and [commit](https://github.com/google/atheris/commit/ee02c830f620fb085fb0260f6a8747fe15d21fbd) on the atheris repo) seem to indicate they don't work that well together, and for coverage guided fuzzing using atheris provides better results.

## API Fuzzing

### [APIFuzzer](https://github.com/KissPeter/APIFuzzer)

For this you'll need the API (defined in ``samples/apifuzzer/main.py``) to be running at localhost:9060. You can check with curl.

If not you can exit and run the container with ``docker run -d -v ${PWD}:/app/ -p 9060:9060 --rm --name chaosdev chaosdev``, then connect using ``docker exec -it chaosdev bash``

````shell
chaos> cd /app/samples/apifuzzer

# if needed, json spec can be retrieved from running api
chaos> curl http://localhost:9060/openapi.json > api-spec.json

# create reports directory then run fuzzer
chaos> mkdir reports
chaos> APIFuzzer -s api-spec.json -u http://localhost:9060/ -r reports/

# view a report
chaos> json_pp < reports/170_1630820111.9629142.json
{
   "state" : "COMPLETED",
   "reason" : "failed",
   "name" : {},
   "response" : "",
   "request_method" : "GET",
   "request_url" : "http://localhost:9060/items//./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././
./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.
/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././
./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.
/./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.?q=asd",
   "parsed_status_code" : 307,
   "status" : "failed",
   "sub_reports" : [],
   "request_body" : {},
   "request_headers" : "{\"User-Agent\": \"APIFuzzer 0.9.9\", \"Accept-Encoding\": \"gzip, deflate\", \"Accept\": \"*/*\", \"Connection\": \"keep-alive\", \"Content-Type\": \"application/json\"}",
   "test_number" : 170
}


````

This tool seems useful to quickly scan an API for unexpected errors, as it would be pretty simple to include in a CI pipeline.

The problem is that it seems to lack flexibility as there are not many ways to configure what it does. For example in the failed test above the tool seems to consider 307 responses as failures, and it looks like we can't change that.


### Atheris against (fast)api code

The ``test_main.py`` file is what a usual fastapi endpoint test file looks like (see [docs](https://fastapi.tiangolo.com/tutorial/testing/)), for reference. Inputs are chosen and coded in the test.

``atheris_test.py`` is the version using fuzzing to test that same endpoint (via the test client), and it can still find the issue - though it is considerably slower than the test with atheris and the function only (without fastapi middleware)

````shell
chaos> cd /app/samples/apifuzzer

chaos> python atheris_test.yp
[TRUNCATED]
...
#39600  REDUCE cov: 12 ft: 12 corp: 7/33b lim: 357 exec/s: 825 rss: 59Mb L: 6/6 MS: 1 ChangeByte-
#65536  pulse  cov: 12 ft: 12 corp: 7/33b lim: 607 exec/s: 829 rss: 59Mb
#131072 pulse  cov: 12 ft: 12 corp: 7/33b lim: 1260 exec/s: 829 rss: 59Mb

 === Uncaught Python exception: ===
ValueError: kiRbY is not accepted by this function.
Traceback (most recent call last):
  File "/app/samples/apifuzzer/atheris_test.py", line 21, in str_test
    response = client.get(url=url)
  File "/usr/local/lib/python3.9/site-packages/requests/sessions.py", line 555, in get
    return self.request('GET', url, **kwargs)
...
[TRUNCATED]
````


Additional notes:
- In ``atheris_only/atheris_generic.py`` there is starter logic for defining a generic atheris fuzzing test that could work with any kind of function, by inferring from the signature
- There are a few examples (e.g. ``atheris_str.py`) throughout the samples showing how to transform the generated bytes in multiple input types. So far we tried (in the docs it's always one input):
  - creating 2 FuzzedDateProvider with the generated data. Problem: the inputs all end up being the same, which is a big constraint.
  - the 2nd call to a ``fdp.ConsumeXX(sys.maxsize)`` is empty, which means it probably uses some sort of buffer which led us to try and split the bytes.
  - splitting the bytes then having 2 FuzzedDataProvider. Seems to work ok so far.
- To save the generated crash files, see the ``-artifact_prefix`` param of libfuzzer
- To reuse crash files, pass the corpus (test files) directory (CORPUS_DIR is the last argument of the command call, not a flag/parameter)
- [Here](https://github.com/google/oss-fuzz/blob/master/projects/ujson/hypothesis_structured_fuzzer.py) is an example using hypothesis and atheris to generate JSON objects, and feed them to ``ujson``.


### Hypothesis against pydantic & fastapi

Hypothesis can build a strategy to generate objects based on a class definition, in this case the [pydantic](https://pydantic-docs.helpmanual.io/) model. See https://pydantic-docs.helpmanual.io/hypothesis_plugin/ for details.

This means we can use the same test client but feed it random (but schema compliant) data instead of pre-defined test data.

````shell
chaos> cd /app/samples/apifuzzer/

# been getting random warnings on latest build for some reason
chaos> pytest hypothesis_test.py --disable-warnings

...
[TRUNCATED]
>             raise InvalidJSONError(ve, request=self)
E             requests.exceptions.InvalidJSONError: Out of range float values are not JSON compliant

/usr/local/lib/python3.9/site-packages/requests/models.py:473: InvalidJSONError
----------------------------------------------------------------------------------------------------------- Hypothesis ------------------------------------------------------------------------------------------------------------
Falsifying example: test_post_item(
    item=Item(name='', description=None, price=inf, tax=None),
)
===================================================================================================== short test summary info =====================================================================================================
FAILED hypothesis_test.py::test_post_item - requests.exceptions.InvalidJSONError: Out of range float values are not JSON compliant

````

One error is found, ``price`` can't take the infinite value as it is not JSON compliant. We can fix this by [not allowing](https://hypothesis.readthedocs.io/en/latest/data.html?#hypothesis.strategies.floats) ``inf`` and ``nan`` values
````python
@given(st.builds(Item, price=st.floats(allow_infinity=False, allow_nan=False)))
def test_post_item_fixed(item):
    ...
````

All the tests should be passing now. This shows how hypothesis could be easily added to existing test suites and add a randomness element.

When adding a test for the string endpoint, the following error is raised:
````text
s = '/'

    @given(st.text())
    def test_not_kirby(s):
        res = client.get(f"/not-kirby/{s}")
>       assert res.status_code == 200
E       assert 404 == 200
E        +  where 404 = <Response [404]>.status_code

````

We could add 404 to the accepted status codes, but we'll fix this by excluding '/' from the generated data - making the tests more efficient, using the [assume](https://hypothesis.readthedocs.io/en/latest/details.html?#making-assumptions) feature of hypothesis.
````python
import ...

@given(st.text())
def test_not_kirby(s):
    assume("/" not in s)  # comment this to trigger 404s
    res = client.get(f"/not-kirby/{s}")
    assert res.status_code == 200
````

And now all the tests should be passing!

Alternatively to `assume` the [``text`` strategy](https://hypothesis.readthedocs.io/en/latest/data.html?#hypothesis.strategies.text) could be customized but that involves playing with [unicode categories](https://hypothesis.works/articles/generating-the-right-data/) and is rather cumbersome.


### [Schemathesis](https://schemathesis.readthedocs.io/en/stable/index.html)

This library is built on top of hypothesis and will read the API schema then generate and run test cases (using the strategies under the hood).

It can be installed with ``pip install schemathesis``. The easiest way to use it is via the command line, if the API is already running - this should work against any API that exposes a Swagger/OpenAPI schema

#### Basic usage

````shell
chaos> cd /app/samples/schemathesis

chaos> schemathesis run http://localhost:9060/openapi.json
================================================================================================= Schemathesis test session starts ================================================================================================
platform Linux -- Python 3.9.7, schemathesis-3.9.7, hypothesis-6.17.4, hypothesis_jsonschema-0.20.1, jsonschema-3.2.0
rootdir: /app/samples/schemathesis
hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('/app/samples/schemathesis/.hypothesis/examples')
Schema location: http://localhost:9060/openapi.json
Base URL: http://localhost:9060/
Specification version: Open API 3.0.2
Workers: 1
Collected API operations: 5

GET / .                                                                                                                                                                                                                      [ 20%]
GET /items/{item_id} F                                                                                                                                                                                                       [ 40%]
GET /not-kirby/ .                                                                                                                                                                                                            [ 60%]
GET /not-kirby/{s} .                                                                                                                                                                                                         [ 80%]
POST /items/ .                                                                                                                                                                                                               [100%]

============================================================================================================= FAILURES ============================================================================================================
_____________________________________________________________________________________________________ GET /items/{item_id} [P] ____________________________________________________________________________________________________
1. Received a response with 5xx status code: 500

Path parameters : {'item_id': 101}
Headers         : {'User-Agent': 'schemathesis/3.9.7', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
Query           : {}

----------

Response payload: `Internal Server Error`

Run this Python code to reproduce this failure:

    requests.get('http://localhost:9060/items/101', headers={'User-Agent': 'schemathesis/3.9.7', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'})

Or add this option to your command line parameters: --hypothesis-seed=197757683039657737791709436318674589151
============================================================================================================= SUMMARY =============================================================================================================

Performed checks:
    not_a_server_error                    241 / 268 passed          FAILED

=================================================================================================== 4 passed, 1 failed in 5.76s ===================================================================================================

````

We can see that it read the schema and generated test cases for each endpoint - by default this will create up to 100 test cases per set and check that no server error (5xx responses) get triggered.

The log also shows how to reproduce this failure. The generated code samples uses python code and the ``requests`` library by default, but [that can be customized](https://schemathesis.readthedocs.io/en/stable/cli.html#code-samples-style) to generate curl commands for example.

Unlike APIFuzzer, there are many ways to configure the tests via the CLI:
- testing specific paths/endpoints (supports regex like ``^/api/users`` to test any path that starts with ``/api/users``) - see `--endpoint` param
- specific HTTP methods, or OpenAPI tags - see `--method` and `--tag` params
- specific fields values - e.g. ``--operation-id`` to set the `operationId` field value

See [Testing specific operations](https://schemathesis.readthedocs.io/en/stable/cli.html#testing-specific-operations) for detail.

In addition to checking for 5xx responses, there are other [common checks built-in](https://schemathesis.readthedocs.io/en/stable/cli.html#how-are-responses-checked). Let's use them all with the ``--checks all`` option, and generate curl samples to reproduce the failures.

````shell
chaos> schemathesis run http://localhost:9060/openapi.json --checks all --code-sample-style curl
================================================================================================= Schemathesis test session starts ================================================================================================
platform Linux -- Python 3.9.7, schemathesis-3.9.7, hypothesis-6.17.4, hypothesis_jsonschema-0.20.1, jsonschema-3.2.0
rootdir: /app/samples/schemathesis
hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('/app/samples/schemathesis/.hypothesis/examples')
Schema location: http://localhost:9060/openapi.json
Base URL: http://localhost:9060/
Specification version: Open API 3.0.2
Workers: 1
Collected API operations: 5

GET / F                                                                                                                                                                                                                      [ 20%]
GET /items/{item_id} F                                                                                                                                                                                                       [ 40%]
GET /not-kirby/ .                                                                                                                                                                                                            [ 60%]
GET /not-kirby/{s} .                                                                                                                                                                                                         [ 80%]
POST /items/ .                                                                                                                                                                                                               [100%]

============================================================================================================= FAILURES ============================================================================================================
____________________________________________________________________________________________________________ GET / [P] ____________________________________________________________________________________________________________
1. Received a response with a status code, which is not defined in the schema: 404

Declared status codes: 200

Headers         : {'User-Agent': 'schemathesis/3.9.7', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}

----------

Response payload: `{"detail":"Not Found"}`

Run this cURL command to reproduce this failure:

    curl -X GET -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'User-Agent: schemathesis/3.9.7' http://localhost:9060//

Or add this option to your command line parameters: --hypothesis-seed=172443696934723187616522578557658936638
_____________________________________________________________________________________________________ GET /items/{item_id} [P] ____________________________________________________________________________________________________
1. Received a response with a status code, which is not defined in the schema: 500

Declared status codes: 200, 422

Path parameters : {'item_id': 101}
Headers         : {'User-Agent': 'schemathesis/3.9.7', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
Query           : {}

----------

Response payload: `Internal Server Error`

Run this cURL command to reproduce this failure:

    curl -X GET -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'User-Agent: schemathesis/3.9.7' http://localhost:9060/items/101

Or add this option to your command line parameters: --hypothesis-seed=317918966440098399389263372817009257537


2. Received a response with 5xx status code: 500

Path parameters : {'item_id': 101}
Headers         : {'User-Agent': 'schemathesis/3.9.7', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
Query           : {}

----------

Response payload: `Internal Server Error`

Run this cURL command to reproduce this failure:

    curl -X GET -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'User-Agent: schemathesis/3.9.7' http://localhost:9060/items/101

Or add this option to your command line parameters: --hypothesis-seed=317918966440098399389263372817009257537
============================================================================================================= SUMMARY =============================================================================================================

Performed checks:
    not_a_server_error                              210 / 222 passed          FAILED
    status_code_conformance                         208 / 222 passed          FAILED
    content_type_conformance                        222 / 222 passed          PASSED
    response_headers_conformance                    222 / 222 passed          PASSED
    response_schema_conformance                     222 / 222 passed          PASSED

=================================================================================================== 3 passed, 2 failed in 4.76s ===================================================================================================

````

#### ASGI / WSGI support

The library also supports testing ASGI compatible apps like fastapi. This can be useful to test the API without having it pre-running. Let's try it out with the ``--app`` argument and the sample server.

Note that we need to add the current directory (where ``server.py`` is defined) to the PYTHONPATH.

````shell
chaos> cd /app/samples/schemathesis

chaos> PYTHONPATH=$(pwd) schemathesis run --app=server:app /openapi.json --checks all
================================================================================================= Schemathesis test session starts ================================================================================================
platform Linux -- Python 3.9.7, schemathesis-3.9.7, hypothesis-6.17.4, hypothesis_jsonschema-0.20.1, jsonschema-3.2.0
rootdir: /app/samples/schemathesis
hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('/app/samples/schemathesis/.hypothesis/examples')
Schema location: /openapi.json
Base URL: /
Specification version: Open API 3.0.2
Workers: 1
Collected API operations: 1

GET /api/{s} .                                                                                                                                                                                                               [100%]

============================================================================================================= SUMMARY =============================================================================================================

Performed checks:
    not_a_server_error                              100 / 100 passed          PASSED
    status_code_conformance                         100 / 100 passed          PASSED
    content_type_conformance                        100 / 100 passed          PASSED
    response_headers_conformance                    100 / 100 passed          PASSED
    response_schema_conformance                     100 / 100 passed          PASSED

======================================================================================================== 1 passed in 0.50s ========================================================================================================

````

The CLI can also be [extended with additional checks](https://schemathesis.readthedocs.io/en/stable/cli.html#registering-custom-checks) by defining new functions, registering them and passing a flag to the CLI.

Finally, all these features are also available through a python interface (e.g. integrate the library to existing test suites instead of using the CLI) which can make it easier to customize the testing behavior and data being generated.

Check the [docs](https://schemathesis.readthedocs.io/en/stable/python.html) for more info.

## Throughput testing

Before going to the next section, note that there are many available tools to benchmark the throughput of an API while writing very minimal code.

### [Locust](https://docs.locust.io/en/stable/)

Locust is one of these load testing tools, that we already some experience with. Let's use it to establish a baseline for the API under test:

The ``quickstart.py`` file contains a basic [locustfile](https://docs.locust.io/en/stable/writing-a-locustfile.html) with 3 tasks defined:
- one to test the root path -> GET /
- one to retrieve an item -> GET /items/55
- one to create an item with a test payload -> POST /items

We want to run the load tests:
- in headless mode (no web UI, do everything via terminal)
- against the API running at ``http://localhost:9060``
- simulate 300 users spawning all at once (spawn rate 300)
- stop the test after 10 seconds and only display the summary stats for a cleaner output

See the final command below, you can also try ``locust --help`` or check the docs for more info.

````shell
chaos> cd /app/samples/throughput

chaos> locust -f quickstart.py --host=http://localhost:9060 --headless --users 300 --spawn-rate 300 --run-time 10s --only-summary
[2021-09-05 19:09:23,529] 71c13c3ed3a0/INFO/locust.main: Run time limit set to 10 seconds
[2021-09-05 19:09:23,529] 71c13c3ed3a0/INFO/locust.main: Starting Locust 2.2.1
[2021-09-05 19:09:23,529] 71c13c3ed3a0/WARNING/locust.runners: Your selected spawn rate is very high (>100), and this is known to sometimes cause issues. Do you really need to ramp up that fast?
[2021-09-05 19:09:23,529] 71c13c3ed3a0/INFO/locust.runners: Ramping to 300 users at a rate of 300.00 per second
[2021-09-05 19:09:23,552] 71c13c3ed3a0/INFO/locust.runners: All users spawned: {"QuickstartUser": 300} (300 total users)
[2021-09-05 19:09:33,355] 71c13c3ed3a0/INFO/locust.main: --run-time limit reached. Stopping Locust
[2021-09-05 19:09:33,367] 71c13c3ed3a0/INFO/locust.main: Running teardowns...
[2021-09-05 19:09:33,367] 71c13c3ed3a0/INFO/locust.main: Shutting down (exit code 0), bye.
[2021-09-05 19:09:33,367] 71c13c3ed3a0/INFO/locust.main: Cleaning up runner...
 Name                                                                              # reqs      # fails  |     Avg     Min     Max  Median  |   req/s failures/s
----------------------------------------------------------------------------------------------------------------------------------------------------------------
 GET /                                                                                264     0(0.00%)  |      36       1     335       2  |   26.87    0.00
 POST /items                                                                          888     0(0.00%)  |      50       1     325       2  |   90.39    0.00
 GET /items/55                                                                        889     0(0.00%)  |      46       1     335       2  |   90.49    0.00
----------------------------------------------------------------------------------------------------------------------------------------------------------------
 Aggregated                                                                          2041     0(0.00%)  |      47       1     335       2  |  207.74    0.00

Response time percentiles (approximated)
 Type     Name                                                                                  50%    66%    75%    80%    90%    95%    98%    99%  99.9% 99.99%   100% # reqs
--------|--------------------------------------------------------------------------------|---------|------|------|------|------|------|------|------|------|------|------|------|
 GET      /                                                                                       2      3      3      4    310    320    330    330    340    340    340    264
 POST     /items                                                                                  2      3      3      4    310    320    320    320    330    330    330    888
 GET      /items/55                                                                               2      3      4      4    310    320    330    330    340    340    340    889
--------|--------------------------------------------------------------------------------|---------|------|------|------|------|------|------|------|------|------|------|------|
 None     Aggregated                                                                              2      3      3      4    310    320    320    330    340    340    340   2041

````

This gives us some baseline stats (for a given amount of users, spawn rate and load test duration) about the API's performance.

You can imagine how a test suite could be configured to validate that selected performance requirements are met. By integrating this to a CI workflow, we can generate reference data on demand and can easily identify how a change in the codebase affected the API's throughput performance.

This will be useful in the next section where we'll explore introducing chaos in the network, which should affect latency and produce different load test results.

## Distributed Chaos

We've focused so far on testing application errors, either by fuzzing the source code directly or at the boundaries, API endpoints.

Sometimes we are more interested in the response of a system as a whole (multiple applications), when chaos such as components becoming unavailable down or network latency is introduced.

### Chaos Mesh

Overview from the docs:
> Chaos Mesh is an open source cloud-native Chaos Engineering platform. It offers various types of fault simulation and has an enormous capability to orchestrate fault scenarios. Using Chaos Mesh, you can conveniently simulate various abnormalities that might occur in reality during the development, testing, and production environments and find potential problems in the system. To lower the threshold for a Chaos Engineering project, Chaos Mesh provides you with a perfect visualization operation. You can easily design your Chaos scenarios on the Web UI interface and monitor the status of Chaos experiments.

This framework is designed for cloud applications (typically targeting pods and nodes running in a Kubernetes cluster). It works by defining "chaos experiments" which can be seen as test scenarios during which different types of faults can be injected to parts of the system.

The library supports [multiple types](https://chaos-mesh.org/docs/basic-features/#fault-injection) (PodChaos, DNS Chaos, HTTPChaos, StressChaos, etc.). The relevant one here is [NetworkChaos](https://chaos-mesh.org/docs/simulate-network-chaos-on-kubernetes/).

TODO (try using Openshift environment):
- ``samples/chaosmesh/network-delay.yaml`` defines the experiment: introduce 40ms network latency for requests targeting pods with label ``app=target-api``
- deploy the api in a cluster (from the chaosdev Dockerfile)
- install chaosmesh in the same cluster, e.g. using [helm chart](https://chaos-mesh.org/docs/production-installation-using-helm/)
- run the experiment above, refer to https://chaos-mesh.org/docs/run-a-chaos-experiment/
- run locust tests against the target-api (may need to deploy another pod with locust installed), then compare to baseline results
- stop chaos experiment by deleting the created resources
- document findings
