


# Using Docker 


````shell

docker build -t chaosdev . 

docker run -it -v ${PWD}:/app/ chaosdev bash

````

## Samples

After starting the container run ``cd /app/samples/`` to change into the directory, then into the relevant sub-directory. 

## atheris_only

**Test**: Using atheris to find bugs in a function that performs calculations. 

> Note that ``print()`` usage in functions can help debug but considerably slows down the fuzzing and should be disabled for longer runs. 

### First test

Run the fuzzer with ``python atheris_test.py``. A bug is quickly found:
````text
a. -4342 + -4342 = -8684

 === Uncaught Python exception: ===
ValueError: math domain error
Traceback (most recent call last):
  File "/app/samples/atheris_test.py", line 53, in fuzzy_testing
    get_sum_then_square_root(*args)
  File "/app/samples/atheris_test.py", line 31, in get_sum_then_square_root
    result = sqrt(add)

==18== ERROR: libFuzzer: fuzz target exited

````
There is no protection against ``sqrt(x)`` when x is negative in the function, hence this bug. Note that crash files are created with the bytes that generated a failure.

### Second test

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

### Third test

Let's add another patch to return the infinite value in this case. You can un-comment the print statements to see the values generated but the test will run a lot slower. 

``python atheris_3.py``

This will run indefinitely (until a bug is found) with the current setup. We can add a stopping condition with a command line flag - atheris uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html#options) under the hood and all its options are available.

In this case we just want to fuzz for 60s max, we can use the `max_total_time` flag.  

Resulting command: ``python atheris_3.py -max_total_time=60`` (try `-help=1` to see all options)

Output
````text
root@da5ac4629f08:/app/samples/atheris_only# python atheris_3.py -max_total_time=60
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

### string text

One final test to see how well the coverage-guided fuzzing adapts to find bugs.

You can run ``python atheris_str.py`` and see how it very quickly finds the 'kiRbY' input that triggers the function to crash.

````text
root@da5ac4629f08:/app/samples/atheris_only# python atheris_str.py
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

## hypothesis

**Test**: Using [hypothesis](https://hypothesis.readthedocs.io/) to find bugs by running tests with generated values following given strategies. 

- Testing the same `get_sum_then_square_root` as previously, feeding it generated integers
- Also testing the ``not_kirby`` function that crashes if the input starts with `kiRbY`

These functions are written in a separate file for reuse: ``functions.py``

Since hypothesis integrates with pytest we can run all the ``test_xxx`` tests at once and catch all the failures. 

### First run

``pytest hypothesis_test.py``

````text
root@da5ac4629f08:/app/samples/hypothesis# pytest hypothesis_test.py
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

### Second run (bugfix)

Un-comment the 2 lines in ``functions.py`` to fix the negative sum error 
````text
def get_sum_then_square_root(x, y):  
    # --- Uncomment this block to fix the error hypothesis detects ---
    if add < 0:
        return None

````

Re-run the tests and they should all be passing now.
````text
root@da5ac4629f08:/app/samples/hypothesis# pytest hypothesis_test.py
======================================================================================================= test session starts =======================================================================================================
platform linux -- Python 3.9.2, pytest-6.2.4, py-1.10.0, pluggy-0.13.1
rootdir: /app/samples/hypothesis
plugins: hypothesis-6.17.1
collected 2 items                                                                                                                                                                                                                 

hypothesis_test.py ..                                                                                                                                                                                                       [100%]

======================================================================================================== 2 passed in 2.33s ========================================================================================================
````

### Automatically generating tests

Hypothesis has a [ghostwriting feature](https://hypothesis.readthedocs.io/en/latest/ghostwriter.html) that will automatically generate tests given some source code.

To generate code from the ``functions.py`` source file for example:
````shell
root@da5ac4629f08:/app# cd samples/hypothesis/

root@da5ac4629f08:/app/samples/hypothesis# hypothesis write functions
`````

An example output is saved in ``generated_test.py``. Note that not all the generated functions are useful/needed, this is still an approximation and there are multiple flags/functions to generate the tests - check docs for details.


## Combining hypothesis & atheris

Atheris seems to be more powerful, as it's tracking code coverage and trying to generate inputs to cover more code. It was able to find bugs that hypothesis couldn't. The interface is cumbersome however, as it simply generates bytes which usually have to be hand-converted to another data type.

Hypothesis gives a very powerful and readable interface to define strategies, combine them, and create complex test scenarios with very little code. 

Luckily hypothesis can [integrate with external fuzzers](https://hypothesis.readthedocs.io/en/latest/details.html#use-with-external-fuzzers), atheris being one of them.

Check the ``/samples/combined/`` directory for a practical example.

````shell
# run the sample combining both
root@da5ac4629f08:/app/samples/combined# python ht_fuzz_test.py

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

However even after letting it run for a while it's not finding the bad input. For comparison purposes the relevant 'atheris only' test (see ``fuzz_only.py``) finds the bad input within the few first seconds.

This (along with this [discussion](https://github.com/google/atheris/issues/20) and [commit](https://github.com/google/atheris/commit/ee02c830f620fb085fb0260f6a8747fe15d21fbd) on the atheris repo) seem to indicate they don't work that well together, and for coverage guided fuzzing using atheris provides better results.

