[[_TOC_]]
# Hackathon Submission Document

Please answer the following 3 questions with information about your project. When people are voting for your project from September 6th - 10th, this form will be a quick view of what your project is about.

## 1. What problem is your hackathon trying to solve and how does it relate to hackathon theme of ‘improving customer experience’?

Software bugs/faults are often caused by edge cases, untested scenarios or code paths that no one thought of or tested against, often because of the associated cost vs likelihood.

This project is about exploring chaos engineering tools and techniques, and how to use them to more thoroughly test written software by adding a randomness element to the test cases, ideally without having to write too much extra code.

The customer experience is directly impacted by the quality of the software developed/maintained internally, and one way to improve robustness is to prepare for and experiment as much chaos as possible during development (as opposed to reacting to a customer issue or production outage).


## 2. What technology (both hardware and software) did your team use to accomplish your goal?

- Python 3.9
- [Atheris](https://github.com/google/atheris)
- [Hypothesis](https://hypothesis.readthedocs.io/)
- Openshift
- [Docker](https://www.docker.com)


## 3. What did your team learn from participating in this hackathon?

- TBD

----

# Project ReadMe
Filling in this section is completely up to you, let readers know about the technical details of your project!

## What is Chaos Engineering?

It can be defined as the principle of testing software's ability to handle unexpected conditions (chaos). This includes connectivity issues, servers going down, unexpected user input and other common factors of bugs and outages.

The goal is to introduce "chaos" into the system, see how it reacts, and correct it if needed. This is useful as there is only so much a developer can think of when testing their code (computers are pretty good at this), and often issues are only found after deployment. By introducing more variability during development and testing, these issues can be found sooner.

[Chaos engineering](https://en.wikipedia.org/wiki/Chaos_engineering) is a [deep](https://www.oreilly.com/library/view/chaos-engineering/9781491988459/) topic and there are many books, techniques, tools about it and ways to implement them.

To set an initial scope, we are interested on the following ways of introducing chaos - ideally applicable to python projects:

- At the application level: negative testing of an application through fuzzing (randomized input to methods/functions, entry points, api endpoints, etc.)
- At the "service" layer, in a distributed system: regularly testing throughput, introducing network failures, latency, unavailability of components, etc.

One sub-category of chaos engineering is Fuzz Testing, which is what we chose to focus on for this hackathon.

## Fuzz Testing

Also known as fuzzing, this is automated software testing that uses *randomly* generated data to try and break code. Typically, when writing test cases a developer will provide their own data, aiming to cover as many scenarios as possible. But, writing tests this way means that there are always values that are not covered. Instead of using fixed data, fuzzing tools will randomly generate new values and see if they can generate unhandled errors.

Fuzzing by itself can also be a complex topic (see the [fuzzing book](https://www.fuzzingbook.org/)). Some general notes:

- Fuzzers typically generate raw bytes, and often provide an interface to get that data in a specific type (integer, string, bool, etc.)
- The goal may be to find inputs that cause crashes/exceptions, or to validate specific software behavior (e.g. using assertions and writing test-suites that consume the generated data)
- Coverage-guided fuzzing implies some monitoring of the code coverage while the tests are running. That information is used to guide the data generation, which usually results in more efficient testing. Issues are also more likely to be found as the tools try to cover as many code paths as possible.
- Replay: failures found during fuzzing can be saved and reused/replayed at a later time (e.g. for regression testing, ).
- Minimize: some fuzzers after finding a failing input will try to reproduce it while 'reducing' the input, in order to provide the smallest, simplest way to reproduce the issue.

The fuzzing libraries that were explored are described below - high level summaries.

The technical details are documented in [USAGE.md](USAGE.md), along with [sample code](/samples) to follow along.

----

### Atheris

> **Documentation**: https://github.com/google/atheris

Atheris is a Python fuzzing engine that uses code coverage when generating its test data. It's not
simply generating random values for testing, but is instead adapting the values provided based on how far they reach
into the functions being tested. This way, it can find issues much faster and more thoroughly than with random values.

For example, if we use atheris to perform fuzzing of the following function (found in `atheris_str.py`):
````python
def not_kirby(s: str):
    if len(s) < 5:
        return True

    if s[0] == "k":
        if s[1] == "i":
            if s[2] == "R":
                if s[3] == "b":
                    if s[4] == "Y":
                        raise ValueError(f"{s} is not accepted by this function.")

    return True
````

Then we get the following output (truncated):
````text
#2      INITED cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 31Mb
#272    NEW    cov: 5 ft: 5 corp: 2/7b lim: 6 exec/s: 0 rss: 31Mb L: 6/6 MS: 5 ShuffleBytes-CopyPart-ChangeBinInt-InsertRepeatedBytes-CrossOver-
#2790   NEW    cov: 6 ft: 6 corp: 3/27b lim: 29 exec/s: 0 rss: 31Mb L: 20/20 MS: 3 ChangeBinInt-InsertByte-InsertRepeatedBytes-
#2814   REDUCE cov: 6 ft: 6 corp: 3/22b lim: 29 exec/s: 0 rss: 31Mb L: 15/15 MS: 4 ChangeBinInt-ShuffleBytes-ChangeBinInt-EraseBytes-
#2860   REDUCE cov: 6 ft: 6 corp: 3/20b lim: 29 exec/s: 0 rss: 31Mb L: 13/13 MS: 1 EraseBytes-
#2891   REDUCE cov: 6 ft: 6 corp: 3/17b lim: 29 exec/s: 0 rss: 31Mb L: 10/10 MS: 1 EraseBytes-
#3062   REDUCE cov: 6 ft: 6 corp: 3/15b lim: 29 exec/s: 0 rss: 31Mb L: 8/8 MS: 1 EraseBytes-
#3219   REDUCE cov: 6 ft: 6 corp: 3/14b lim: 29 exec/s: 0 rss: 31Mb L: 7/7 MS: 2 ChangeBit-EraseBytes-
#3542   REDUCE cov: 6 ft: 6 corp: 3/13b lim: 29 exec/s: 0 rss: 31Mb L: 6/6 MS: 3 ChangeByte-ChangeASCIIInt-EraseBytes-
#4272   REDUCE cov: 7 ft: 7 corp: 4/20b lim: 33 exec/s: 0 rss: 31Mb L: 7/7 MS: 5 ChangeASCIIInt-ChangeByte-ChangeASCIIInt-InsertByte-ChangeBit-
#4881   REDUCE cov: 7 ft: 7 corp: 4/19b lim: 38 exec/s: 0 rss: 31Mb L: 6/6 MS: 4 ShuffleBytes-InsertByte-ChangeBit-EraseBytes-
#29442  REDUCE cov: 8 ft: 8 corp: 5/25b lim: 277 exec/s: 0 rss: 31Mb L: 6/6 MS: 1 ChangeByte-
#33395  NEW    cov: 9 ft: 9 corp: 6/55b lim: 309 exec/s: 0 rss: 31Mb L: 30/30 MS: 3 CrossOver-ChangeBit-InsertRepeatedBytes-
#33521  REDUCE cov: 9 ft: 9 corp: 6/49b lim: 309 exec/s: 0 rss: 31Mb L: 24/24 MS: 1 EraseBytes-
#33577  REDUCE cov: 9 ft: 9 corp: 6/48b lim: 309 exec/s: 0 rss: 31Mb L: 23/23 MS: 1 EraseBytes-
#33714  REDUCE cov: 9 ft: 9 corp: 6/40b lim: 309 exec/s: 0 rss: 31Mb L: 15/15 MS: 2 ChangeBit-EraseBytes-
#33775  REDUCE cov: 9 ft: 9 corp: 6/37b lim: 309 exec/s: 0 rss: 31Mb L: 12/12 MS: 1 EraseBytes-
#34551  REDUCE cov: 9 ft: 9 corp: 6/32b lim: 309 exec/s: 0 rss: 31Mb L: 7/7 MS: 1 EraseBytes-
#35509  REDUCE cov: 9 ft: 9 corp: 6/31b lim: 317 exec/s: 0 rss: 31Mb L: 6/6 MS: 3 ShuffleBytes-ChangeBit-EraseBytes-

 === Uncaught Python exception: ===
ValueError: kiRbY
 is not accepted by this function.
Traceback (most recent call last):
  File "/app/samples/atheris_only/atheris_str.py", line 27, in test_one_input
    not_kirby(random_str)
  File "/app/samples/atheris_only/atheris_str.py", line 18, in not_kirby
    raise ValueError(f"{s} is not accepted by this function.")
````

We can see that atheris successfully found a string that was not accepted by the function. This would have been
incredibly difficult with random test values alone, and it may have taken *many* iterations before the program happened to
pick the string "kiRbY". But, because the test coverage is being used, atheris can determine that having the input start
 with "k", then "i", then "R" etc. caused the test to go deeper within the code and continued to try values containing
these characters until it found an error.

A few notes about the output:
- `NEW`: means that atheris found a value that went further into the code than before
- `REDUCE`: means that atheris found a simpler value that can reach the same depth as previous attempts
- `pulse`: atheris will produce pulse messages every once in a while to indicate that it is still working


### Hypothesis

> **Documentation:** https://hypothesis.readthedocs.io/en/latest/

Hypothesis is a python library for property-based testing, used to create better unit tests with fuzzing and strategies instead of fixed specific values. As such, it handles generating data for the tests, and covers a large number of scenarios, in addition to typical testing.

For example, let's say we want to test the function below (found in `samples/hypothesis/functions.py`):
````python`
def get_sum_then_square_root(x: int, y: int):
    add = x + y

    # --- Uncomment this block to fix the error hypothesis detects ---
    # if add < 0:
    #     return None

    result = math.sqrt(add)
    return result
````

We want to make sure this function works with any combinations of integers. Writing that is very easy using the library:
````python
from hypothesis import given, strategies as st
from math import sqrt

@given(x=st.integers(), y=st.integers())
def test_sum_then_square_root(x: int, y: int):
    test_sum = x + y
    if test_sum < 0:
        assert get_sum_then_square_root(x, y) is None
    else:
        assert get_sum_then_square_root(x, y) == sqrt(test_sum)

````

There are many different strategies to generate any kind of data (from primary types to user-defined models) and they can be composed together - even recursively - to create very flexible and complex test scenarios. An example would be generating random data that's still conformant to an API schema or model/class, then use that to test functionality. Check docs for more info.

If we run the previous test we can see a failure and the following towards the end of the output log:
````text
Falsifying example: test_sum_then_square_root(
    x=0, y=-1,
)
````

Here, while randomly generating values, Hypothesis found that assigning a negative value causes an unhandled error in the function. It then continued to generate values until it found the most simple ones to generate the same error, hence the output containing `x=0, y=-1`.

While this library does not use code coverage like Atheris (and can't find the error in the `not_kirby` function for example), it has its own advantages as well:
- The API is very nice and makes it easy to write complex scenarios with little code. See all the [available strategies](https://hypothesis.readthedocs.io/en/latest/data.html)
- It integrates with pytest, and can be easily added to existing test suites and run in CI
- It can be used in combination with [external fuzzers](https://hypothesis.readthedocs.io/en/latest/details.html?highlight=fuzz#use-with-external-fuzzers), including atheris.
- It can [ghostwrite tests](https://hypothesis.readthedocs.io/en/latest/ghostwriter.html) - generate tests automatically for given python code. An example is provided in the samples.


### APIFuzzer

> **Documentation**: https://github.com/KissPeter/APIFuzzer

APIFuzzer is another python fuzzing tool that can be invoked from the CLI. It reads an API description (Swagger, OpenAPI schemas) and step by step fuzzes the fields to validate if the application can cope with the fuzzed parameters.

*Pro*: It is very easy to install and run against a deployed server, and should be a low-effort addition to any CI workflow.

*Con*: It's not the most flexible however, as there are not many ways to configure and tailor the data generation to an app's specific needs, unlike the other libraries.

### Schemathesis

> **Documentation**: https://schemathesis.readthedocs.io/en/stable/index.html

Schemathesis is an API testing tool for web applications built with Open API and GraphQL specifications.

It is built on top of Hypothesis and will read the API schema then generate and run test cases (using the strategies under the hood).

This [very good article](https://testdriven.io/blog/fastapi-hypothesis/) goes on detail about using hypothesis and schemathesis to test a fastapi based application, for reference.

There are 2 main ways to use it (see [FAQ](https://schemathesis.readthedocs.io/en/stable/faq.html)):
- Via a CLI interface (install via pip or using the provided docker image). Simplest for basic cases and will work with APIs in any language, as long as they expose a Swagger/OpenAPI spec.
- Via the python interface, by integrating the library to existing python code. This makes it a bit easier to configure the behavior and test apps written in python without requiring the API to be running already. There is support for ASGI (e.g. fastapi) and WSGI (e.g. Flask) apps as well.

Check out [CONTRIBUTING.md](USAGE.md) for more details on features and usage.

## Additional references

- [Awesome python resources for testing and generating test data](https://githubmemory.com/repo/cleder/awesome-python-testing)
- [Comparing Chaos Engineering Tools for Kubernetes Workloads](https://blog.container-solutions.com/comparing-chaos-engineering-tools)
- [OSS-Fuzz: Continuous Fuzzing for Open Source Software](https://google.github.io/oss-fuzz/)
- [Chaos Mesh - Orchestrate chaos experiments in Kubernetes](https://chaos-mesh.org/)
- [Chaos Toolkit - An Open API for Chaos Engineering](https://github.com/chaostoolkit/chaostoolkit)
- [Chaos Monkey - Netflix's resiliency test tool](https://netflix.github.io/chaosmonkey/)
- [Litmus Chaos - Another chaos orchestrator](https://litmuschaos.io)
