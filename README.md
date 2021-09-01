[[_TOC_]]
# Hackathon Submission Document

Please answer the following 3 questions with information about your project. When people are voting for your project from September 6th - 10th, this form will be a quick view of what your project is about.

## 1. What problem is your hackathon trying to solve and how does it relate to hackathon theme of ‘improving customer experience’?

Software bugs/faults are often caused by edge cases, untested scenarios or code paths that no one thought of or tested against, often because of the associated cost vs likelihood.

This project is about exploring chaos engineering (testing) techniques, and how to use them to more thoroughly test written software by adding a randomness element to the test cases, ideally without having to write too much extra code.

The customer experience is directly impacted by the quality of the software developed/maintained internally, and one way to improve robustness is to prepare for and experiment as much chaos as possible during development (as opposed to reacting to a customer issue or production outage).


## 2. What technology (both hardware and software) did your team use to accomplish your goal?

- Python
- [Atheris](https://github.com/google/atheris)
- [Hypothesis](https://hypothesis.readthedocs.io/)
- Openshift




## 3. What did your team learn from participating in this hackathon?

- TBD



# Project ReadMe
Filling in this section is completely up to you, let readers know about the technical details of your project!

## Atheris
Documentation: https://github.com/google/atheris

Atheris is a Python fuzzing engine that uses code coverage when generating its test data. By doing this, it is not
simply generating random values for testing, but is instead adapting the values provided based on how far they reach
into the functions being tested. This way, it can find issues much faster and more thoroughly than with random values.

For example, if we use atheris to perform fuzzing on the following function (found in `atheris_str.py`):
```
def not_kirby(s: str):
    if len(s) < 5:
        return True

    if s[0] == "k":
        if s[1] == "i":
            if s[2] == "R":
                if s[3] == "b":
                    if s[4] == "Y":
                        raise ValueError(f"{s} is not accepted by this function.")

    return
```

Then we get the following output:
```
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
```

We can see that atheris successfully found a string that was not accepted by the function. This would have been
incredibly difficult with random values alone, since it may have taken many iterations before the program happened to
pick the string "kirby". But, because the test coverage is being used, atheris can determine that having the input start
 with "k", then "i", then "r" etc. caused the test to go deeper within the code and continued to try values containing
these characters until it reached the error.

A few notes about the output:
- `NEW`: means that atheris found a value that went further into the code than before
- `REDUCE`: means that atheris found a simpler value that can reach the same depth as previous attempts
- `pulse`: atheris will produce pulse messages every once in a while to indicate that it is still working
