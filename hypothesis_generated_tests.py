# This test code was written by the `hypothesis.extra.ghostwriter` module
# and is provided under the Creative Commons Zero public domain dedication.

import hypothesis_test
from hypothesis import given, strategies as st, settings

get_sum_then_square_root_operands = st.integers()


@given(
    a=get_sum_then_square_root_operands,
    b=get_sum_then_square_root_operands,
    c=get_sum_then_square_root_operands,
)
def test_associative_binary_operation_get_sum_then_square_root(a, b, c):
    left = hypothesis_test.get_sum_then_square_root(
        x=a, y=hypothesis_test.get_sum_then_square_root(x=b, y=c)
    )
    right = hypothesis_test.get_sum_then_square_root(
        x=hypothesis_test.get_sum_then_square_root(x=a, y=b), y=c
    )
    assert left == right, (left, right)


@given(a=get_sum_then_square_root_operands, b=get_sum_then_square_root_operands)
def test_commutative_binary_operation_get_sum_then_square_root(a, b):
    left = hypothesis_test.get_sum_then_square_root(x=a, y=b)
    right = hypothesis_test.get_sum_then_square_root(x=b, y=a)
    assert left == right, (left, right)


@given(a=get_sum_then_square_root_operands)
def test_identity_binary_operation_get_sum_then_square_root(a):
    assert a == hypothesis_test.get_sum_then_square_root(x=a, y=0)


@given(s=st.text())
@settings(max_examples=1000)
def test_fuzz_not_kirby(s):
    hypothesis_test.not_kirby(s=s)
