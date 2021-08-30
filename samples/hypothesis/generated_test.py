# This test code was written by the `hypothesis.extra.ghostwriter` module
# and is provided under the Creative Commons Zero public domain dedication.

import functions
from hypothesis import given, strategies as st

get_sum_then_square_root_operands = st.integers()


@given(
    a=get_sum_then_square_root_operands,
    b=get_sum_then_square_root_operands,
    c=get_sum_then_square_root_operands,
)
def test_associative_binary_operation_get_sum_then_square_root(a, b, c):
    left = functions.get_sum_then_square_root(
        x=a, y=functions.get_sum_then_square_root(x=b, y=c)
    )
    right = functions.get_sum_then_square_root(
        x=functions.get_sum_then_square_root(x=a, y=b), y=c
    )
    assert left == right, (left, right)


@given(a=get_sum_then_square_root_operands, b=get_sum_then_square_root_operands)
def test_commutative_binary_operation_get_sum_then_square_root(a, b):
    left = functions.get_sum_then_square_root(x=a, y=b)
    right = functions.get_sum_then_square_root(x=b, y=a)
    assert left == right, (left, right)


@given(a=get_sum_then_square_root_operands)
def test_identity_binary_operation_get_sum_then_square_root(a):
    assert a == functions.get_sum_then_square_root(x=a, y=0)


@given(s=st.text())
def test_fuzz_not_kirby(s):
    functions.not_kirby(s=s)
