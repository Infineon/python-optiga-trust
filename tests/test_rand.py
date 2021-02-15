import pytest
from optigatrust import crypto


@pytest.mark.parametrize("n", [
	0, 1, 2, 3, 4, 5, 6, 7
])
def test_rand_undervalue(n):
	_random = crypto.random(n)
	assert isinstance(_random, bytes) and len(_random) == 0


@pytest.mark.parametrize("n", [
	8, 9, 15, 31, 33, 64, 128, 129, 255, 256
])
def test_rand_normalrange(n):
	_random = crypto.random(n)
	assert isinstance(_random, bytes) and len(_random) == n


@pytest.mark.parametrize("n", [
	257, 1000, 1024, 2048
])
def test_rand_overflow(n):
	_random = crypto.random(n)
	assert isinstance(_random, bytes) and len(_random) == 0
