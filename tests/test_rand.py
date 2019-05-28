import pytest
from optigatrust.rand import get_random_bytes


@pytest.mark.parametrize("n", [
	0, 1, 2, 3, 4, 5, 6, 7
])
def test_rand_undervalue(n):
	random = get_random_bytes(n)
	assert isinstance(random, bytes) and len(random) == 0


@pytest.mark.parametrize("n", [
	8, 9, 15, 31, 33, 64, 128, 129, 255, 256
])
def test_rand_normalrange(n):
	random = get_random_bytes(n)
	assert isinstance(random, bytes) and len(random) == n


@pytest.mark.parametrize("n", [
	257, 1000, 1024, 2048
])
def test_rand_overflow(n):
	random = get_random_bytes(n)
	assert isinstance(random, bytes) and len(random) == 0
