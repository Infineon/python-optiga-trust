# Testing

This project uses [pytest](https://pytest.org) as test framework. Additionally, [oscrypto](https://pypi.org/project/oscrypto/) is used to validate signatures in the tests.

Please install all requirements for testing as follows.

```bash
python -m pip install -r tests/requirements.txt
```

## Running tests

The tests can be run centrally from the root folder with the following command.
```bash
python -m pytest
```

Additionally, a coverage report can be generated as follows.
```bash
python -m pytest --cov --cov-report term --cov-report xml:coverage.xml
```


If only certain tests shall be run, this can be done by specifying the test file.
```bash
python -m pytest ./tests/test_rand.py
```

## Windows setup

To run the tests in this folder on Windows, OpenSSL 3.x.x and [oscrypto](https://github.com/wbond/oscrypto) has to be installed and configured.

### Installing OpenSSL

Please install OpenSSL from [Win32OpenSSL](https://slproweb.com/products/Win32OpenSSL.html).

### Installing oscrypto

Currently, oscrypto has some issues in combination with OpenSSL v3.x.x. There is no new release containing the bugfix, and thus it has to be installed directly via the commit on GitHub. See more in the related [issue](https://github.com/wbond/oscrypto/issues/78).

```bash
python -m pip install git+https://github.com/wbond/oscrypto.git@1547f535001ba568b239b8797465536759c742a3
```
NOTE: This is only needed on Windows systems. On Linux, the official release of oscrypto can be used. It is part of [tests/requirements.txt](requirements.txt)
