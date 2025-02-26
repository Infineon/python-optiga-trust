# Testing

This project uses [pytest](https://pytest.org) as test framework. 

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

## Configuring OPTIGA™ Trust M v3 samples for tests

The tests in this folder require a certain configuration of the OPTIGA™ Trust M v3 sample under test. Thus, please prepare your samples (once), to manually set the data and metadata of the OPTIGA™ Trust M v3 sample using the following command in order to ensure the tests run correctly.

```bash 
optigatrust object --in ./tests/fixtures/optiga_trust_m_v3_test_configuration.json
```