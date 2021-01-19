optigatrust.core API Documentation

The module provides generic access to your Hardware Security Module over available interface. 


 - [`init()`](#init-function)
 - [`random()`](#random-function)
 - [Class `Object`](#object-class)
     - [`read()`](#read-function)
     - [`write()`](#write-function)
     - [`read_raw_meta()`](#read_raw_meta-function)
     - [`write_raw_meta()`](#write_raw_meta-function)


### `init()` function

```python
def init():
    """
    This function either initialises non-initialised communication channel between the chip and the application, or
    returns an existing communication
    ONLY ONE Optiga Instance is supported
    
    :param None:
    
    :raises:
        OSError: If some problems occured during the initialisation of the library or the chip
        
    :return:
        a CDLL Instance
    """
```

### `random()` function

```python
def random(n, trng=True):
    """
    This function generates a random number

    :param n:
        how much randomness to generate. Valid values are from 8 to 256

    :param trng:
        If True the a True Random Generator will be used, otherwise Deterministic Random Number Generator

    :raises:
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
        Bytes object with randomness
    """
```

### `Object()` Class

```python
class Object:
    """
    A class used to represent an Object on the OPTIGA Trust Chip

    :ivar meta: a dictionary of the metadata present right now on the chip for the given object. It is writable,
    so user can update the metadata assigning the value to it
    :vartype meta: dict

    :ivar id: the id of the object; e.g. 0xe0e0
    :vartype id: int

    :ivar optiga: the instance of the OPTIGA handler used internally by the Object class
    :vartype optiga: core.Descriptor

    :ivar updated: this boolean variable notifies whether metadata or data has been updated and this can bu used to
    notify other modules to reread data if needed
    :vartype updated: bool
    """
    
    def __init__(self, _id):
        """
        This class

        :param _id:
            an Object ID which you would like to initialise; e.g. 0xe0e0

        return:
            self
        """
```

### `read()` function

```python
def read(self, offset=0, force=False):
    """
    This function helps to read the data stored on the chip

    :param offset:
        An optional parameter defining whether you want to read the data with offset

    :param force:
        This is a parameter which can be used to try to read the data even if id can't be somehow finden

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
        bytearray with the data
    """
```

### `write()` function

```python
def write(self, data, offset=0):
    """
    This function helps to write the data onto the chip

    :param data:
        Data to write, should be either bytes of bytearray

    :param offset:
        An optional parameter defining whether you want to read the data with offset

    :raises
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library
    """
```


### `read_raw_meta()` function

```python
def read_raw_meta(self) -> bytearray:
    """
    This function helps to read the metadata associated with the data object stored on the chip

    :raises:
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :returns:
        bytearray with the data
    """
```

### `write_raw_meta()` function

```python
def write_raw_meta(self, data):
    """
    This function helps to write the metadata associated with the data object stored on the chip

    :param data:
        Data to write, should be bytearray

    :param data_id:
        An ID of the Object (e.g. 0xe0e1)

    :raises
        ValueError - when any of the parameters contain an invalid value
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library
    """
```

