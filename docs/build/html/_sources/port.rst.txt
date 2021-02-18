Export or Import Chip (Meta)Data
================================

Example
-------

::

    from optigatrust import port
    import json

    dump = port.to_json()
    json.dumps(dump, indent=4)

API
---


.. automodule:: optigatrust.port
   :members: to_json, from_json, to_otc