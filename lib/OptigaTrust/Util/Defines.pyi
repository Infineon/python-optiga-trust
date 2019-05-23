from typing import NamedTuple
from enum import Enum

class Rng(Enum): ...

class Curves(Enum): ...

class KeyUsage(Enum): ...

class ObjectId(Enum): ...

class KeyId(Enum):
	def has_value(cls, value: object) -> bool: ...

UID = NamedTuple("UID",[('cim_id', int),
						('platform_id', int),
						('model_id', int),
						('rommask_id', int),
						('chip_type', int),
						('batch_num', int),
						('x_coord', int),
						('y_coord', int),
						('fw_id', int),
						('fw_build', int)
						])