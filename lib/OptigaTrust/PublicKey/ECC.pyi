from typing import Optional
from OptigaTrust.Util.Defines import *

def generate(curve: Optional[str] = ["nistp384", "nistp256"],
             usage: Optional[str] = ["auth,sign,agreement"],
             keyid: Optional[KeyId] = [KeyId.USER_PRIVKEY_1,
                                       KeyId.USER_PRIVKEY_2,
                                       KeyId.USER_PRIVKEY_3,
                                       KeyId.USER_PRIVKEY_4]
             ) -> bytes: ...