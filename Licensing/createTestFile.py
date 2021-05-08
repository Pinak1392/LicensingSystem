from pathlib import Path
import os
from SymmetricEncrypt import encrypt, createKey

path = "out\u2009"

f = open("out\u2009", 'wb')
f.close()
phile = Path(path)

a = phile.stat().st_ctime
m = phile.stat().st_mtime

key = createKey(str(a*m))
msg = encrypt(key,"1000")
del key
f = open("out\u2009", 'wb')
f.write(msg)
f.close()
os.utime(path,(m,m))