#Fails due to inability to adjust to daylight saving

from pathlib import Path
import os
import time
from SymmetricEncrypt import encrypt, decrypt, createKey
from ctypes import windll, wintypes, byref



def modCTime(filepath, epoch):
    # Convert Unix timestamp to Windows FileTime using some magic numbers
    # See documentation: https://support.microsoft.com/en-us/help/167296
    timestamp = int((epoch * 10000000) + 116444736000000000)
    ctime = wintypes.FILETIME(timestamp & 0xFFFFFFFF, timestamp >> 32)

    # Call Win32 API to modify the file creation date
    handle = windll.kernel32.CreateFileW(filepath, 256, 0, None, 3, 128, None)
    windll.kernel32.SetFileTime(handle, byref(ctime), None, None)
    windll.kernel32.CloseHandle(handle)


path = "out\u2009"
phile = Path(path)

if not phile.exists():
    print("error file tampering detected")
    input("")
    exit()

try:
    a = phile.stat().st_ctime
    m = phile.stat().st_mtime

    f = open(phile, 'rb')
    txt = f.read()
    f.close()

    key = createKey(str(a*m))
    msg = decrypt(key, txt)
    del key
    print(msg)
    msg = str(int(msg) - 1)
    
    m = time.time()
    modCTime(path, a + 0.00002)
    a = phile.stat().st_ctime

    key = createKey(str(a*m))
    msg = encrypt(key,msg)
    del key
    f = open(phile, 'wb')
    f.write(msg)
    f.close()
    os.utime(path,(m,m))
        

except:
    print("error file tampering detected")

input("")