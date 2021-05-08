import matplotlib.pyplot as plt
import time

n = 100000000
sieve = [2]

for i in range(3,n,2):
    t = True
    for a in sieve:
        if a > i**(1/2):
            break
        if i%a == 0:
            t = False
            break
    
    if t:
        sieve.append(i)

