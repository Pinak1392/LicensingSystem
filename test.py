from dateutil.relativedelta import relativedelta
import inspect

def funcValidParam(func, **kwargs):
    sig = inspect.signature(func)
    paramset = {i for i in sig.parameters}
    inParams = set(kwargs)
    return {i:kwargs[i] for i in (paramset&inParams)}, {i:kwargs[i] for i in (inParams-paramset)}

dic = {"years":1,"days":2,"leof":4}

print(funcValidParam(relativedelta,**dic))
