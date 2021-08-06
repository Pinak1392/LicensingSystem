from uuid import uuid4
from datetime import date, datetime
import inspect

def funcValidParam(func, **kwargs):
    sig = inspect.signature(func)
    paramset = {i for i in sig.parameters}
    inParams = set(kwargs)
    return {i:kwargs[i] for i in (paramset&inParams)}, {i:kwargs[i] for i in (inParams-paramset)}

def createDateTime(dateStr):
    format_string = '%Y-%m-%d'
    datetime_object = datetime.strptime(dateStr, format_string).date()
    return datetime_object

def createUUID():
    return str(uuid4())

def today():
    return str(date.today())