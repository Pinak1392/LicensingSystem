from uuid import uuid4
from datetime import date, datetime
import inspect
from SymmetricEncrypt import *

#Seperate useable arguments from non useable ones
def funcValidParam(func, **kwargs):
    sig = inspect.signature(func)
    paramset = {i for i in sig.parameters}
    inParams = set(kwargs)
    return {i:kwargs[i] for i in (paramset&inParams)}, {i:kwargs[i] for i in (inParams-paramset)}

#Creates a string out of a datetime object (was made for when I used sqlite3 as my db, is still used to work with the old code)
def createDateTime(dateStr):
    format_string = '%Y-%m-%d'
    datetime_object = datetime.strptime(dateStr, format_string).date()
    return datetime_object

#The below functions exist so they can be easily place in the database default statements (Can be replaced with lambda)
#Creates uuid
def createUUID():
    return str(uuid4())

#Simple function to create a string version of todays date
def today():
    return str(date.today())