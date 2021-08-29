from flask_sqlalchemy import SQLAlchemy
from functions import *
from dateutil.relativedelta import relativedelta

db = SQLAlchemy()

#Models
#The user table for the database
class User(db.Model):
    #Parameters
    id = db.Column(db.Integer, nullable=False, unique=True, primary_key=True)
    email = db.Column(db.String(40), nullable=False, unique=True)
    phoneNo = db.Column(db.String(12), nullable=False, unique=True)
    password = db.Column(db.LargeBinary(), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    #Authenticated is true if a user is logged in
    authenticated = db.Column(db.Boolean, default=False)
    #A user is inactive if they haven't been verified
    active = db.Column(db.Boolean, default=False)
    #One time use userkey used for email verification and other one time access purposes
    userKey = db.Column(db.String(80), default=createUUID, nullable=False)
    #The user pickling key
    pickleKey = db.Column(db.String(80), default=createUUID, nullable=False)
    #Admin values
    admin = db.Column(db.Boolean, default=False)
    superadmin = db.Column(db.Boolean, default=False)
    #Stores the licenses for a user
    licenses = db.relationship('License', backref='owner', cascade="all, delete-orphan")

    def addLicense(self, amount, **kwargs):
        newLicense = License(owner = self, **kwargs)
        newLicense.addKey(amount)
        db.session.commit()
        #Return license registration key
        return newLicense.getKey

    #Reset userkey
    def generateNewToken(self):
        self.userKey = createUUID()

    def is_active(self):
        return self.active

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return self.authenticated

    def is_anonymous(self):
        return False


#License table
class License(db.Model):
    #Dates are set as strings due to the system originally being on sqlite3 (I need to change this)
    creationDate = db.Column(db.String(10), default=today, nullable=False)
    expiryDate = db.Column(db.String(10), nullable=False)
    getKey = db.Column(db.String(80), default=createUUID, primary_key=True)
    #User backreference
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id', onupdate="cascade"), nullable=False)
    keys = db.relationship('Key', backref='owner', cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        #Seperates kwargs that belong to the relative delta functions from the kwargs that define the License parameters. (Also cause I thought it would be cool to make this)
        nkwargs, kwargs = funcValidParam(relativedelta, **kwargs)
        if not nkwargs:
            nkwargs["years"] = 1
        kwargs['expiryDate'] = str(date.today() + relativedelta(**nkwargs))
        super(License, self).__init__(**kwargs)
        db.session.add(self)

    #Adds keys
    def addKey(self, amount):
        for i in range(amount):
            db.session.add(Key(owner = self))

    #Takes the input months, years and days and renews the license
    def renew(self, **kwargs):
        e = createDateTime(self.expiryDate)
        #Add days based on today or the expiry date, whichever is latest
        self.expiryDate = str(max(e, date.today()) + relativedelta(**kwargs))

    #Resets expiry to x days from now
    def resetExpiry(self, **kwargs):
        self.expiryDate = str(date.today() + relativedelta(**kwargs))

    #Resets the registration key
    def resetGetKey(self):
        self.getKey = createUUID()
        for i in self.keys:
            i.owner_id = self.getKey

    #Resets all the keys
    def resetAll(self):
        for i in self.keys:
            i.reset()


#Key table
class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machineId = db.Column(db.String(200), default='')
    alias = db.Column(db.String(80), default='')
    inUse = db.Column(db.Boolean, default=False)
    #License backreference
    owner_id = db.Column(db.String(80), db.ForeignKey('license.getKey', onupdate="cascade"), nullable=False)
    lastAccess = db.Column(db.DateTime)
    lastIP = db.Column(db.String(16))
    accessAmount = db.Column(db.Integer, default=0)

    #Reset back to default
    def reset(self):
        self.inUse = False
        self.machineId = ''
        self.alias = None

    #Checks if machineID is similar enough
    def checkSimilar(self, s):
        if self.machineId == '':
            return False

        s = s.split(':')
        m = self.machineId.split(':')
        c = []
        for i in range(len(m)):
            if s[i] != m[i]:      
                c.append(i)

        if len(c) > 2:
            return False

        for i in c:       
            m[i] = s[i]

        self.machineId = ':'.join(m)
        db.session.commit()
        return True