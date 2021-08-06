from flask_sqlalchemy import SQLAlchemy
from functions import *
from dateutil.relativedelta import relativedelta

db = SQLAlchemy()

#Models
class User(db.Model):
    id = db.Column(db.Integer, nullable=False, unique=True, primary_key=True)
    email = db.Column(db.String(40), nullable=False, unique=True)
    phoneNo = db.Column(db.String(12), nullable=False, unique=True)
    password = db.Column(db.LargeBinary(), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    authenticated = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=False)
    userKey = db.Column(db.String(80), default=createUUID, nullable=False)
    admin = db.Column(db.Boolean, default=False)
    licenses = db.relationship('License', backref='owner', cascade="all, delete-orphan")

    def addLicense(self, amount, **kwargs):
        newLicense = License(owner = self, **kwargs)
        newLicense.addKey(amount)
        db.session.commit()
        return newLicense.getKey

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


class License(db.Model):
    creationDate = db.Column(db.String(10), default=today, nullable=False)
    expiryDate = db.Column(db.String(10), nullable=False)
    getKey = db.Column(db.String(80), default=createUUID, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id', onupdate="cascade"), nullable=False)
    keys = db.relationship('Key', backref='owner', cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        nkwargs, kwargs = funcValidParam(relativedelta, **kwargs)
        if not nkwargs:
            nkwargs["years"] = 1
        kwargs['expiryDate'] = str(date.today() + relativedelta(**nkwargs))
        super(License, self).__init__(**kwargs)
        db.session.add(self)

    def addKey(self, amount):
        for i in range(amount):
            db.session.add(Key(owner = self))

    #Takes the input months, years and days
    def renew(self, **kwargs):
        e = createDateTime(self.expiryDate)
        self.expiryDate = str(max(e, date.today()) + relativedelta(**kwargs))

    def resetExpiry(self, **kwargs):
        self.expiryDate = str(date.today() + relativedelta(**kwargs))

    def resetGetKey(self):
        self.getKey = createUUID()
        for i in self.keys:
            i.owner_id = self.getKey

    def resetAll(self):
        for i in self.keys:
            i.reset()


class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machineId = db.Column(db.String(200), default='')
    alias = db.Column(db.String(80), default='')
    inUse = db.Column(db.Boolean, default=False)
    owner_id = db.Column(db.String(80), db.ForeignKey('license.getKey', onupdate="cascade"), nullable=False)
    lastAccess = db.Column(db.DateTime)
    lastIP = db.Column(db.String(16))
    accessAmount = db.Column(db.Integer, default=0)

    def reset(self):
        self.inUse = False
        self.machineId = ''
        self.alias = None

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