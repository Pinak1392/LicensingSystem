from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
import inspect
from uuid import uuid4
from datetime import date, datetime
from dateutil.relativedelta import relativedelta
from flask_apscheduler import APScheduler

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://gbnwhhhxyzaclx:84e827e01d92386d86334885ac88a53b3ecac998303218b4dc49d6b766d97ea2@ec2-52-21-252-142.compute-1.amazonaws.com:5432/d84p5v7pdmp1sr'
db = SQLAlchemy(app)

scheduler = APScheduler()
scheduler.api_enabled = True
scheduler.init_app(app)
scheduler.start()

#Funcs
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

#Background tasks
#@scheduler.task('interval', id='do_expiryCheck', seconds=30)
@scheduler.task('cron', id='do_expiryCheck', day='*')
def expiryCheck():
    day = date.today()
    
    #Check for expiry in month
    for i in License.query.filter_by(expiryDate = str(day + relativedelta(month=1))).all():
        pass
    
    #Check for expiry in week
    for i in License.query.filter_by(expiryDate = str(day + relativedelta(day=7))).all():
        pass
    
    #Check for expiry today
    for i in License.query.filter_by(expiryDate = str(day)).all():
        print("Key for account: <" + i.email + "> expires today")


#Models
class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(40), nullable=False, unique=True)
    creationDate = db.Column(db.String(10), default=today, nullable=False)
    expiryDate = db.Column(db.String(10), nullable=False)
    getKey = db.Column(db.String(80), default=createUUID, nullable=False)
    keys = db.relationship('Key', backref='owner', cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        nkwargs, kwargs = funcValidParam(relativedelta, **kwargs)
        if not nkwargs:
            nkwargs["years"] = 1
        kwargs['expiryDate'] = str(date.today() + relativedelta(**nkwargs))
        super(License, self).__init__(**kwargs)
        db.session.add(self)
        db.session.add(Key(owner = self))

    def __str__(self):
        return f"UID: {self.id}, Email: {self.email}, Keys[\n" + '\n--------------------------\n'.join(["    " + str(i).replace("\n","\n    ") for i in self.keys]) + "\n]"

class Key(db.Model):
    keyId = db.Column(db.String(80), default=createUUID, nullable=False, primary_key=True)
    key = db.Column(db.String(80), default=createUUID, nullable=False)
    inUse = db.Column(db.Boolean, default=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('license.id'), nullable=False)

    def __str__(self):
        return f"ID:{self.keyId}\nKey:{self.key}"


#Routes
@app.route("/")
def appCheck():
    usersStr = "<br><br><br>".join([str(i) for i in License.query.all()]).replace('\n','<br>').replace(' ','&nbsp;')
    return usersStr

@app.route("/create", methods=['POST'])
def newUser():
    uEmail = request.form.get('email')
    num = int(request.form.get('num'))
    newLicense = License(email=uEmail)
    for i in range(num - 1):
        newKey = Key(owner=newLicense)
        db.session.add(newKey)
    
    db.session.commit()

    return str(newLicense.getKey)

@app.route("/createKey", methods=['POST'])
def newKey():
    uEmail = request.form.get('email')
    num = int(request.form.get('num'))
    user = License.query.filter_by(email=uEmail).first()
    if not user:
        return "error, not a registered user"
    for i in range(num):
        newKey = Key(owner=user)
        db.session.add(newKey)
        db.session.commit()

    return "True"

@app.route("/getKey", methods=['POST'])
def getKey():
    getKey = request.form.get('getKey')
    keys = License.query.filter_by(getKey=getKey).first().keys
    for i in keys:
        if i.inUse == False:
            i.inUse = True
            db.session.commit()
            return str(key)
    return "All keys in use"

@app.route("/verify", methods=['POST'])
def verify():
    keyVal = request.form.get('key')
    key = Key.query.filter_by(key=keyVal).first()
    if key:
        print(createDateTime(key.owner.expiryDate), date.today())
        if createDateTime(key.owner.expiryDate) < date.today():
            return "expired"

        return str(uuid4())

    return "error"

@app.route("/newKeyReceived", methods=['POST'])
def newKeyReceived():
    keyId = request.form.get('id')
    oldkeyVal = request.form.get('oldkey')
    keyVal = request.form.get('key')
    key = Key.query.filter_by(keyId=keyId, key=oldkeyVal).first()
    key.key = keyVal
    db.session.commit()

    return 'received'

if __name__ == '__main__':
    app.run(debug=True)