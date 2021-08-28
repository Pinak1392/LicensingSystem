from flask import *
from dateutil.relativedelta import relativedelta
from flask_apscheduler import APScheduler
from flask_login.utils import _secret_key, fresh_login_required, login_fresh
from flask_migrate import Migrate
from flask_login import LoginManager, login_required, logout_user, login_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from functools import wraps
import sys
import requests

#Routable function storage
routes = {}

app = Flask(__name__)
app.secret_key = '\xfd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xd5\xa2\xa0\x9fR"\xa1\xa8'
app.debug = True

#Setup db
from models import *
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://gbnwhhhxyzaclx:84e827e01d92386d86334885ac88a53b3ecac998303218b4dc49d6b766d97ea2@ec2-52-21-252-142.compute-1.amazonaws.com:5432/d84p5v7pdmp1sr'
db.init_app(app)

#Import forms
from forms import *

#Setup password encryption
bcrypt = Bcrypt(app)

#Setup login system
login_manager = LoginManager(app)

@login_manager.unauthorized_handler
def handle_needs_login():
    flash("You have to be logged in to access this page.")
    #instead of using request.path to prevent Open Redirect Vulnerability 
    session['next']=url_for(request.endpoint,**request.view_args)
    return redirect(url_for('login'))

@login_manager.needs_refresh_handler
def handle_needs_login():
    flash("To protect your account, please reauthenticate to access this page.")
    #instead of using request.path to prevent Open Redirect Vulnerability 
    session['next']=url_for(request.endpoint,**request.view_args)
    return redirect(url_for('login'))


#Setup migration
migrate = Migrate(app, db)

#Setup mail
app.config['MAIL_DEFAULT_SENDER'] = 'vayuWeb@gmail.com'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'vayuWeb@gmail.com'
app.config['MAIL_PASSWORD'] = 'vayuWebMail75%'

mail = Mail(app)

app.config["SCHEDULER_API_ENABLED"] = True
scheduler = APScheduler()
scheduler.api_enabled = True
scheduler.init_app(app)

#Funcs
from functions import *

#Create user loader
@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


#before request stuff
@app.before_request
def before_request():
    r = request.endpoint
    try:
        app.view_functions[r].keepfresh
    except:
        try:
            session.pop("_fresh")
        except:
            pass
    


#Check url
from urllib.parse import urlparse, urljoin

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


#Decorator to add functions to routing dictionary (No longer necessary, but still cool nonetheless)
# def routable(func):
#     routes[func.__name__] = func
#     return func

def keepfresh(func):
    func.keepfresh = True
    return func

#Decorator to check for admin
def admin(func):
    #Keeps original function as the main called function (useful for debugging)
    @wraps(func)
    def decorated(*args, **kwargs):
        if(current_user and current_user.admin):
            return func(*args, **kwargs)

        flash("Error: endpoint restricted")
        return redirect(url_for('home'))

    return decorated


def createAdmin(email,phone,password,name):
    pw_hash = bcrypt.generate_password_hash(password)
    adminUser = User(email = email, phoneNo = phone, name = name, password = pw_hash, admin = True, active = True)
    db.session.add(adminUser)
    db.session.commit()

def createSuperAdmin(email,phone,password,name):
    pw_hash = bcrypt.generate_password_hash(password)
    adminUser = User(email = email, phoneNo = phone, name = name, password = pw_hash, admin = True, superadmin=True, active = True)
    db.session.add(adminUser)
    db.session.commit()

def createActiveUser(email,phone,password,name):
    pw_hash = bcrypt.generate_password_hash(password)
    user = User(email = email, phoneNo = phone, name = name, password = pw_hash, active = True)
    db.session.add(user)
    db.session.commit()


#Background tasks
@scheduler.task('cron', id='do_expiryCheck', day='*')
def expiryCheck():
    with app.app_context():
        day = date.today()
        
        #Check for expiry in month
        for i in License.query.filter_by(expiryDate = str(day + relativedelta(month=1))).all():
            pass
        
        #Check for expiry in week
        for i in License.query.filter_by(expiryDate = str(day + relativedelta(day=7))).all():
            pass
        
        #Check for expiry today
        for i in License.query.filter_by(expiryDate = str(day)).all():
            msg = Message(subject="License Expiry warning",
                recipients=[i.owner.email],
                body = "A Vayu license for your account expires today")

            mail.send(msg)

@scheduler.task('cron', id='do_prune', day='*')
def pruner():
    with app.app_context():
        for i in User.query.filter_by(active = False).all():
            db.session.delete(i)
            db.session.commit()

@scheduler.task('interval', id='stop_sleep', seconds=30)
def nosleep():
    requests.get('https://licenseprototype.herokuapp.com/')

scheduler.start()
    


#Routes
@app.route('/home', methods=['GET'])
@app.route("/", methods=['GET'])
def home():
    #From when I wanted to encrypt my endpoints. (No longer necessary)
    # try:
    #     content = json.loads(request.form.get("val"))
    #     return routes[content[0]](content[1])
    # except:
    #     pass

    return render_template("homepage.html", user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if 'forgot' in request.form:
        user = User.query.filter_by(email = form.email.data).first()

        if not user or not user.active:
            flash('Email unrecognised')
            return render_template("login.html", form=form, user=current_user)

        msg = Message(subject="Reset Password",
              recipients=[user.email],
              html = "<a href=" + request.url_root + 'forgot/' + user.userKey + ">Click here</a>")
        mail.send(msg)
        return redirect(url_for("login"))

    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user:
            if not user.active:
                flash('User not verified, resending verification email')
                session['email'] = user.email
                return redirect(url_for("verifyEmail"))

            if bcrypt.check_password_hash(user.password, form.password.data):
                user.authenticated = True
                db.session.commit()
                login_user(user, remember=form.rememberMe.data)
                flash('Logged in successfully.')
                
                try:
                    if not is_safe_url(session['next']):
                        return abort(400)

                    return redirect(session.pop('next'))
                except:
                    return redirect(url_for("home"))
                    
            else:
                flash('Incorrect password.')
        else:
            flash('Unknown or unverified user.')

    return render_template("login.html", form=form, user=current_user)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        pw_hash = bcrypt.generate_password_hash(form.password.data)

        newUser = User(email = form.email.data, phoneNo = form.phoneNumber.data, name = form.name.data, password = pw_hash)
        user = User.query.filter_by(email = form.email.data).first()
        
        if user:
            flash("Email is already in use. If you are attempting to resend a validation email, login with the unvalidated account.")
        
        else:
            try:
                if form.admin.data:
                    newUser.admin = True
                
                db.session.add(newUser)
                db.session.commit()
                session['email'] = newUser.email
                return redirect(url_for("verifyEmail"))
            except Exception as e:
                db.session.rollback()
                db.session.flush() # for resetting non-commited .add()
                print(e)
                flash("Info not compatable with DB")

    return render_template("register.html", form=form, user=current_user)

@app.route("/change", methods=["GET", "POST"])
@fresh_login_required
@keepfresh
def change():
    form = ChangeForm()
    if form.validate_on_submit():
        if form.email.data != '':
            oldAccount = {"id":current_user.id, 'email':current_user.email}
            oldAccPickle = encrypt(current_user.pickleKey, str(encrypt(app.secret_key, json.dumps(oldAccount))))
            current_user.email = form.email.data
            
        if form.name.data != '':
            current_user.name = form.name.data
            
        if form.phoneNumber.data != '':
            current_user.phoneNo = form.phoneNumber.data

        try:
            msg = Message(subject="Verify Email",
              recipients=[oldAccount['email']],
              body = "Your account email has been changed. If you have not caused this. Contact us IMMEDIATELY and send us the key below.\n\n" + oldAccPickle)
            mail.send(msg)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            db.session.flush()
            flash("Email or phone number already taken")

        flash("Information successfully changed")
            

    return render_template("change.html", form=form, user=current_user)


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    user = current_user
    flash(user.name + " successfully logged out")
    user.authenticated = False
    db.session.commit()
    logout_user()
    return redirect(url_for("home"))


@app.route("/verifyEmail", methods=["GET"])
def verifyEmail():
    user = User.query.filter_by(email=session['email']).first()
    msg = Message(subject="Verify Email",
              recipients=[user.email],
              html = "<a href=" + url_for('activate',userKey=user.userKey) + ">Click here</a>")
    mail.send(msg)
    return render_template("verifyEmail.html")


@app.route("/purchase", methods=["GET", "POST"])
@login_required
def purchase():
    form = MakeLicenseForm()
    if form.validate_on_submit():
        try:
            getKey = current_user.addLicense(form.keys.data, years = form.years.data, months = form.months.data, days = form.days.data)
            msg = Message(subject="Your Vayu Registration Key",
              recipients=[current_user.email],
              body = "Your Vayu registration key = " + getKey)
            mail.send(msg)
            flash("Successfully added license")
            return redirect(url_for("home"))
        except Exception as e:
            db.session.rollback()
            db.session.flush() # for resetting non-commited .add()
            print(e)

    return render_template("purchase.html", form=form, user=current_user)


@app.route("/renew/<getKey>", methods=["GET", "POST"])
@login_required
def renew(getKey):
    l = License.query.get(getKey)

    if not l or (l.owner != current_user and not current_user.admin):
        flash("You do not own this license or it does not exist")
        return redirect(url_for("home"))

    form = MakeLicenseForm()
    if form.validate_on_submit():
        try:
            if 'Renew' in request.form:
                l.renew(years = form.years.data, months = form.months.data, days = form.days.data)
                db.session.commit()
                msg = Message(subject="Your Vayu license has been renewed",
                recipients=[l.owner.email],
                body = "Your Vayu registration key = " + getKey)
                mail.send(msg)
                flash("Successfully renewed license")

            if 'Reset' in request.form:
                l.resetExpiry(years = form.years.data, months = form.months.data, days = form.days.data)
                db.session.commit()
                msg = Message(subject="Your Vayu license has had its expiry reset",
                recipients=[l.owner.email],
                body = "Your Vayu registration key = " + getKey)
                mail.send(msg)
                flash("Successfully reset license expiry")

            if current_user.admin:
                return redirect(url_for("manageUser", email=session['email']))

            return redirect(url_for("viewLicense"))
        except Exception as e:
            db.session.rollback()
            db.session.flush() # for resetting non-commited .add()
            print(e)

    return render_template("renew.html", form=form, user=current_user, getKey=getKey)


@app.route("/viewLicense", methods=["GET", "POST"])
@login_required
def viewLicense():
    if "View" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        return redirect(url_for("manageLicense", getKey=l.getKey))

    if "Renew" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        return redirect(url_for("renew", getKey=l.getKey))

    return render_template("licenses.html", user=current_user)


@app.route('/activate/<userKey>')
def activate(userKey):
    user = User.query.filter_by(userKey = userKey).first()
    if not user:
        flash("Verification expired")
        try:
            session['email'] = user.email
            user.generateNewToken()
            return redirect(url_for("verifyEmail"))
        except:
            flash("Can't set email try logging in")
            return redirect(url_for('login'))

    user.active = True
    user.generateNewToken()
    db.session.commit()
    flash("Successfully registered")
    return redirect(url_for("login"))


@app.route('/forgot/<userKey>', methods=["GET", "POST"])
@keepfresh
def forgot(userKey):
    form = ForgotForm()

    if current_user and not login_fresh():
        flash("To protect your account, please login again")
        return redirect(url_for("login"))

    if form.validate_on_submit():
        pw_hash = bcrypt.generate_password_hash(form.password.data)
        user = User.query.filter_by(userKey = userKey).first()
        user.password = pw_hash
        user.generateNewToken()
        db.session.commit()

        if current_user:
            flash("Password changed")
            return redirect(url_for("settings"))

        return redirect(url_for("login"))

    return render_template("forgot.html", form=form, userKey=userKey)


@app.route('/users', methods=["GET", "POST"])
@login_required
@admin
def users():
    form = SearchForm()

    if "Remove" in request.form:
        s = request.form.get('User')
        u = User.query.filter_by(email = s).first()
        db.session.delete(u)
        db.session.commit()
        flash("Successfully removed User")

    if "View" in request.form:
        s = request.form.get('User')
        return redirect(url_for("manageUser", email=s))

    u = User.query.filter(User.name.ilike(f"%{form.search.data}%") | User.email.ilike(f"%{form.search.data}%")).all()

    return render_template("users.html", users=u, user=current_user, form=form)


@app.route('/allLicenses')
@login_required
@admin
def allLicenses():
    return render_template("allLicenses.html", licenses = License.query.all(), user=current_user)


@app.route('/manageUser/<email>', methods=['GET', 'POST'])
@login_required
@admin
def manageUser(email):
    selected = User.query.filter_by(email=email).first()
    form = MakeLicenseForm()

    if "Remove" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        db.session.delete(l)
        db.session.commit()
        flash("Successfully removed license")

    if "View" in request.form:
        s = request.form.get('License')
        return redirect(url_for("manageLicense", getKey=s))

    if "Renew" in request.form:
        session['email'] = email
        s = request.form.get('License')
        l = License.query.get(s)
        return redirect(url_for("renew", getKey=l.getKey))

    if "Reset registration key" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        l.resetGetKey()
        db.session.commit()
        flash("Registration key has been reset")

    if "Reset all keys" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        l.resetAll()
        db.session.commit()
        flash("All keys have been reset")

    if form.validate_on_submit():
        getKey = selected.addLicense(form.keys.data, years = form.years.data, months = form.months.data, days = form.days.data)
        msg = Message(subject="Your Vayu Registration Key",
            recipients=[selected.email],
            body = "Your Vayu registration key = " + getKey)
        mail.send(msg)
        flash("Successfully added license")
        return redirect(url_for("manageUser", email=email))

    return render_template("manageUser.html", selectedUser=selected, user=current_user, form=form)


@app.route('/manageLicense/<getKey>', methods=['GET', 'POST'])
@login_required
def manageLicense(getKey):
    selected = License.query.get(getKey)
    form = MakeLicenseForm()
    searchform = SearchForm()

    if selected not in current_user.licenses and not current_user.admin:
        flash("License not owned by current user")
        return redirect(url_for("home"))

    elif "Remove" in request.form:
        s = request.form.get('Key')
        l = Key.query.get(s)
        db.session.delete(l)
        db.session.commit()
        flash("Successfully removed key")

    elif "Reset" in request.form:
        s = request.form.get('Key')
        l = Key.query.get(s)
        l.reset()
        db.session.commit()
        flash("Successfully reset key")

    elif form.validate_on_submit():
        if form.keys.data:
            selected.addKey(form.keys.data)
            db.session.commit()
            flash("Successfully added key")

    keys = Key.query.filter(Key.alias.ilike(f"%{searchform.search.data}%") & (Key.owner_id == selected.getKey)).all()

    return render_template("manageLicense.html", selectedLicense=selected, user=current_user, form=form, searchform=searchform, keys=keys)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():  
    return render_template("settings.html", user=current_user)

#Vayu accessible functions
@app.route('/verify', methods=["POST"])
def verify():
    machineID = request.form.get("machineid")
    try:
        ip = request.environ['HTTP_X_FORWARDED_FOR']
    except:
        ip = request.environ['REMOTE_ADDR']

    keys = Key.query.all()
    for i in keys:
        key = i.checkSimilar(machineID)
        if key:
            d = createDateTime(i.owner.expiryDate)
            i.lastIP = ip
            i.lastAccess = datetime.now()
            i.accessAmount += 1
            db.session.commit()
            if date.today() <= d:
                return "True"

            return "License is expired"

    return "Machine not verified"


@app.route('/setupkey', methods=["POST"])
def setupkey():
    machineId = request.form.get("machineid")
    getKey = request.form.get("regkey")
    alias = request.form.get("hostname")

    l = License.query.get(getKey)

    if l:
        for key in l.keys:
            if not key.inUse:
                key.inUse = True
                key.machineId = machineId
                key.alias = alias
                db.session.commit()
                return "True"

        return "No keys available"

    return "License not found"

if __name__ == '__main__':
    app.run(debug=True)