from flask import *
from dateutil.relativedelta import relativedelta
from flask_apscheduler import APScheduler
from flask_login.utils import fresh_login_required, login_fresh
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

#The handlers for an unauthorized login or a reverification request
@login_manager.unauthorized_handler
def handle_needs_login():
    flash("You have to be logged in to access this page.")
    #instead of using request.path to prevent Open Redirect Vulnerability 
    session['next']=url_for(request.endpoint,**request.view_args)
    return redirect(url_for('login'))

@login_manager.needs_refresh_handler
def handle_needs_refresh():
    flash("To protect your account, please reauthenticate to access this page.")
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

#APScheduler config
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
        #Checks if the endpoint is one that requires reverification
        app.view_functions[r].keepfresh
    except:
        try:
            #Otherwise it removes the fresh session token (This exploits the refresh handler in flask to create a reverifier)
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


#Decorator to add functions to routing dictionary (No longer necessary, but useful as a reference)
# def routable(func):
#     routes[func.__name__] = func
#     return func

# A wrapper that tags a route as one that requires reverification
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

#Creates an admin (without requiring email verification)
def createAdmin(email,phone,password,name):
    pw_hash = bcrypt.generate_password_hash(password)
    adminUser = User(email = email, phoneNo = phone, name = name, password = pw_hash, admin = True, active = True)
    db.session.add(adminUser)
    db.session.commit()

#Creates a super admin (without requiring email verification)
def createSuperAdmin(email,phone,password,name):
    pw_hash = bcrypt.generate_password_hash(password)
    adminUser = User(email = email, phoneNo = phone, name = name, password = pw_hash, admin = True, superadmin=True, active = True)
    db.session.add(adminUser)
    db.session.commit()

#Creates a user (without requiring email verification)
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

#Prunes out non verified users at the end of every day
@scheduler.task('cron', id='do_prune', day='*')
def pruner():
    with app.app_context():
        for i in User.query.filter_by(active = False).all():
            db.session.delete(i)
            db.session.commit()

#A function that stops the heroku server from going to sleep. Needs to be removed in final production.
@scheduler.task('interval', id='stop_sleep', seconds=30)
def nosleep():
    requests.get('https://licenseprototype.herokuapp.com/')

#Start background tasks
scheduler.start()
    


#Routes

#The homepage route
@app.route('/home', methods=['GET'])
@app.route("/", methods=['GET'])
def home():
    return render_template("homepage.html", user=current_user)


#Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    #Checks if the forgot button was pressed
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

    #Checks if the form has valid information after submit button has been pressed
    if form.validate_on_submit():
        #User query function
        user = User.query.filter_by(email = form.email.data).first()
        if user:
            #If user is not verified, resend verification email
            if not user.active:
                flash('User not verified, resending verification email')
                #Session email stores the user email for inter route information exchange
                session['email'] = user.email
                return redirect(url_for("verifyEmail"))

            #I use bcrypt to hash the passwords to store in the DB
            if bcrypt.check_password_hash(user.password, form.password.data):
                user.authenticated = True
                db.session.commit()
                #The login user function provided by flask-login. form.rememberMe.data is taken from the checked box in the form.
                login_user(user, remember=form.rememberMe.data)
                flash('Logged in successfully.')
                
                #The redirection function if the user has navigated to the login from a different page (mostly pages that require reverification)
                try:
                    if not is_safe_url(session['next']):
                        return abort(400)

                    return redirect(session.pop('next'))
                except:
                    #If there is no need for a redirect, go to the homepage
                    return redirect(url_for("home"))
                    
            else:
                flash('Incorrect password.')
        else:
            flash('Unknown or unverified user.')

    return render_template("login.html", form=form, user=current_user)


#The registration page
@app.route("/register", methods=["GET", "POST"])
def register():
    #The registration form
    form = RegisterForm()
    if form.validate_on_submit():
        pw_hash = bcrypt.generate_password_hash(form.password.data)

        #Check if user already exists with entered email
        user = User.query.filter_by(email = form.email.data).first()
        phone = User.query.filter_by(phone = form.phoneNumber.data).first()

        #Create new user instance
        newUser = User(email = form.email.data, phoneNo = form.phoneNumber.data, name = form.name.data, password = pw_hash)
        
        #If email or phone already in use
        if user:
            flash("Email is already in use. If you are attempting to resend a validation email, login with the unvalidated account.")
        if phone:
            flash("Phone number is already in use.")
        
        else:
            try:
                #Check if the form has set admin as true
                if form.admin.data:
                    newUser.admin = True
                
                #Enter user into the system
                db.session.add(newUser)
                db.session.commit()

                #Got to email verification
                session['email'] = newUser.email
                return redirect(url_for("verifyEmail"))
            except Exception as e:
                #Incase of failure, rollback and flash a generic error
                db.session.rollback()
                db.session.flush() # for resetting non-commited .add()
                print(e)
                flash("Info not compatable with DB")

    #Return html for the endpoint with the form object and the current user object
    return render_template("register.html", form=form, user=current_user)


#The endpoint in charge of changing user info
@app.route("/change", methods=["GET", "POST"])
#Added keep fresh and fresh login required decorators to signal a reverification check
@fresh_login_required
@keepfresh
def change():
    form = ChangeForm()
    if form.validate_on_submit():
        #Only change out info with inputed data. All others will be unchanged
        if form.email.data != '':
            #In the case of an email change, create a backup accountID and email dictionary and double encrypt it before sending it to the old email.
            #This will hopefully mitigate the damage of a hacker changing an email. It also doesn't allow for a user to directly control the database easily.
            oldAccount = {"id":current_user.id, 'email':current_user.email, 'date':str(datetime.now())}
            oldAccPickle = encrypt(current_user.pickleKey, str(encrypt(app.secret_key, json.dumps(oldAccount))))
            current_user.email = form.email.data

            #Send old email a warning about the email change
            msg = Message(subject="Verify Email",
              recipients=[oldAccount['email']],
              body = "Your account email has been changed or a change was attempted. If you have not caused this. Contact us IMMEDIATELY and send us the key below.\n\n" + oldAccPickle)
            mail.send(msg)
            
        if form.name.data != '':
            current_user.name = form.name.data
            
        if form.phoneNumber.data != '':
            current_user.phoneNo = form.phoneNumber.data

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            db.session.flush()
            flash("Email or phone number already taken")

        flash("Information successfully changed")
            

    return render_template("change.html", form=form, user=current_user)


#Simple logout route
@app.route("/logout", methods=["GET"])
@login_required
def logout():
    user = current_user
    #Flash message on the next page user is redirected to
    flash(user.name + " successfully logged out")
    user.authenticated = False
    db.session.commit()
    logout_user()
    return redirect(url_for("home"))


#Email verification route
@app.route("/verifyEmail", methods=["GET"])
def verifyEmail():
    #Get user from session email
    user = User.query.filter_by(email=session['email']).first()

    #Verification endpoint is sent to user with a special userkey that is reset every use
    msg = Message(subject="Verify Email",
              recipients=[user.email],
              html = "<a href=" + url_for('activate',userKey=user.userKey) + ">Click here</a>")
    mail.send(msg)
    return render_template("verifyEmail.html")


#Currently just a form which allows the creation of licenses with no payment
@app.route("/purchase", methods=["GET", "POST"])
#This is a decorator which requires a logged in account
@login_required
def purchase():
    form = MakeLicenseForm()
    if form.validate_on_submit():
        try:
            #Creates the license
            getKey = current_user.addLicense(form.keys.data, years = form.years.data, months = form.months.data, days = form.days.data)
            #Emails license registration key to user
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


#Renews a license
@app.route("/renew/<getKey>", methods=["GET", "POST"])
@login_required
def renew(getKey):
    #Gets license
    l = License.query.get(getKey)

    #Checks if the license is owned by the user, or the user is an admin
    if not l or (l.owner != current_user and not current_user.admin):
        flash("You do not own this license or it does not exist")
        return redirect(url_for("home"))

    #Reuses the make license form cause it has all the required parts and validation
    form = MakeLicenseForm()
    if form.validate_on_submit():
        try:
            #If the button clicked was renew, renew the license for the amount of time entered. The amount of time added is either
            #added to the expiration date, or the date today depending on which one is later
            if 'Renew' in request.form:
                l.renew(years = form.years.data, months = form.months.data, days = form.days.data)
                db.session.commit()
                msg = Message(subject="Your Vayu license has been renewed",
                recipients=[l.owner.email],
                body = "Your Vayu registration key = " + getKey)
                mail.send(msg)
                flash("Successfully renewed license")

            #If the reset button is clicked (Admin only) the expiration date is set to x number of days from today
            if 'Reset' in request.form:
                l.resetExpiry(years = form.years.data, months = form.months.data, days = form.days.data)
                db.session.commit()
                msg = Message(subject="Your Vayu license has had its expiry reset",
                recipients=[l.owner.email],
                body = "Your Vayu registration key = " + getKey)
                mail.send(msg)
                flash("Successfully reset license expiry")

            #If you are currently admin, redirect to the user you were managing or go home if you directly went to the route via url
            if current_user.admin:
                if 'email' in session:
                    return redirect(url_for("manageUser", email=session['email']))
                else:
                    return redirect(url_for("home"))

            #Otherwise go back to regular license view screen
            return redirect(url_for("viewLicense"))
        except Exception as e:
            db.session.rollback()
            db.session.flush() # for resetting non-commited .add()
            print(e)

    return render_template("renew.html", form=form, user=current_user, getKey=getKey)


#View all your licenses
@app.route("/viewLicense", methods=["GET", "POST"])
@login_required
def viewLicense():
    #This takes you to the screen where you can manage the keys
    if "View" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        return redirect(url_for("manageLicense", getKey=l.getKey))

    #This takes you to the renewal screen
    if "Renew" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        return redirect(url_for("renew", getKey=l.getKey))

    #Resets a licenses registration key
    if "Reset registration key" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        l.resetGetKey()
        db.session.commit()
        flash("Registration key has been reset")

    #Resets all keys in a license
    if "Reset all keys" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        l.resetAll()
        db.session.commit()
        flash("All keys have been reset")

    return render_template("licenses.html", user=current_user)


#This endpoint activates the user
@app.route('/activate/<userKey>')
def activate(userKey):
    user = User.query.filter_by(userKey = userKey).first()
    
    #Incase of failed user activation
    if not user:
        flash("Verification expired")
        try:
            #Try resending verification email
            session['email'] = user.email
            user.generateNewToken()
            return redirect(url_for("verifyEmail"))
        except:
            #Send user to login to see if their account can be found through manual means
            flash("Can't set email try logging in")
            return redirect(url_for('login'))

    #Activate user
    user.active = True
    user.generateNewToken()
    db.session.commit()
    flash("Successfully registered")
    return redirect(url_for("login"))


#Change password endpoint
@app.route('/forgot/<userKey>', methods=["GET", "POST"])
@keepfresh
#Requires a user key variable from the endpoint
def forgot(userKey):
    form = ForgotForm()

    #If user is trying to change password through normal means as opposed to forgetting their password and going through email
    #Ask for a reverification
    if current_user and not login_fresh():
        flash("To protect your account, please login again")
        return redirect(url_for("login"))

    if form.validate_on_submit():
        pw_hash = bcrypt.generate_password_hash(form.password.data)
        user = User.query.filter_by(userKey = userKey).first()
        user.password = pw_hash
        user.generateNewToken()
        db.session.commit()

        #If user changed password through the settings
        if current_user:
            flash("Password changed")
            return redirect(url_for("settings"))

        return redirect(url_for("login"))

    return render_template("forgot.html", form=form, userKey=userKey)


#View all users
@app.route('/users', methods=["GET", "POST"])
@login_required
#Requires user to be admin
@admin
def users():
    form = SearchForm()

    #Delete user if remove was clicked
    if "Remove" in request.form:
        s = request.form.get('User')
        u = User.query.filter_by(email = s).first()
        db.session.delete(u)
        db.session.commit()
        flash("Successfully removed User")

    #View user if view is clicked
    if "View" in request.form:
        s = request.form.get('User')
        return redirect(url_for("manageUser", email=s))

    #Search function
    u = User.query.filter(User.name.ilike(f"%{form.search.data}%") | User.email.ilike(f"%{form.search.data}%")).all()

    return render_template("users.html", users=u, user=current_user, form=form)


#Defunct route, simply allows you to view all licenses. It isn't useful anymore, but it does still work.
@app.route('/allLicenses')
@login_required
@admin
def allLicenses():
    return render_template("allLicenses.html", licenses = License.query.all(), user=current_user)


#User management
@app.route('/manageUser/<email>', methods=['GET', 'POST'])
@login_required
@admin
def manageUser(email):
    #Get user
    selected = User.query.filter_by(email=email).first()
    #Form to create a license
    form = MakeLicenseForm()

    #Remove user
    if "Remove" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        db.session.delete(l)
        db.session.commit()
        flash("Successfully removed license")

    #Takes you to license management
    if "View" in request.form:
        s = request.form.get('License')
        return redirect(url_for("manageLicense", getKey=s))

    #Renews the selected license
    if "Renew" in request.form:
        session['email'] = email
        s = request.form.get('License')
        l = License.query.get(s)
        return redirect(url_for("renew", getKey=l.getKey))

    #Resets a licenses registration key
    if "Reset registration key" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        l.resetGetKey()
        db.session.commit()
        flash("Registration key has been reset")

    #Resets all keys in a license
    if "Reset all keys" in request.form:
        s = request.form.get('License')
        l = License.query.get(s)
        l.resetAll()
        db.session.commit()
        flash("All keys have been reset")

    #Create license for selected user
    if form.validate_on_submit():
        getKey = selected.addLicense(form.keys.data, years = form.years.data, months = form.months.data, days = form.days.data)
        msg = Message(subject="Your Vayu Registration Key",
            recipients=[selected.email],
            body = "Your Vayu registration key = " + getKey)
        mail.send(msg)
        flash("Successfully added license")
        return redirect(url_for("manageUser", email=email))

    #Selected user is the user that you are managing
    return render_template("manageUser.html", selectedUser=selected, user=current_user, form=form)


#Manage license
@app.route('/manageLicense/<getKey>', methods=['GET', 'POST'])
@login_required
def manageLicense(getKey):
    #Get license
    selected = License.query.get(getKey)
    form = MakeLicenseForm()
    searchform = SearchForm()

    #Check if current user owns license or is an admin
    if selected not in current_user.licenses and not current_user.admin:
        flash("License not owned by current user")
        return redirect(url_for("home"))

    #Remove key (Admin only)
    elif "Remove" in request.form:
        s = request.form.get('Key')
        l = Key.query.get(s)
        db.session.delete(l)
        db.session.commit()
        flash("Successfully removed key")

    #Reset key to default state
    elif "Reset" in request.form:
        s = request.form.get('Key')
        l = Key.query.get(s)
        l.reset()
        db.session.commit()
        flash("Successfully reset key")

    #Add keys to license
    elif form.validate_on_submit():
        if form.keys.data:
            selected.addKey(form.keys.data)
            db.session.commit()
            flash("Successfully added key")

    #Search keys based on what person/computer is using them
    keys = Key.query.filter(Key.alias.ilike(f"%{searchform.search.data}%") & (Key.owner_id == selected.getKey)).all()

    return render_template("manageLicense.html", selectedLicense=selected, user=current_user, form=form, searchform=searchform, keys=keys)


#Settings page
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():  
    return render_template("settings.html", user=current_user)

#Verify license
@app.route('/verify', methods=["POST"])
def verify():
    #Get machine info
    machineID = request.form.get("machineid")
    try:
        #Get ip info
        ip = request.environ['HTTP_X_FORWARDED_FOR']
    except:
        #Get ip info
        ip = request.environ['REMOTE_ADDR']

    keys = Key.query.all()
    for i in keys:
        #Check if key machineID is similar enough to received machineID. Accept it if it is.
        #I only check for similarity instead of congruency because a person may change a part of their machine.
        key = i.checkSimilar(machineID)
        if key:
            d = createDateTime(i.owner.expiryDate)
            #Save ip
            i.lastIP = ip
            #Save last access
            i.lastAccess = datetime.now()
            #Increment access amount (Not the most useful parameter due to vayu accessing server multiple times per use)
            i.accessAmount += 1
            db.session.commit()
            #Check for expiry
            if date.today() <= d:
                return "True"

            return "License is expired"

    return "Machine not verified"


#Setup the key
@app.route('/setupkey', methods=["POST"])
def setupkey():
    machineId = request.form.get("machineid")
    getKey = request.form.get("regkey")
    alias = request.form.get("hostname")

    #Get the license that is refered to in post request
    l = License.query.get(getKey)

    if l:
        #Set info in first available key
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