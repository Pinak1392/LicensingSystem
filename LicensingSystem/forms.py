from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.fields.core import IntegerField, BooleanField
from wtforms.fields.html5 import EmailField
from wtforms.validators import Length, InputRequired, NumberRange, ValidationError
from wtforms.widgets.html5 import NumberInput
from string import punctuation


#Validators
def checkSafePassword(form, field):
        err = True
        for i in field.data:
            if i.upper() == i:
                err = False
                break
        
        if err:
            raise ValidationError('Password must include atleast one uppercase')

        err = True
        for i in '0123456789':
            if i in field.data:
                err = False
                break

        if err:
            raise ValidationError('Password must include atleast one number')

        err = True
        for i in punctuation:
            if i in field.data:
                err = False
                break

        if err:
            raise ValidationError('Password must include atleast one special character')


#Forms
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired()])
    password = PasswordField('Password')
    rememberMe = BooleanField('Remember me?')

class RegisterForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8), checkSafePassword])
    name = StringField('Name', validators=[InputRequired(), Length(max=100)])
    email = EmailField('Email', validators=[InputRequired(), Length(max=40)])
    phoneNumber = StringField('Phone Number', validators=[InputRequired(), Length(max=12)])
    admin = BooleanField('Admin?')

class ChangeForm(FlaskForm):
    name = StringField('Name', validators=[Length(max=100)])
    email = EmailField('Email', validators=[Length(max=40)])
    phoneNumber = StringField('Phone Number', validators=[Length(max=12)])

class ForgotForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), checkSafePassword])
    conpassword = PasswordField('Confirm New Password', validators=[InputRequired()])

    def validate_conpassword(form, field):
        if not field.data == form.password.data:
            raise ValidationError('Confirmation password must be same as new password')

class SearchForm(FlaskForm):
    search = StringField('Search', validators=[Length(max=100)], default="")

class MakeLicenseForm(FlaskForm):
    years = IntegerField('Year(s)', validators=[InputRequired(), NumberRange(min=0, message='Must enter a number greater than 0')], default=0, widget=NumberInput())
    months = IntegerField('Month(s)', validators=[InputRequired(), NumberRange(min=0, message='Must enter a number greater than 0')], default=1, widget=NumberInput())
    days = IntegerField('Day(s)', validators=[InputRequired(), NumberRange(min=0, message='Must enter a number greater than 0')], default=0, widget=NumberInput())
    keys = IntegerField('Key(s)', validators=[InputRequired(), NumberRange(min=0, message='Must enter a number greater than 0')], default=1, widget=NumberInput())