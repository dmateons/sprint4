from flask_wtf import FlaskForm
from wtforms import TextField, SubmitField, PasswordField, TextAreaField
from wtforms.fields.html5 import EmailField
from wtforms.validators import EqualTo, InputRequired

class Login(FlaskForm):
    usu = TextField('Usuario *', validators = [InputRequired(message='Indique el usuario')])
    cla = PasswordField('Clave *', validators = [InputRequired(message='Indique la clave')])
    btn = SubmitField('Login')

class Registro(FlaskForm):
    nom = TextField('Nombre *', validators = [InputRequired(message='Indique el nombre')])
    usu = TextField('Usuario *', validators = [InputRequired(message='Indique el usuario')])
    ema = EmailField('Email *', validators = [InputRequired(message='Indique el email')])
    cla = PasswordField('Clave *', validators = [InputRequired(message='Indique la clave')])
    ver = PasswordField('Verificación *', validators = [InputRequired(message='Indique la verificación'), EqualTo(cla,message='Clave y la verificación no coinciden')])
    btn = SubmitField('Registrar')