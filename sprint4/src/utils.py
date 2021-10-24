import re
from validate_email import validate_email

def email_valido(email):
    return validate_email(email)

def login_valido(login):
    return re.search('^[a-zA-Z0-9_\-.]{5,40}$',login)

def pass_valido(clave):
    return re.search('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])[^\W]{5,40}',clave)