from flask import Flask, render_template, redirect, session, flash, request
from forms import Login, Registro
from markupsafe import escape
import os
from utils import login_valido, pass_valido, email_valido
from werkzeug.security import check_password_hash, generate_password_hash
from db import seleccion, accion

app = Flask(__name__)

app.secret_key = os.urandom(24)

@app.route('/')
@app.route('/login/')

@app.route('/inicio/')
def inicio():
    """ V6. Incluye TLS y HTTPS """
    frm=Login()
    return render_template('login.html', prueba=frm, titulo='Iniciar Sesión')

@app.route('/login/', methods=['POST'])
def login():
    """ V6. Inlcuye TLS y HTTPS """
    frm=Login()
    # Será un código con mitigación de riesgo
    usu = escape(frm.usu.data.strip())
    pwd = escape(frm.cla.data.strip())
    # Preparar la consulta - No paramétrica
    sql = f"SELECT id, nombre, email, clave FROM usuario WHERE usuario='{usu}'"
    # Ejecutar la consulta
    res = seleccion(sql)
    # Procesar los resultados
    if len(res)==0:
        flash('ERROR: Usuario o contraseña invalidos')
        return render_template('login.html', prueba=frm, titulo='Iniciar Sesión')
    else:
        # Recupero la clave almacenada en la base de datos - cifrada
        cbd = res[0][3]
        # Comparo contra la clave suminstrada por el usuario
        if check_password_hash(cbd,pwd):
            # Se guardarán los datos del usuario en una variable de sesion
            session.clear()
            session['id'] = res[0][0]
            session['nom'] = res[0][1]
            session['usr'] = usu
            session['cla'] = pwd
            session['ema'] = res[0][2]
            return redirect('/habitaciones/')
        else:
            flash('ERROR: Usuario o contraseña invalidos')
            return render_template('login.html', prueba=frm, titulo='Iniciar Sesión')

@app.route('/logout/', methods=['GET','POST'])
def logout():
    session.clear()
    return redirect('/')

@app.route('/registro', methods=['GET', 'POST'])
def register():
    """ V6. Inlcuye TLS y HTTPS """
    frm = Registro()
    if request.method == 'GET':
        return render_template('registro.html', prueba=frm, titulo='Registro de datos')
    else:
        # Recuperar los datos del formulario
        # Esta forma permite validar las entradas
        nom = escape(request.form['nom'])
        usu = escape(request.form['usu'])
        ema = escape(request.form['ema'])
        cla = escape(request.form['cla'])
        ver = escape(request.form['ver'])
        # Validar los datos
        swerror = False
        if nom==None or len(nom)==0:
            flash('ERROR: Debe suministrar un nombre de usuario')
            swerror = True
        if usu==None or len(usu)==0 or not login_valido(usu):
            flash('ERROR: Debe suministrar un usuario válido ')
            swerror = True
        if ema==None or len(ema)==0 or not email_valido(ema):
            flash('ERROR: Debe suministrar un email válido')
            swerror = True
        if cla==None or len(cla)==0 or not pass_valido(cla):
            flash('ERROR: Debe suministrar una clave válida')
            swerror = True
        elif ver==None or len(ver)==0 or not pass_valido(ver):
            flash('ERROR: Debe suministrar una verificación de clave válida')
            swerror = True
        if cla!=ver:
            flash('ERROR: La clave y la verificación no coinciden')
            swerror = True
        if not swerror:
            # Preparar el query -- Paramétrico
            sql = "INSERT INTO usuario(nombre, usuario, email, clave) VALUES(?, ?, ?, ?)"
            # Ejecutar la consulta
            pwd = generate_password_hash(cla)
            res = accion(sql, (nom, usu, ema, pwd))
            # Proceso los resultados
            if res==0:
                flash('ERROR: No se pudieron almacenar los datos, reintente')
            else:
                flash('INFO: Los datos fueron almacenados satisfactoriamente')
        return render_template('registro.html', prueba=frm, titulo='Registro de datos')

@app.route('/dashboard',methods=["GET","POST"])
def dashboard():
    return render_template('dashboard.html')

@app.route('/ubicacion',methods=["GET"])
def ubicacion():
    return render_template('ubicacion.html')

@app.route('/habitaciones/',methods=["GET"])
def habitaciones():
    return render_template('habitaciones.html')

@app.route('/comentarios',methods=["GET","POST"])
def comentarios():
    return render_template('comentarios.html')

@app.route('/pago',methods=["GET"])
def pago():
    return render_template('pago.html')

if __name__ == '__main__':
    app.run(host='127.0.0.2', port=8000, debug=True)
 