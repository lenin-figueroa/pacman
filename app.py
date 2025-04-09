from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta_aqui'  # Cambiar en producción
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pacman.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelos
class Jugador(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), unique=True, nullable=False)
    telefono = db.Column(db.String(20), unique=True, nullable=False)
    puntuacion = db.Column(db.Integer, default=0, nullable=False)
    fecha_puntuacion = db.Column(db.DateTime, nullable=True)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# Rutas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        password = request.form['password']
        
        admin = Admin.query.filter_by(usuario=usuario).first()
        
        if admin and admin.check_password(password):
            login_user(admin)
            return redirect(url_for('admin_panel'))
        else:
            flash('Usuario o contraseña incorrectos')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        telefono = request.form['telefono']
        
        # Buscar si ya existe un jugador con ese nombre o teléfono
        jugador_por_nombre = Jugador.query.filter_by(nombre=nombre).first()
        jugador_por_telefono = Jugador.query.filter_by(telefono=telefono).first()
        
        if jugador_por_nombre:
            flash('Este nombre ya está registrado. Por favor, usa otro nombre.')
            return redirect(url_for('registro'))
        
        if jugador_por_telefono:
            flash('Este teléfono ya está registrado. Por favor, usa otro teléfono.')
            return redirect(url_for('registro'))
        
        # Si no existe, crear nuevo jugador
        jugador = Jugador(nombre=nombre, telefono=telefono)
        db.session.add(jugador)
        db.session.commit()
        flash('¡Registro exitoso! ¡A jugar!')
        
        # Guardar el ID del jugador en la sesión
        session['jugador_id'] = jugador.id
        session['jugador_nombre'] = jugador.nombre
        
        return redirect(url_for('juego'))
    
    return render_template('registro.html')

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/juego')
def juego():
    if 'jugador_id' not in session:
        return redirect(url_for('registro'))
    return render_template('juego.html')

@app.route('/guardar_puntuacion', methods=['POST'])
def guardar_puntuacion():
    if 'jugador_id' not in session:
        return {'success': False, 'error': 'No hay jugador registrado'}
    
    puntos = request.json.get('puntos')
    if puntos is not None:
        jugador = Jugador.query.get(session['jugador_id'])
        if jugador and puntos > jugador.puntuacion:
            jugador.puntuacion = puntos
            jugador.fecha_puntuacion = datetime.utcnow()
            db.session.commit()
        return {'success': True, 'redirect': url_for('tabla_posiciones')}
    return {'success': False}

@app.route('/tabla_posiciones')
def tabla_posiciones():
    # Obtener los 10 mejores jugadores
    mejores_jugadores = Jugador.query.order_by(Jugador.puntuacion.desc()).limit(10).all()
    return render_template('tabla_posiciones.html', jugadores=mejores_jugadores)

@app.route('/admin')
@login_required
def admin_panel():
    jugadores = Jugador.query.order_by(Jugador.puntuacion.desc()).all()
    return render_template('admin.html', jugadores=jugadores)

# Función para crear un administrador
def create_admin(usuario, password):
    with app.app_context():
        admin = Admin.query.filter_by(usuario=usuario).first()
        if not admin:
            admin = Admin(usuario=usuario)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            print(f"Administrador {usuario} creado exitosamente")
        else:
            print(f"El administrador {usuario} ya existe")

if __name__ == '__main__':
    with app.app_context():
        # Forzar la recreación de la base de datos
        db.drop_all()
        db.create_all()
        # Crear un administrador por defecto si no existe
        create_admin('admin', 'admin123')
    app.run(debug=True) 