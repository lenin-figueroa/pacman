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
    puntuaciones = db.relationship('Puntuacion', backref='jugador', lazy=True)
    
    @property
    def mejor_puntuacion(self):
        if not self.puntuaciones:
            return 0
        return max(p.puntos for p in self.puntuaciones)

class Puntuacion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    puntos = db.Column(db.Integer, nullable=False)
    fecha = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    jugador_id = db.Column(db.Integer, db.ForeignKey('jugador.id'), nullable=False)

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
        jugador = Jugador.query.filter_by(nombre=nombre, telefono=telefono).first()
        
        if jugador:
            # Si el jugador existe y coinciden nombre y teléfono, iniciar sesión
            session['jugador_id'] = jugador.id
            session['jugador_nombre'] = jugador.nombre
            flash('¡Bienvenido de nuevo!')
            return redirect(url_for('juego'))
        
        # Si no existe el jugador, verificar si el nombre o teléfono están en uso por otro jugador
        jugador_por_nombre = Jugador.query.filter_by(nombre=nombre).first()
        jugador_por_telefono = Jugador.query.filter_by(telefono=telefono).first()
        
        if jugador_por_nombre and jugador_por_nombre.telefono != telefono:
            flash('Este nombre ya está registrado con otro teléfono. Por favor, usa otro nombre.')
            return redirect(url_for('registro'))
        
        if jugador_por_telefono and jugador_por_telefono.nombre != nombre:
            flash('Este teléfono ya está registrado con otro nombre. Por favor, usa otro teléfono.')
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
        flash('Debes registrarte para jugar')
        return redirect(url_for('registro'))
    
    # Verificar que el jugador existe en la base de datos
    jugador = Jugador.query.get(session['jugador_id'])
    if not jugador:
        session.clear()
        flash('Error: Jugador no encontrado. Por favor, regístrate nuevamente.')
        return redirect(url_for('registro'))
    
    return render_template('juego.html', jugador=jugador)

@app.route('/guardar_puntuacion', methods=['POST'])
def guardar_puntuacion():
    if 'jugador_id' not in session:
        return {'success': False, 'error': 'No hay jugador registrado'}
    
    try:
        puntos = request.json.get('puntos')
        if puntos is None:
            return {'success': False, 'error': 'No se recibieron puntos'}
        
        # Convertir puntos a entero para asegurar que sea un número
        puntos = int(puntos)
        
        jugador = Jugador.query.get(session['jugador_id'])
        if not jugador:
            return {'success': False, 'error': 'Jugador no encontrado'}
        
        # Crear nueva puntuación
        puntuacion = Puntuacion(puntos=puntos, jugador_id=jugador.id)
        db.session.add(puntuacion)
        db.session.commit()
        print(f"Puntuación actualizada para {jugador.nombre}: {puntos}")
        
        return {'success': True}
    except Exception as e:
        print(f"Error al guardar puntuación: {str(e)}")
        return {'success': False, 'error': f'Error al guardar puntuación: {str(e)}'}

@app.route('/tabla_posiciones')
def tabla_posiciones():
    # Obtener todos los jugadores y ordenarlos manualmente por mejor_puntuacion
    jugadores = Jugador.query.all()
    jugadores_ordenados = sorted(jugadores, key=lambda j: j.mejor_puntuacion, reverse=True)
    return render_template('tabla_posiciones.html', jugadores=jugadores_ordenados[:10])

@app.route('/admin')
@login_required
def admin_panel():
    # Obtener todos los jugadores y ordenarlos manualmente por mejor_puntuacion
    jugadores = Jugador.query.all()
    jugadores_ordenados = sorted(jugadores, key=lambda j: j.mejor_puntuacion, reverse=True)
    return render_template('admin.html', jugadores=jugadores_ordenados)

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