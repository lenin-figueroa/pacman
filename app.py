from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta_aqui'  # Cambiar en producción
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pacman.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelos
class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    telefono = db.Column(db.String(20), nullable=False)
    es_admin = db.Column(db.Boolean, default=False)
    puntuaciones = db.relationship('Puntuacion', backref='usuario', lazy=True)

class Puntuacion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    puntos = db.Column(db.Integer, nullable=False)
    fecha = db.Column(db.DateTime, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# Rutas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        telefono = request.form['telefono']
        
        if Usuario.query.filter_by(telefono=telefono).first():
            flash('Este número de teléfono ya está registrado')
            return redirect(url_for('registro'))
        
        usuario = Usuario(nombre=nombre, telefono=telefono)
        db.session.add(usuario)
        db.session.commit()
        
        login_user(usuario)
        return redirect(url_for('juego'))
    
    return render_template('registro.html')

@app.route('/juego')
@login_required
def juego():
    return render_template('juego.html')

@app.route('/guardar_puntuacion', methods=['POST'])
@login_required
def guardar_puntuacion():
    puntos = request.json.get('puntos')
    if puntos is not None:
        puntuacion = Puntuacion(puntos=puntos, usuario_id=current_user.id)
        db.session.add(puntuacion)
        db.session.commit()
        return {'success': True}
    return {'success': False}

@app.route('/admin')
@login_required
def admin():
    if not current_user.es_admin:
        flash('No tienes permiso para acceder a esta página')
        return redirect(url_for('index'))
    
    puntuaciones = Puntuacion.query.order_by(Puntuacion.puntos.desc()).all()
    return render_template('admin.html', puntuaciones=puntuaciones)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 