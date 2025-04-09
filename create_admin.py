from app import app, db, Usuario
from flask_login import login_user

def create_admin_user(nombre, telefono):
    with app.app_context():
        # Verificar si el usuario ya existe
        usuario = Usuario.query.filter_by(telefono=telefono).first()
        
        if usuario:
            # Si el usuario existe, actualizarlo a admin
            usuario.es_admin = True
            db.session.commit()
            print(f"Usuario {nombre} actualizado a administrador")
        else:
            # Si no existe, crear nuevo usuario admin
            usuario = Usuario(nombre=nombre, telefono=telefono, es_admin=True)
            db.session.add(usuario)
            db.session.commit()
            print(f"Usuario administrador {nombre} creado exitosamente")

if __name__ == "__main__":
    nombre = input("Ingrese el nombre del administrador: ")
    telefono = input("Ingrese el teléfono del administrador: ")
    create_admin_user(nombre, telefono) 