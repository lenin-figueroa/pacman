from app import app, db, Admin

def create_admin_user(usuario, password):
    with app.app_context():
        # Verificar si el administrador ya existe
        admin = Admin.query.filter_by(usuario=usuario).first()
        
        if admin:
            # Si el administrador existe, actualizar la contraseña
            admin.set_password(password)
            db.session.commit()
            print(f"Administrador {usuario} actualizado exitosamente")
        else:
            # Si no existe, crear nuevo administrador
            admin = Admin(usuario=usuario)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            print(f"Administrador {usuario} creado exitosamente")

if __name__ == "__main__":
    usuario = input("Ingrese el nombre de usuario del administrador: ")
    password = input("Ingrese la contraseña del administrador: ")
    create_admin_user(usuario, password) 