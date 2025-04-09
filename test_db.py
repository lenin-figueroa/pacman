from app import app, db

def test_connection():
    try:
        with app.app_context():
            # Intenta crear las tablas
            db.create_all()
            print("✅ Conexión exitosa a PostgreSQL")
            print("✅ Las tablas se crearon correctamente")
            
            # Intenta hacer una consulta simple
            from app import Jugador
            jugadores = Jugador.query.all()
            print(f"✅ Consulta exitosa. Número de jugadores: {len(jugadores)}")
            
    except Exception as e:
        print("❌ Error al conectar con la base de datos:")
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    test_connection() 