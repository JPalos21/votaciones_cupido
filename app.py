from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import os
import hashlib


app = Flask(__name__)
app.secret_key = 'super-secreto' # para las sesiones

#hashed = generate_password_hash("AdminCupido123")
#print("Contraseña ")
#print (hashed)

ADMIN_USER = 'admin'
ADMIN_PASS = 'scrypt:32768:8:1$xPxzJirs8i7mNMjS$069ca10664d66688e931b97417d822be99173dcc19f7f4eee20620c9cd66be83663d424d31269c005fd2f19d7c4d883a489884a8f426db22400a56f30f65b7d5'
colores = ['#E81E1E', '#2196F3', '#4CAF50', '#FF9800', '#9C27B0']

# Configuracion de la base de datos
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Render
db_url = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite' + os.path.join(BASE_DIR, 'votos.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL').replace("postgres://", "postgresql://")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo
class Pregunta(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    texto = db.Column(db.String(200), nullable = False)
    activa = db.Column(db.Boolean, default = True)

    opciones = db.relationship('Opcion', backref='pregunta', cascade="all, delete-orphan")

class Opcion(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    texto = db.Column(db.String(100), nullable = False)
    pregunta_id = db.Column(db.Integer, db.ForeignKey('pregunta.id'), nullable = False)

class Voto(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.String(64), nullable = False)
    opcion_id = db.Column(db.Integer, db.ForeignKey('opcion.id'), nullable=False)
    ip_hash = db.Column(db.String(64))

    opcion = db.relationship('Opcion')

# Si no existe creamos la base de datos
with app.app_context():
    db.create_all()

# Función para hashear la ip
def hash_ip(ip):
    return hashlib.sha256(ip.encode()).hexdigest()

@app.before_request
def identificar_usuario():
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
        # print(f'Nuevo usuario: {session["user_id"]}')
    # else:
    #     print(f'Usuario existente: {session["user_id"]}')

@app.route('/', methods=['GET'])
def index():
    pregunta = Pregunta.query.filter_by(activa = True).first()
    opciones = pregunta.opciones if pregunta else []
    opciones_coloreadas = [(opcion, colores[i % len(colores)]) for i, opcion in enumerate(opciones)]

    votos = Voto.query.all()
    total = len(votos)
    conteo = {o.id: 0 for o in opciones}
    for v in votos:
        if v.opcion_id in conteo:
            conteo[v.opcion_id] += 1

    porcentajes = {
        o.id: round((conteo[o.id] / total) * 100, 1) if total > 0 else 0
        for o in opciones
    }
    
    user_id = session.get('user_id')
    voto = Voto.query.filter_by(user_id = user_id).first() if user_id else None

    ip = request.remote_addr
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()
    ip_voto = Voto.query.filter_by(ip_hash=ip_hash).first()

    voto_mostrar = voto if voto else ip_voto

    if not pregunta:
        return "No hay pregunta activa en este momento."

    return render_template('index.html', pregunta=pregunta, opciones=opciones, porcentajes=porcentajes, voto=voto_mostrar, user_id=user_id,
                           opciones_coloreadas=opciones_coloreadas, conteo=conteo)
    
@app.route('/vote', methods=['POST'])
def vote():
    ip = request.remote_addr
    ip_hash = hash_ip(ip)

    user_id = session.get('user_id')
    if not user_id:
        session['user_id'] = str(uuid.uuid4())
        user_id = session['user_id']

    voto_existente = Voto.query.filter_by(ip_hash=ip_hash).first()
    if voto_existente:
        flash("Ya has votado desde esta dirección")
        return redirect('/')
    
    opcion_id = request.form.get('opcion_id')
    opcion = Opcion.query.get(opcion_id)

    if opcion:
        nuevo_voto = Voto(user_id=user_id, opcion_id=opcion.id, ip_hash=ip_hash)
        db.session.add(nuevo_voto)
        db.session.commit()
    
    return redirect('/')

@app.route('/login-admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        usuario = request.form['usuario']
        clave = request.form['clave']
        if usuario == ADMIN_USER and check_password_hash(ADMIN_PASS, clave):
            session['admin'] = True
            return redirect('/votaciones-admin')
        else:
            flash('Credenciales incorrectas')
    return render_template('login_admin.html')

@app.route('/logout-admin')
def logout_admin():
    session.pop('admin', None)
    return redirect('/')

@app.route('/reiniciar-base')
def reset_db():
    db.drop_all()
    db.create_all()
    return redirect('/votaciones-admin')

@app.route('/votaciones-admin', methods=['GET', 'POST'])
def admin():
    if not session.get('admin'):
        return redirect('/login-admin')
    
    if request.method == 'POST':
        texto_pregunta = request.form.get('pregunta')
        opciones = [request.form.get(f'opcion{i}') for i in range(1,5)]
        opciones = [o for o in opciones if o]

        # Desactivo la anterior pregunta
        Pregunta.query.update({Pregunta.activa: False})

        nueva_pregunta = Pregunta(texto = texto_pregunta, activa = True)
        db.session.add(nueva_pregunta)
        db.session.flush() # Obtenemos el id

        for texto in opciones:
            db.session.add(Opcion(texto=texto, pregunta_id=nueva_pregunta.id))

        db.session.commit()
        flash('Pergunta actualizada correctamente')

    return render_template('admin.html')

if __name__ == '__main__':
    app.run(debug=True)
