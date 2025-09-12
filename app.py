from mimetypes import init
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(20)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view  = 'login'

#-------------------------
#MODELS
#-------------------------
class User(UserMixin, db.Model):
    id= db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100),unique = True, nullable = False)
    password =  db.Column(db.String(20), nullable = False)
    tasks = db.relationship('Task' , backref='user', lazy=True)

class Task(db.Model):
    id= db.Column(db.Integer,primary_key=True)
    title = db.Column(db.String(150))
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default = 'Pendente')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)

#------------------------------------
# LOGIN MANAGER
# -----------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(init(user_id))

#--------------------------------------
#ROTAS
#--------------------------------------
@app.route("/")
def index():
    return render_template('index.html')

#cadastro de usuários -- CREATE
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        #verificar se ja existe o usuário
        user = User.query.filter_by(email=email).first()
        if user:
            flash('E-mail ja cadastrado!', 'warning')
            return redirect(url_for('register'))
        
        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Cadastro realizado com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

#login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('task'))
        else:
            flash('E-mail ou senha incorretos.', 'danger')
    
    return render_template('login.html')

#logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

#----------------------------------------
# CRIAÇÃO DO BANCO NA PRIMEIRA EXECUÇÃO
# ---------------------------------------
if __name__ == '__main__':
    if not os.path.exists('database.db'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)
 
