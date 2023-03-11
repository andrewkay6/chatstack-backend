from flask import Flask, request, jsonify
from flask_socketio import SocketIO,emit
from flask_cors import CORS
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf.csrf import CSRFProtect, generate_csrf
import json
from dotenv import load_dotenv
import os
import mysql.connector
import bcrypt


app = Flask(__name__)

socketio = SocketIO(app,cors_allowed_origins="*")

load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
SECRET_KEY = os.getenv("SECRET_KEY")

app.config['SECRET_KEY'] = SECRET_KEY

app.config.update(
    DEBUG=True,
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",

)

cors = CORS(
    app,
    resources={r"/*":{"origins":"*"}},
    expose_headers=["Content-Type", "X-CSRFToken"],
    supports_credentials=True,
    )
cnx = mysql.connector.connect(user=DB_USER, password=DB_PASSWORD, host=DB_HOST, database=DB_NAME)
cursor = cnx.cursor()


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"


class User(UserMixin):
    ...

def get_user(user_id):
    query = "SELECT * FROM user_authentication WHERE userID = %s"
    values = (user_id,)

    cursor.execute(query, values)
    result = cursor.fetchone()
    return result

@login_manager.user_loader
def user_loader(id):
    user = get_user(id)
    if user:
        user_model = User()
        user_model.id = user[0]
        return user_model
    return None

@socketio.on("connect")
def connected():
    try:
        print(request.sid)
        print("client has connected")
        emit("connect",{"data": f"id: {request.sid} is connected"})
        
    except Exception as e:
        print("Error:", e)

@socketio.on('send_message')
def handle_message(data):
    try:
        print("data from the front end: ",str(data))
        print(request.sid)
        parsedFrontEnd = json.loads(str(data)) 
        emit("data",{'data': json.dumps(parsedFrontEnd), 'id' : request.sid},broadcast=True, exclude_sid=request.sid)
    except Exception as e:
        print("Error:", e)

@socketio.on("disconnect")
def disconnected():
    try:
        print("user disconnected" + str(request.sid))
        emit("disconnect",f"user {request.sid} disconnected",broadcast=True)
    except Exception as e:
        print("Error:", e)


@app.route("/api/login", methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']

    query = "SELECT * FROM user_authentication WHERE username = %s"
    values = (username,)

    cursor.execute(query, values)
    user = cursor.fetchone()
    if (not user):
        print("NO USER")
        return jsonify({'message': 'no username found'})
   
    
    if user[1] == username and (bcrypt.checkpw(password.encode('utf8'), user[2].encode('utf8'))):
        user_model = User()
        user_model.id = user[0]

        login_user(user_model)
        return jsonify({"login": True})
    
    return jsonify({"login": False})

@app.route("/api/create-user", methods=['POST'])
def create_user():
    username = request.json['username']
    password = request.json['password']

    hashed_password = get_hashed_password(password)
    query = "INSERT INTO user_authentication (username, password) VALUES (%s, %s)"
    values = (username, hashed_password)

    try:
        cursor.execute(query, values)
        cnx.commit()
        response = {'message': 'User created successfully', 'messageType': 'S'}
    except mysql.connector.Error as error:
        if error.errno == mysql.connector.errorcode.ER_DUP_ENTRY:
            response = {'message': 'Username already exists'}
        else:
            response = {'message': 'Unexpected error occurred'}

        response['messageType'] = 'E'
    return json.dumps(response)


@app.route("/api/getcsrf", methods=["GET"])
def get_cstf():
    token = generate_csrf()
    response = jsonify({"message": "CSRF cookie set"})
    response.headers.set("X-CSRFToken", token)
    return response

@app.route("/api/data")
@login_required
def get_data():
    ""

@app.route("/api/getsession")
def get_session():
    if current_user.is_authenticated:
        return jsonify({"login": True})

    return jsonify({"login": False})

@app.route("/api/ping")
def ping():
    return jsonify({"message": "ping"})

def get_hashed_password(password):
    hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

    return hashed

    
if __name__ == '__main__':
    socketio.run(app, debug= True,port=5000)