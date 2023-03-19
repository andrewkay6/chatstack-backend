from flask import Flask, request, jsonify, session
from flask_socketio import SocketIO,emit, disconnect
from flask_cors import CORS
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
import functools
from flask_session import Session
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
def authenticated_only(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            disconnect()
        else:
            return f(*args, **kwargs)
    return wrapped

@socketio.on("connect")
def connected():

    try:
        print(request.sid)
        print("client has connected")
        emit("connect",{"data": f"id: {request.sid} is connected"})
        
    except Exception as e:
        print("Error:", e)

@socketio.on('send_message')
@authenticated_only
def handle_message(data):
    try:
        print("data from the front end: ",str(data))
        print(request.sid)
        parsedFrontEnd = json.loads(str(data)) 

        add_message_to_db(parsedFrontEnd['message'], session['user_id'])
        emit("data",json.dumps({'message': parsedFrontEnd['message'], 'id' : session['user_id'], 'username' : session['username']}),broadcast=True, exclude_sid=request.sid)
    except Exception as e:
        print("Error:", e)


def add_message_to_db(message, userID):
    query = ("INSERT INTO message_history (messageContents, userID) VALUES (%s, %s);")
    values = (message, userID)
    cursor.execute(query, values)
    cnx.commit()

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

    query =  """
        SELECT * FROM user_info 
        INNER JOIN user_authentication 
        ON user_info.userID = user_authentication.userID
        WHERE username = %s; 
    """
    values = (username,)

    cursor.execute(query, values)
    user = cursor.fetchone()

    print(user)
    if (not user):
        print("NO USER")
        return jsonify({'message': 'Unknown username and password combination.', 'messageType': 'E'})
   
    userInfo = {
        'userID' : user[0],
        'username' : user[1],
        'password' : user[3]
    }
    if userInfo['username'] == username and (bcrypt.checkpw(password.encode('utf8'), userInfo['password'].encode('utf8'))):
        user_model = User()
        user_model.id = userInfo['userID']
        session["username"] = userInfo['username']
        session["user_id"] = userInfo['userID']
        login_user(user_model)
        return jsonify({"message": 'Successfully logged in', 'messageType': 'S'})
    
    return jsonify({'message': 'Unknown username and password combination.', 'messageType': 'E'})

@app.route("/api/create-user", methods=['POST'])
def create_user():
    username = request.json['username']
    password = request.json['password']
    hashed_password = get_hashed_password(password)
    print(password)
    check_username = """
        SELECT username FROM user_info
        WHERE username = %s;
    """

    cursor.execute(check_username, (username,))
    result = cursor.fetchone()

    if (result):
        return jsonify({'message': 'Username already exists', 'messageType': 'E'})


    add_user_authentication = """
        INSERT INTO user_authentication
        (password)
        VALUES (%s);
    """

    cursor.execute(add_user_authentication, (hashed_password,))
    cnx.commit()

    user_id = cursor.lastrowid

    add_user_info = """
        INSERT INTO user_info
        (userID, username)
        VALUES (%s, %s);
    """
    cursor.execute(add_user_info, (user_id, username))
    cnx.commit()


    return jsonify({'message': 'Successfuly created user ' + username, 'messageType': 'S'})


@app.route("/api/getcsrf", methods=["GET"])
def get_csrf():
    token = generate_csrf()
    response = jsonify({"message": "CSRF cookie set"})
    response.headers.set("X-CSRFToken", token)
    return response

@app.route("/api/fetch-message-history", methods=["POST"])
@login_required
def get_message_history():
    
    number_of_rows = 10 #int(request.json["numberOfRows"])
    start_from_id = request.json["startFromID"]

    query = """
        SELECT * from message_history 
        WHERE messageID >= %s LIMIT %s;
    """
    values = (start_from_id, number_of_rows)
    cursor.execute(query, values)

    messages = cursor.fetchall()

    print(messages)

    return jsonify({"messages": messages})



@app.route("/api/getsession")
def get_session():
    if current_user.is_authenticated:
        return jsonify({"login": True})

    return jsonify({"login": False})


def get_hashed_password(password):
    hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
    print(hashed)
    return hashed

    
if __name__ == '__main__':
    socketio.run(app, debug= True,port=5000)