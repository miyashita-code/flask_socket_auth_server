from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_socketio import SocketIO, join_room, leave_room
from flask_cors import CORS

from flask_migrate import Migrate

import threading
import time
import jwt
import datetime
import uuid
import hashlib
import json, os
import requests
from dotenv import load_dotenv

from models import db, UserAuth
from flask import request, jsonify


load_dotenv()



FIREBASE_API_KEY = os.environ.get('FIREBASE_API_KEY')

app = Flask(__name__)
CORS(app)


app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY_FLASK')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False



db.init_app(app)
migrate = Migrate(app, db)

socketio = SocketIO(app, cors_allowed_origins="*")

backend_instances = {}  # ルームIDをキーとするインスタンスの辞書

def sign_in_with_email_and_password(email: str, password: str, api_key=FIREBASE_API_KEY):
    """
    Authenticate user with email and password using Firebase.

    Args:
    email (str): User's email.
    password (str): User's password.
    api_key (str): Firebase API key.

    Returns:
    dict: Response from Firebase authentication.
    error_message (str): Error message if authentication fails.
    """
    url = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
    payload = {
        'email': email,
        'password': password,
        'returnSecureToken': True
    }

    error_message = "通信エラーが発生しました。"
    
    try:
        response = requests.post(f"{url}?key={api_key}", data=payload)
        response.raise_for_status()
        return response.json(), None
    except requests.exceptions.HTTPError as errh:
        error_message = "メールアドレスまたはパスワードが間違っています。"
    except requests.exceptions.ConnectionError as errc:
        pass
    except requests.exceptions.Timeout as errt:
        pass
    except requests.exceptions.RequestException as err:
        pass
    return None, error_message



class BackEndProcess:
    def __init__(self, socketio, room, client_data):
        self.room = room
        self.messages = []
        self.active = True
        self.client_data = client_data
        self.socketio = socketio

    def run(self):
        """
        Run the backend process. Emit instructions based on message length.
        """
        print(f"backend process started : {self.client_data.name}")
        while self.active:
            time.sleep(1)
            message_length = sum(len(m) for m in self.messages)
            self.socketio.emit('message_length', {'length': message_length}, room=self.room)



    def stop(self):
        """ Stop the backend process. """
        self.active = False

    def set_messages(self, message):
        """ Add a message to the message list. """
        self.messages.append(message)

    def set_room(self, room):
        """ Set the room ID. """
        self.room = room

    def get_room(self):
        """ Get the room ID. """
        return self.room


def check_token(token):
    """
    Check if the JWT token is valid.

    Args:
    token (str): JWT token.

    Returns:
    tuple: (is_valid (bool), current_user (UserAuth), error_message (str))
    """
    current_user = None

    if not token:
        return (False, None, 'Token is missing!')

    try:
        data = jwt.decode(token, os.environ.get('SECRET_KEY_JWT'), algorithms=['HS256'])
        current_user = UserAuth.query.filter_by(id=data['user_id']).first()
    except:
        return (False, None, 'Token is invalid!')

    return (True, current_user, None)


@app.route('/')
def index():
    """ Return the welcome message. """
    return 'Hello, this is the Flask-SocketIO server!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle the login process. Show login page on GET request, 
    and handle login logic on POST request.
    """
    if request.method == 'GET':
        return render_template("login.html", msg="")

    email = request.form['email']
    password = request.form['password']


    user, error_message = sign_in_with_email_and_password(email, password)

    if user is None:
        return render_template("login.html", msg=error_message)

    session['usr'] = email
    return redirect(url_for('create_user'))

@app.route("/create_user", methods=['GET'])
def create_user():
    """
    Show the create user page. Redirect to login if the user is not in session.
    """
    usr = session.get('usr')

    if usr is None:
        return redirect(url_for('login'))

    return render_template("create_user.html", usr=usr)

@app.route('/register', methods=['POST'])
def register_user():
    """
    Handle user registration. Create new user and store in database.
    """
    usr = session.get('usr')
    if usr is None:
        return redirect(url_for('login'))

    name = request.form.get('username')
    user_id = str(uuid.uuid4())
    api_key = hashlib.sha256(name.encode()).hexdigest()

    new_user = UserAuth(id=user_id, name=name, api_key=api_key)
    db.session.add(new_user)
    db.session.commit()

    return render_template("display_api_key.html", api_key=api_key, name=name, user_id=user_id)


@app.route('/logout')
def logout():
    """ Handle user logout. Clear session and redirect to login. """
    session.pop('usr', None)
    return redirect(url_for('login'))


@app.route('/api/token', methods=['POST'])
def get_token():
    """
    Generate and return a JWT token for authenticated users.
    """
    api_key = request.headers.get('API-Key')
    user = UserAuth.query.filter_by(api_key=api_key).first()

    if user:
        payload = {
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        token = jwt.encode(payload, os.environ.get('SECRET_KEY_JWT'), algorithm=os.environ.get('JWT_ALGORITHM'))
        return jsonify({'token': token})
    else:
        return jsonify({'message': 'Invalid API Key'}), 401


@socketio.on('connect')
def handle_connect():
    """
    Handle socket connection. Join room and create/update backend process instance.
    """
    token = request.args.get('token')

    is_valid, current_user, error_message = check_token(token)

    if not is_valid:
        return jsonify({'message': error_message}), 403

    print(f"socket connected : {current_user.name}")

    # join room
    room = request.sid
    join_room(room)

    # Manage backend process instance for the connected user
    if current_user.id not in backend_instances:
        bp = BackEndProcess(socketio, room, current_user)
        backend_instances[current_user.id] = bp
        threading.Thread(target=bp.run).start()
    else:
        backend_instances[current_user.id].set_room(room)


@socketio.on('disconnect')
def handle_disconnect():
    """
    Handle socket disconnection. Leave room and stop backend process.
    """
    room = request.sid
    leave_room(room)

    for user_id, bp in backend_instances.items():
        if bp.get_room() == room:
            bp.stop()
            del backend_instances[user_id]
            break

@socketio.on('message')
def handle_message(data):
    """
    Handle chat messages. Validate token and process message.
    """
    token = data['token']
    is_valid, current_user, error_message = check_token(token)

    if not is_valid:
        return jsonify({'message': error_message}), 403

    if current_user.id in backend_instances:
        print(f"message received : {data['message']}, room : {request.sid}, bg : {backend_instances}")
        backend_instances[current_user.id].set_messages(data['message'])

if __name__ == '__main__':
    socketio.run(app, debug=True, port=int(os.environ.get('PORT')))
