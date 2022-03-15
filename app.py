from flask import Flask, jsonify, make_response, render_template, request
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
import jwt
import datetime
import os

app = Flask(__name__)
dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, 'routerinfo.db') 
app.config['SECRET_KEY']='004f2af45d3a4e161a7dd2d17fdae47f'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///C:\\f_app\\routerinfo.db' #Absolute path of db accordng to the respective system
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
 
db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


class router_details(db.Model):
   sap_id = db.Column(db.String(18), primary_key=True)
   user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
   hostname = db.Column(db.String(14))
   loopback = db.Column(db.String(20))
   mac_address = db.Column(db.String(17))
   isdeleted = db.Column(db.Boolean)

# db.create_all() 
# Note: Run the code until the above line and then comment it. To check the table created, run the following commands:
   # sqlite3 routerinfo.db
   # .tables

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/register', methods=['POST'])
def signup_user():  
    data = request.get_json()  

    hashed_password = generate_password_hash(data['password'], method='sha256')
 
    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False) 
    db.session.add(new_user)  
    db.session.commit()    

    return jsonify({'message': 'registeration successfully'})

@app.route('/login', methods=['POST'])  
def login_user(): 
    auth = request.authorization   

    if not auth or not auth.username or not auth.password:  
        return make_response('could not verify', 401, {'Authentication': 'login required"'})    

    user = Users.query.filter_by(name=auth.username).first()   
     
    if check_password_hash(user.password, auth.password):

        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
        return jsonify({'token' : token}) 

    return make_response('could not verify',  401, {'Authentication': '"login required"'})

@app.route('/router', methods=['POST'])
@token_required
def create_router_details(current_user):
   
    data = request.get_json() 

    new_books = router_details(sap_id=str(uuid.uuid4()), hostname=data['hostname'], loopback=data['loopback'], mac_address=data['macaddr'], user_id=current_user.id)  
    db.session.add(new_books)   
    db.session.commit()   

    return jsonify({'message' : 'New Router entry added'})

@app.route('/routers', methods=['GET'])
@token_required
def get_routers(current_user):

    routers = router_details.query.filter_by(user_id=current_user.id, isdeleted=None).all()

    output = []
    for router in routers:
        router_data = {}
        router_data['sapid'] = router.sap_id
        router_data['hostname'] = router.hostname
        router_data['loopback'] = router.loopback
        router_data['macaddr'] = router.mac_address
        output.append(router_data)

    return jsonify({'list_of_routers' : output})

@app.route('/routers/<loopback>', methods=['DELETE'])
@token_required
def delete_router(current_user, loopback):
    router_data = router_details.query.filter_by(loopback=loopback, isdeleted=None, user_id=current_user.id).first()
    if not router_data:
        return jsonify({'message': 'Router does not exist'})
    router_data.isdeleted = 1
    db.session.commit()
    return jsonify({'message': 'Router entry deleted'})

@app.route('/routers/<loopback>', methods=['PUT'])
@token_required
def update_router(current_user, loopback):
    data = request.get_json() 
    router_data = router_details.query.filter_by(loopback=loopback, isdeleted=None, user_id=current_user.id).first()
    if not router_data:
        return jsonify({'message': 'Router does not exist'})
    router_data.hostname = data['hostname']    
    router_data.mac_address = data['macaddr']
    db.session.commit()
    return jsonify({'message': 'Router entry Updated'})

@app.route("/")
def index():
  return render_template("index.html")


if  __name__ == '__main__':  
     app.run(debug=True)
