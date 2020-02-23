from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import numpy
import tensorflow as tf
import requests
import subprocess
import json

app = Flask(__name__)
api = Api(app)

client = MongoClient('mongodb://db:27017')
db = client.imageRecognition
users = db["users"]

def user_exists(username):
    return users.find({
        "username":username
    }).count()!=0

class Register(Resource):
    def post(self):
        posted_data = request.get_json()
        username = posted_data["username"]
        password = posted_data["password"]
        
        if user_exists(username):
            ret_json = {
                "status":301,
                "msg":"Invalid Username"
            }
            return jsonify(ret_json)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert({
            "username":username,
            "password":hashed_pw,
            "tokens":4
        })

        return generate_return_dictionary(200,"You successfully signed up for this API")

def generate_return_dictionary(status,msg):
    ret_json = {
        "status":status,
        "msg":msg
    }
    return ret_json

def verify_pw(username, password):
    if not user_exists(username):
        return False
    hashed_pw = users.find({
        "username":username
    })[0]["password"]

    return bcrypt.hashpw(password.encode('utf8'),hashed_pw)==hashed_pw

def verify_credentials(username, password):
    if not user_exists(username):
        return generate_return_dictionary(301,"Invalid Username"),True
    correct_pw = verify_pw(username,password)
    if not correct_pw:
        return generate_return_dictionary(302,"Invalid Password"),True
    return None,False

class Classify(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["password"]
        url      = posted_data["url"]

        #TODO
        ret_json, error = verify_credentials(username,password)
        if error:
            return jsonify(ret_json)

        tokens = users.find({
            "username":username
        })[0]["tokens"]

        #TODO
        if tokens<=0:
            return jsonify(generate_return_dictionary(303,"Not enough tokens!"))

        r = requests.get(url)
        ret_json = {}

        with open("temp.jpg","wb") as f:
            f.write(r.content)
            proc = subprocess.Popen('python classify_image.py --model_dir=. --image_file=./temp.jpg', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            proc.communicate()[0]
            proc.wait()
            with open('text.txt') as g:
                ret_json = json.load(g)

        users.update({
            "username":username
        },{
            "$set":{
                "tokens":tokens-1
            }
        })
        
        return ret_json

class Refill(Resource):
    def post(self):
        posted_data = request.get_json()
        username = posted_data["username"]
        password = posted_data["admin_pw"]
        amount   = posted_data["amount"]

        if not user_exists(username):
            return jsonify(generate_return_dictionary(301,"Invalid Username"))
        
        correct_pw = "abc123"

        if not password == correct_pw:
            return jsonify(generate_return_dictionary(304,"Invalid Administrator Password"))

        users.update({
            "username":username,
        },{
            "$set":{
                "tokens":amount
            }
        })

        return jsonify(generate_return_dictionary(200,"Refilled successfully"))

api.add_resource(Register,'/register')
api.add_resource(Classify,'/classify')
api.add_resource(Refill,'/refill')

if __name__=="__main__":
    app.run(host='0.0.0.0')