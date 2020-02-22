from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
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