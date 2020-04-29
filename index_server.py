from flask import Flask, json, request
from flask_restful import Resource, Api
import random

peers = []


api = Flask(__name__)


@api.route('/peers', methods=['GET'])
def get_peers():
        return json.dumps(peers), 200



@api.route('/peers', methods=['POST'])
def post_peer():
    peer = {
        "port" : request.json["port"],
        "id" : request.json["id"],
        "public_key" : request.json["public_key"]}
    peers.append(peer)
    return "", 201



if __name__ == '__main__':
    api.run()