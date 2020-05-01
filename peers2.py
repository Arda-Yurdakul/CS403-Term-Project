import random
import sys
import threading
import time
from multiprocessing import Process

import zmq

import requests
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Pyro4.util import json

n = int(sys.argv[2])
t = int(sys.argv[4])
endpoint = "http://localhost:5000/peers"


def peer_func(id):
    mutex = threading.Lock()
    ID = id
    MyPORT = random.randrange(1300, 60000)
    sign_key = ECC.generate(curve='NIST P-256')
    verify_key = sign_key.public_key()
    peer = {
        "id": ID,
        "port": MyPORT,
        "public_key": verify_key.export_key(format='OpenSSH'),
        "random_numbers_list": []}
    res = requests.post(endpoint, json=peer)

    peer["list"] = requests.get(endpoint).json()
    peer["random_number"] = random.getrandbits(256)
    ports = []
    messages = []
    for i in range(n):
        ports.append(peer["list"][i]["port"])
    
    context = zmq.Context()
    num_sender = context.socket(zmq.PUB)
    num_sender.bind("tcp://127.0.0.1:" + str(MyPORT))
    
    time.sleep(1)

    contexts = []
    for k in range(n):
        context2 = zmq.Context()
        num_receiver = context2.socket(zmq.SUB)
        num_receiver.connect("tcp://127.0.0.1:" + str(ports[(id + k) % n]))
        num_receiver.subscribe("")
        contexts.append(num_receiver)
       
    time.sleep(1)

    num_sender.send_string(str(peer["random_number"]))
    
    time.sleep(1)

    for k in range(n):
        res = contexts[k].recv_string()
        messages.append(res)
    
    if id == 0 or id == 18:
        print(messages)


if __name__ == "__main__":
    procs = []
    for i in range(n):
        proc = Process(target=peer_func, args=(i,))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()

