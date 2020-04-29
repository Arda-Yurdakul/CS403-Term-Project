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
        "public_key": verify_key.export_key(format='OpenSSH')}
    res = requests.post(endpoint, json=peer)
    print(str(id) + "Done")
    peer["list"] = requests.get(endpoint).json()
    peer["random_number"] = random.getrandbits(256)
    ports = []
    for i in range(n):
        ports.append(peer["list"][i]["port"])

    context = zmq.Context()
    for port in ports:
        if port.__eq__(MyPORT):
            continue
        else:
            num_sender = context.socket(zmq.PUSH)
            num_sender.bind("tcp://127.0.0.1:" + str(MyPORT))
            num_sender.connect("tcp://127.0.0.1:" + str(port))

            num_receiver = context.socket(zmq.PULL)
            num_receiver.bind("tcp://127.0.0.1:" + str(port))
            num_receiver.connect("tcp://127.0.0.1:" + str(MyPORT))

            num_sender.send_string(str(peer["random_number"]))
            res = num_receiver.recv_string()
            num_receiver.close()
            num_sender.close()


if __name__ == "__main__":
    procs = []
    for i in range(n):
        proc = Process(target=peer_func, args=(i,))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()
