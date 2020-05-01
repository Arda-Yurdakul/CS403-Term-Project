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
        time.sleep(0.5)
        num_receiver.subscribe("")
        contexts.append(num_receiver)

    time.sleep(1)

    num_sender.send_string(str(peer["random_number"]))



    for k in range(n):
        res = int(contexts[k].recv_string())
        messages.append(res)


    selection = 0

    for message in messages:
        selection = selection ^ message
        time.sleep(0.01)


    d = SHA3_256.new(selection.to_bytes(32, byteorder='big'))
    for k in range(t - 1):
        d = SHA3_256.new(d.digest())

    selection = int.from_bytes(d.digest(), "big") % n
    file = ""
    for message in messages:
        file += str(message) + "\n"
    file += str(selection) + "\n"


    time.sleep(1)
    signer = DSS.new(sign_key, 'fips-186-3')
    h = SHA3_256.new(file.encode('utf-8'))
    signature = signer.sign(h)
    file += str(int.from_bytes(signature, "big")) + "\n"
    file += verify_key.export_key(format='OpenSSH')

    time.sleep(1)
    file_writer = open("sample_election_" + str(id) + ".log", "w")
    file_writer.write(file)
    file_writer.close()


if __name__ == "__main__":
    procs = []
    for i in range(n):
        proc = Process(target=peer_func, args=(i,))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()
