import random
import string
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
ell = int(sys.argv[8])
r = int(sys.argv[6])

endpoint = "http://localhost:5000/peers"
tolerance = (n - 1)//3


def findPublicKey(peers, pid):
    for peer in peers:
        if peer["id"] == pid:
            return peer["public_key"]


def peer_func(id):
    mutex = threading.Lock()
    ID = random.randint(0, 2 ** 24 - 1)
    MyPORT = random.randrange(1300, 60000)
    sign_key = ECC.generate(curve='NIST P-256')
    verify_key = sign_key.public_key()
    pid = ID
    id = ID
    peer = {
        "id": ID,
        "port": MyPORT,
        "public_key": verify_key.export_key(format='OpenSSH'),
        "random_numbers_list": []}
    res = requests.post(endpoint, json=peer)

    peer["list"] = requests.get(endpoint).json()
    peer_list = peer["list"]
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

    found = False
    messages = sorted(messages)
    selection = int.from_bytes(d.digest(), "big") % pow(2, 24)
    for i in range(n):
        if selection >= peer["list"][i]["id"]:
            continue
        else:
            found = True
            selection = peer["list"][i]["id"]

    if found == False:
        selection = messages[0]
        if peer["random_number"] == selection:
            selection = ID

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
    file_writer = open("election_" + str(pid) + ".log", "w")
    file_writer.write(file)
    file_writer.close()


    num_sender.close()


    if pid == selection:
        public_keys = {}
        for p in peer_list:
            public_keys[p["id"]] = p["public_key"]
        json.dump(public_keys, open("publickeys.txt", 'w'))

        h_prev = SHA3_256.new("".encode('utf-8'))

        for k in range(r):
            receiver_socket = context.socket(zmq.PULL)
            receiver_socket.bind("tcp://127.0.0.1:" + str(MyPORT))
            print("a")
            block = ""
            for m in range(ell):
                tau = "".join([random.choice(string.ascii_letters + string.digits) for _ in range(64)])
                block += (tau + "\n")
            print("b")
            h = SHA3_256.new(block.encode('utf-8') + h_prev.digest())
            signature = signer.sign(h)
            signature = {'pid': pid, 'signature': str(int.from_bytes(signature, "big")), "block": block}
            for p in peer_list:
                if p["id"] != id:
                    sender_socket = context.socket(zmq.PUSH)
                    sender_socket.connect("tcp://127.0.0.1:"+ str(p["port"]))
                    sender_socket.send_json(signature)
                    time.sleep(0.5)
                    sender_socket.disconnect("tcp://127.0.0.1:" + str(p["port"]))
            print("c")
            block_signatures = [json.dumps({"pid": pid, "signature": signature["signature"]})]
            
            time.sleep(0.5)

            print("d")
            for l in range(n - 1):
                try:
                    new_signature = receiver_socket.recv_json()
                    verifier = DSS.new(ECC.import_key(findPublicKey(peer_list, new_signature["pid"])), 'fips-186-3')
                    h_block = SHA3_256.new(new_signature["block"].encode('utf-8') + h_prev.digest())
                    actual_signature = int(new_signature['signature']).to_bytes(64, byteorder='big')
                    verifier.verify(h_block, actual_signature)
                    block_signatures.append(json.dumps({"pid": new_signature["pid"], "signature":
                        new_signature["signature"]}))

                except ValueError:
                    print("Value Error Pid:", pid, "block", k)

            print("Process:", pid, "Block:", k, "Total has:", len(block_signatures))
            if len(block_signatures) > (2 * tolerance):
                file_writer = open("block_" + str(pid) + "_" + str(k) + ".log", "w")
                file_writer.write(block)
                file_writer.write(str(block_signatures).replace("\'", ""))

            receiver_socket.unbind("tcp://127.0.0.1:" + str(MyPORT))
            h_prev = h
            time.sleep(0.5)
    else:
        h_prev = SHA3_256.new("".encode('utf-8'))
        for k in range(r):
            receiver_socket = context.socket(zmq.PULL)
            receiver_socket.bind("tcp://127.0.0.1:" + str(MyPORT))
            block_signatures = []
            block = ""
            for l in range(n - 1):
                try:
                    new_signature = receiver_socket.recv_json()
                    verifier = DSS.new(ECC.import_key(findPublicKey(peer_list, new_signature["pid"])), 'fips-186-3')
                    h_block = SHA3_256.new(new_signature["block"].encode('utf-8') + h_prev.digest())
                    actual_signature = int(new_signature['signature']).to_bytes(64, byteorder='big')
                    verifier.verify(h_block, actual_signature)
                    block_signatures.append(
                        json.dumps({"pid": new_signature["pid"], "signature": new_signature["signature"]}))
                    if new_signature["pid"] == selection:
                        h = SHA3_256.new(new_signature["block"].encode('utf-8') + h_prev.digest())
                        own_signature = signer.sign(h)
                        own_signature = {'pid': pid, 'signature': str(int.from_bytes(own_signature, "big"))}
                        block_signatures.append(json.dumps(own_signature))
                        signature = {"pid": pid, "signature": own_signature["signature"],
                                     "block": new_signature["block"]}
                        block = signature["block"]

                        for p in peer_list:
                            if p["id"] != id:
                                sender_socket = context.socket(zmq.PUSH)
                                sender_socket.connect("tcp://127.0.0.1:" + str(p["port"]))
                                sender_socket.send_json(signature)
                                sender_socket.disconnect("tcp://127.0.0.1:" + str(p["port"]))
                except ValueError:
                    print("Value Error Pid:", pid, "block", k)
            h_prev = h

            #print("Process:", pid, "Block:", k, "Total has:", len(block_signatures))

            if len(block_signatures) > (2 * tolerance):
                file_writer = open("block_" + str(pid) + "_" + str(k) + ".log", "w")
                file_writer.write(block)
                file_writer.write(str(block_signatures).replace("\'", ""))

            receiver_socket.unbind("tcp://127.0.0.1:" + str(MyPORT))
            time.sleep(0.1)





if __name__ == "__main__":
    procs = []
    for i in range(n):
        proc = Process(target=peer_func, args=(i,))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()
