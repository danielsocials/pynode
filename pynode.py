import config
from node.node import *
import time
import datetime
import json
import hashlib
import asyncore
import logging
import threading
from node.rpcserver import rpc_server
from chain.chaindb import ChainDb

def run():

    logging.basicConfig(level=logging.DEBUG)
    node_id = hashlib.sha256().digest()
    logging.info('node id: %s' % node_id.hex())


    db = ChainDb(config.storage)

    if config.enable_server:
        server = Server(ip="127.0.0.1", port=9999, node_id=node_id, db=db)
        server.loop()

    for peer in config.peers:
        ip, port = peer.split(':')
        client =  Client(ip, int(port), node_id, db)
        client.send_handshake_msg()
    node_thread = threading.Thread(target=client.loop, name="node loop")
    node_thread.start()
    if config.enable_rpcserver:
        msg_thread = threading.Thread(target=rpc_server(8888, client), name="Rpc server")
        msg_thread.setDaemon(True)
        msg_thread.start()

run()
