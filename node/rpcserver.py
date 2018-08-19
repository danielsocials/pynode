from flask import Flask
from json import dumps
from .node import blocks, blocks_idx
import time

def rpc_server(port, gnode):
    import logging
    log = logging.getLogger('werkzeug')
    #log.disabled = True
    app = Flask(__name__)
    #app.logger.disabled = True
    
    @app.route('/v1/chain/get_info')
    def get_info():
        return dumps({
                   "server_version": gnode.version,
                   "chain_id": gnode.chain_id,
                   "head_block_num": gnode.head_num,
                   "last_irreversible_block_num": gnode.last_irreversible_block_num,
                   "last_irreversible_block_id": gnode.last_irreversible_block_id.hex(),
                   "head_block_id": gnode.head_id.hex(),
                   "head_block_time": time.strftime("%Y-%m-%dT%H:%M:%S.000",time.gmtime()),
                   "head_block_producer": gnode.code,
                   "virtual_block_cpu_limit": 200000000,
                   "virtual_block_net_limit": 1048576000,
                   "block_cpu_limit": 200000,
                   "block_net_limit": 1048576
                 })

    @app.route('/v1/chain/get_block')
    def get_block(blknum):
        pass
    @app.route('/v1/chain/push_transaction')
    def push_transaction(txid):
        pass
 
    app.run(port=port)
    #app.run(port=port, debug=False, threaded=True, use_reloader=False, use_evalex=False)
