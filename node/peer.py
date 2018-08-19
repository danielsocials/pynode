
class Peer(object):
    def __init__(self):

        self.connected = True

        self.socket = None
        self.ip = None
        self.port = 0
        self.head_num = 0
        self.head_id = 0
        self.last_irreversible_block_num = 0
        self.last_irreversible_block_id = 0

        self.sync_num = 0
        self.sync_id = 0
