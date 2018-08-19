import os
import sys
import plyvel
import logging
from pyeos.utils import int_to_bytes

blocks_idx = {} # {id: hash}
blocks = {} # {hash: blk_data}

class ChainDb(object):

    def __init__(self, storage="memory"):
        self.storage = storage
        self.db=None
        if storage == "leveldb":
           self.db = self.open_blkdb(os.getcwd())

    def open_blkdb(self, datadir):
      try:
        db=plyvel.DB(os.path.join(datadir, 'blocks'),compression=None, create_if_missing=True)
      except:
        logging.error("Couldn't open blocks datadir. Try quitting any running pynodeos apps.")
        raise
        sys.exit(1)
      self.db=db
      return db
    
    def read_last_head(self):
       return self.db.get(b'head')

    def write_last_head(self, head_num):
       if self.storage == "leveldb":
           self.db.put(b'head', int_to_bytes(head_num))

    def read_last_irr(self):
       return self.db.get(b'irr')

    def read_hash(self, blk_num):
       return self.db.get(int_to_bytes(blk_num))

    def read_block(self, blkhash):
       return self.db.get(blkhash)

    def write_last_irr(self, irr_height):
       if self.storage == "leveldb":
          self.db.put(b'irr', int_to_bytes(irr_height))
 
    def write_blk_index(self, blk_num, blk_id):
       self.db.put(blk_num, blk_id)
    
    def write_blk(self, blk_id, blkdata):
       self.db.put(blk_id, blkdata)
    
    def save_blk_to_mem(self, blknum, prevhash, blkdata):
        blocks_idx[blknum-1] = prevhash
        blocks[prevhash] = blkdata
    
    def save_blk_to_db(self, blknum, prevhash, blkdata):
        if not self.db.get(int_to_bytes(blknum-1)):
            self.write_blk_index(int_to_bytes(blknum-1), prevhash)
            self.write_blk(prevhash, blkdata)
    
    def save_blk(self, blknum, prevhash, blkdata):
        if self.storage == "memory":
           self.save_blk_to_mem(blknum, prevhash, blkdata)
        elif self.storage == "leveldb":
           self.save_blk_to_db(blknum, prevhash, blkdata)
        else:
            logging.error("No blocks storage")

    def blk_indb(self, blknum):
        if self.storage == "memory":
            if (blknum-1) in blocks_idx:
               return True
        elif storage == "leveldb":
            if self.db.get(int_to_bytes(blknum-1)):
               return True
        return False


