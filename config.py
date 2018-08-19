VERSION = "1.0"

coin = 'EOS' #or 'ENU'
code = 'eosio' 
expire_offset = 600
pubkey = 'EOS6kerat8iDhU1vs9svmwi4J5HJu4w4LXZHnxYUZrArLZCUrjAr6'
prvkey = '5JWnFiPz2kcyeC39Dgp8aXiJLPEMEDcdLbhSP3juq7LakJqbJH7'

connect = 'http://127.0.0.1:38888'
rpcuser = 'rpc'
rpcpass = 'pass'

head_num = 1
#head_id = '00000001bcf2f448225d099685f14da76803028926af04d2607eafcf609c265c'

last_irreversible_block_num = 0
last_irreversible_block_id = "0000000000000000000000000000000000000000000000000000000000000000"

virtual_block_cpu_limit = 200000000
virtual_block_net_limit = 1048576000
block_cpu_limit = 200000
block_net_limit = 1048576
 
storage = "memory" # "leveldb" 
#storage = "leveldb" # "leveldb" 

# currently the blocks saved in memory
save_block_count = 100000

# eos main net
CHAIN_ID = 'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906'
head_id = '00000001405147477ab2f5f51cda427b638191c66d2c59aa392d5c2c98076cb0' 
peers = ["35.198.59.183:6987"]

# enu main net
#head_id = '00000001bcf2f448225d099685f14da76803028926af04d2607eafcf609c265c' 
#CHAIN_ID = 'cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f'
#peers = ["172.104.104.8:9000"]


server= ["127.0.0.1:9999"]
enable_server = False
enable_rpcserver = True
