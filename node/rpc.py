import http
import io
import base64
from urllib.parse import urlparse
from .exceptions import RPCError
from urllib import request, parse

class RpcClient:
     def __init__(self, connect='http://127.0.0.1:8888', username='', password=''):
        self.url = connect
        self.__url = urlparse.urlparse(conn)
        if self.__url.port is None:
        	port = 8888
        else:
        	port = self.__url.port
        self.username = username or ''
        self.password = password or ''
        ssl_context = None
        self.conn = httplib.HTTPSConnection(self.__url.hostname, port, None, None, False, timeout)

     def close(self):
        return  self.session.close()

     @property
     def request_headers(self):
        headers = None
        if self.username and self.password:
            auth_bytes = '{}:{}'.format(
                self.username, self.password).encode()
            auth = base64.encodestring(auth_bytes).strip()
            headers = {
                'Authorization': 'Basic {}'.format(
                    auth.decode())
            }
        return headers
 
     def request_rest(self, path, json=None, data=None, retry=1, **kw):
        return  self.request_rest_p(path, json, data, retry=retry, **kw)

     def request_rest_p(self, path, json, data, retry=1, **kw):
        for i in range(retry):
            try:
                r =  self._request_rest(path, json, data)
                return r
            except (OSError):
                if i < retry - 1:
                     io.sleep(0.1)
                     continue
                else:
                    raise

     def _request_rest(self, path, json, data, **kw):
        timeout = kw.get('timeout', 100)
        fullpath = self.url + path

        u = None
        if data:
            u = request.urlopen(fullpath, data)
        else:
            u = request.urlopen(fullpath)
        resp = u.read()
        with self.session.request("GET", path) as resp:
                if resp.status != 200:
                    msg =  resp.text()
                    raise RPCError(resp.status, msg)
                ret =  resp.json()
                return ret

     def get_transaction(self, txid):
        path = '/v1/history/get_transaction'
        payload = {"id": txid}
        return  self.request_rest(path, json=payload)

     def get_info(self):
        """
        Get latest information related to a node.

        :return: response object
        """
        path = '/v1/chain/get_info'
        return  self.request_rest(path)

     def get_block(self, block_id):
        """
        Get information related to a block.

        :param block_id: (str) the format must be a string of a json
        :return: response object
        """
        path = '/v1/chain/get_block'
        payload = {"block_num_or_id": block_id}
        return  self.request_rest(path, json=payload)
