
from proxy_prints import *
from char_encodings import *

import re

# from http.client import HTTPResponse
from http.client import *
from io import BytesIO








#   helper : HTTP request
# -------------------------
# using python Standard Library,
# since newer http packages not available in this py ver under this kernel.

class HttpRequestParser():

    def __init__(self, data_bytearray):
        self.text = data_bytearray.decode('utf-8')
        self.body_start = self._find_body_start()

    def _find_headers(self):
        # incomplete - could be developed to get all headers upon init
        header_re = '\r\n([\w-]+): ([^\r\n]+)'
        matches = re.finditer(header_re, self.text[:self.get_body_start()])

    def find_header(self, hdr):
        hdr_title_re = '\r\n{}: ([^\r\n]+)'.format(hdr)
        match = re.search(hdr_title_re, self.text[:self.get_body_start()])
        if match is not None:
            return match.group(1)
        else:
            return None

    def _find_body_start(self):
        body_start_re = '\r\n\r\n'
        match = re.search(body_start_re, self.text)
        if match:
            return match.start()
        else:
            print(SUBTAG+'HttpRequestParser - warning - could\'nt find body start')
            return None

    def get_body_start(self):
        if self.body_start is not None:
            return self.body_start
        else:
            print(SUBTAG+'HttpRequestParser - warning - requested body not found - returned whole')
            return 0

    def get_body(self):
        return self.text[self.get_body_start():]























#   helper : HTTP Response
# -------------------------
# using python Standard Library HTTPResponse parser,
# since newer http packages not available in this py ver under this kernel.
# https://docs.python.org/3/library/http.client.html
# https://stackoverflow.com/questions/24728088/python-parse-http-response-string

class HttpResponseObj:
    class FakeSocket:
        def __init__(self, data):
            self._file = BytesIO(data)

        def makefile(self, *args, **kwargs):
            return self._file

    def __init__(self, data_bytearray):
        self.data_bytearray = data_bytearray
        #print('CHECK TYPES', self.data_bytearray is data_bytearray)
        self.data_len = len(data_bytearray)
        self.sock = HttpResponseObj.FakeSocket(data_bytearray)
        self.resp = HTTPResponse(self.sock)
        try:
            self.resp.begin()
        except HTTPException as e:
            print(SUBTAG2+'Exception', e)
            # print(SUBTAG2+'full buffer print:', data_bytearray)
            raise e

    def read_content(self, as_string=False):
        print(SUBTAG2+'data_len/http_content_len : {}/{}'.format(self.data_len, self.resp.length))
        res = None
        return_raw_data = False
        content_start = self.data_len - self.resp.length
        if content_start < 0:
            print(SUBTAG2+'** warning! incomplete data : data_len/http_content_len : {}/{} **'.format(self.data_len, self.resp.length))
            return_raw_data = True
        else:
            self.resp.fp.seek(content_start)  # fix fp position for HTTPResponse
            try:
                res = self.resp.read()
            except IncompleteRead as e:
                print(SUBTAG2+'\n** warning: HTTPResponse incomplete read **')
                return_raw_data = True
        if return_raw_data:
            res = self.data_bytearray
        if as_string:
            res = decode_to_str(res)
        return res

    def getheader(self, header):
        res = self.resp.getheader(header)
        if res is None:
            print(SUBTAG2+'error - HttpResponseObj getheader - got NONE HTML HEADER')
        return res

