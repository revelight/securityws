
from proxy_epoll import *
from proxy_filters import *
from collections import OrderedDict

#
# --- Proxy create and run commands ---

local_addr = ''
addr_http = (local_addr, 8001)
addr_ftp_ctrl = (local_addr, 2001)
addr_ftp_data = (local_addr, 2000)
addr_smtp = (local_addr, 2500)
addr_struts = (local_addr, 8081)


def run_proxy_http():
    proxy = Proxy.factory(addr_http, HttpHandler.filter_http_contentlen)
    proxy.run_proxy()


def run_ftp_ctrl():
    proxy = Proxy.factory(addr_ftp_ctrl, FtpHandler.filter_ftp_ctrl)
    proxy.run_proxy()


def run_ftp_data():
    proxy = Proxy.factory(addr_ftp_data, FtpHandler.filter_ftp_data)
    proxy.run_proxy()


def run_proxy_http_email_code():
    proxy = Proxy.factory(addr_http, HttpHandler.filter_http_email_code)
    proxy.run_proxy()


def run_smtp():
    proxy = Proxy.factory(addr_smtp, SMTPHandler.filter_smtp_email_code)
    proxy.run_proxy()


def run_struts():
    proxy = Proxy.factory(addr_struts, STRUTSHandler.filter_struts_rest_xstream)
    proxy.run_proxy()



#
# --- Main run ---

proxy_service_dict = OrderedDict(
    [('1', run_proxy_http), ('2', run_ftp_ctrl), ('3', run_ftp_data),
    ('4', run_proxy_http_email_code), ('5', run_smtp), ('6', run_struts)])


def bad_proxy_number():
    print("oops check your command")


def run_by_num():

    for k, v in proxy_service_dict.items():
        print('{}-{}  '.format(k, v.__name__), end='')
    print()

    cmd_input = input()
    proxy_service_dict.get(cmd_input[0], bad_proxy_number)()


run_by_num()
