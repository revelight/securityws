from proxy_epoll import *
from proxy_html_helpers import *
from char_encodings import *

from proxy_http_helpers import *



#
#
#                 filtering helpers
# -----------------------------------------------
#
#
#

h_DIR_IN = 'in'    # incoming traffic - to org
h_DIR_OUT = 'out'  # outgoing traffic - from org


def h_proxy_get_direction(proxy, sock, sock_is_dst=True):
    if sock_is_dst:
        direction = h_DIR_IN if sock.getsockname()[0] == eth_net_in else h_DIR_OUT
    else:
        direction = h_DIR_IN if sock.getsockname()[0] == eth_net_out else h_DIR_OUT
    return direction


def h_proxy_filter_classify_text_w_html_support(proxy, dst_sock, text, exclude_direction=None):

    # default - for exclude_direction
    if exclude_direction is None:
        pass
        #exclude_direction = h_DIR_OUT

    # filter
    dir = h_proxy_get_direction(proxy, dst_sock)
    if dir == exclude_direction:
        print('classify - direction excluded: {}  -> fwd'.format(dir))
        return Proxy.Verdict.FORWARD
    else:
        # classify the content
        msg_class = classify_text_w_html_support(text)
        # translate result to proxy verdict
        if msg_class == ML_CLASS_CODE:
            print(SUBTAG+'ml_class CODE  -> drop')
            return Proxy.Verdict.DROP
        elif msg_class == ML_CLASS_EMAIL:
            print(SUBTAG+'ml_class EMAIL  -> fwd')
            return Proxy.Verdict.FORWARD
        else:
            print(SUBTAG + 'ml_class BAD RETURN  -> drop')
            return Proxy.Verdict.DROP



#
#
#    Protocol Handlers and respective Filters
# -----------------------------------------------
#


#
#    SMTP
# ------------

class SMTPHandler:
    smtp_resp_codes = {'211', '214', '220', '221', '250', '251', '354', '421', '450', '451', '452', '500', '501', '502',
                       '503', '504', '550', '551', '552', '553', '554'}
    smtp_cmds = {'HELO', 'MAIL', 'RCPT', 'DATA', 'QUIT', 'EXPN', 'HELP', 'NOOP', 'SEND', 'SAML', 'SOML', 'TURN', 'VRFY'}

    @staticmethod
    def h_handle_smtp(proxy, dst_sock, data_bytearray, smtp_filter_actives):

        print(MAINTAG+'FILTER - SMTP: ')

        # get cmd. any upper/lower case is valid. http://www.freesoft.org/CIE/RFC/821/15.htm
        smtp_cmd = decode_to_str(data_bytearray[:4]).upper()

        if dst_sock not in smtp_filter_actives:  # because content itself might also begin with DATA
            if smtp_cmd == 'DATA':
                smtp_filter_actives.add(dst_sock)
            print(SUBTAG+'smtp - outside of DATA cmd range -> fwd')
            return Proxy.Verdict.FORWARD
        else:
            text = decode_to_str(data_bytearray)

            # check when to deactivate filter mode
            if '\r\n.\r\n' in text:  # end of DATA transmission
                smtp_filter_actives.remove(dst_sock)

            # filter mode is active for this fd - filter
            print(SUBTAG + 'smtp - within range of DATA cmd - filtering..')
            # print('--- filtering smtp text : ---\n.{}\n---------- end of smtp text ------------'.format(text))
            return h_proxy_filter_classify_text_w_html_support(proxy, dst_sock, text)

    # static flag set of fd's in active filtering mode (after DATA before \r\n.\r\n)
    smtp_filter_actives = set()

    @staticmethod
    def filter_smtp_email_code(proxy, dst_sock, data_bytearray):
        return SMTPHandler.h_handle_smtp(proxy, dst_sock, data_bytearray, SMTPHandler.smtp_filter_actives)


#
#    STRUTS
# ------------

class STRUTSHandler:

    # -- OPTIONS --
    flag_STRICT = True         # also use strict threat chain classes
    flag_ONLY_IN = True        # filter only 'in' traffic (attack is against an inside server)
    flag_SPECIFIC_URI = False  # filter only if URI contains user specific path
    threat_http_request_uri_contains = ''  # checked if flag_SPECIFIC_URI

    # -- CONSTS --
    threat_http_request_type = 'post'           # attack is a POST request
    threat_content_type = 'application/xml'     # of app/xml type
    # note: all lowercase : https://stackoverflow.com/questions/4106544/post-vs-post-get-vs-get

    # regex tcc : threat regex patterns
    regex_tcc_all = '{}'
    regex_tcc_class = '<\w+\s+class\s*?=\s*?["\']{}["\']\s*?>*'
    regex_tcc_class_cmd_str = '<\w+\s+class\s*?=\s*?["\']{}["\']\s*?>*\s*?<command>*\s*?<string>*'
    regex_tcc_default = regex_tcc_class

    # tcc : threat chain classes
    loose_tcc = [
        'java.lang.ProcessBuilder',
        'java.lang.Runtime.exec',
        'org.springframework.jndi.support.SimpleJndiBeanFactory',
        'com.sun.rowset.JdbcRowSetImpl',
        'com.sun.jndi.ldap.LdapAttribute',
        'javax.naming.Reference',
        'com.sun.jndi.rmi.registry.ReferenceWrapper',
        'javax.script.ScriptEngineFactory',
        'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl', ]
    strict_tcc = [
        'org.springframework.aop.aspectj.autoproxy.AspectJAwareAdvisorAutoProxyCreator$PartiallyComparableAdvisorHolder',
        'org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor',
        'com.rometools.rome.feed.impl.EqualsBean',
        'org.apache.xbean.naming.context.ContextUtil$ReadOnlyBinding',
        'javax.naming.spi.ContinuationDirContext',
        'org.apache.commons.configuration.ConfigurationMap',
        'sun.misc.Service$LazyIterator',
        'com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl',
        'com.sun.jndi.rmi.registry.BindingEnumeration',
        'java.net.URLClassLoader',
        'javax.imageio.spi.FilterIterator',
        'org.apache.commons.beanutils.BeanComparator',
        'org.codehaus.groovy.runtime.MethodClosure',
        'java.beans.EventHandler', ]

    @staticmethod
    def is_threat_in_text(text, threat_tokens, regex_tcc=None):
        if regex_tcc is None:
            regex_tcc = STRUTSHandler.regex_tcc_default
        for ttk in threat_tokens:
            pat = regex_tcc.format(ttk)
            match = re.search(pat, text, re.IGNORECASE)
            print(SUBTAG+'checking token : ', ttk, ' with pattern :', pat)
            if match is not None:  # Return None if no position in the string matches the pattern
                print(SUBTAG+'THREAT FOUND! : --► {} ◄-- '.format(text[match.start():match.end()]))
                return True
        print(SUBTAG+'no threat found.')
        return False

    @staticmethod
    def filter_struts_rest_xstream(proxy, dst_sock, data_bytearray):

        print(MAINTAG+'FILTER - STRUTS2 XSTREAM XML deserialize RCE: ')

        #print(data_bytearray)

        # traffic direction
        dir = h_proxy_get_direction(proxy, dst_sock)
        print(SUBTAG+'traffic direction is:', dir)
        if STRUTSHandler.flag_ONLY_IN:
            if not dir == h_DIR_IN:
                print(SUBTAG+'traffic direction not IN -> fwd')
                return Proxy.Verdict.FORWARD
        # request type
        reqtype = decode_to_str(data_bytearray[:4]).lower()
        if reqtype != STRUTSHandler.threat_http_request_type:
            print(SUBTAG+'request not POST -> fwd')
            return Proxy.Verdict.FORWARD
        # specific uri
        if STRUTSHandler.flag_SPECIFIC_URI:
            uri = data_bytearray.split(' ', 2)[1]
            if STRUTSHandler.threat_http_request_uri_contains not in uri:
                print(SUBTAG+'request uri not qualifying -> fwd')
                return Proxy.Verdict.FORWARD

        # content type
        req = HttpRequestParser(data_bytearray)
        content_type = req.find_header('Content-Type')

        if content_type is not None:
            if content_type != STRUTSHandler.threat_content_type:
                print(SUBTAG+'content-type not application/xml -> fwd')
                return Proxy.Verdict.FORWARD
            else:
                print(SUBTAG + 'content-type is application/xml - filter request body')
        else:
            # req.get_body will return entire raw request which is also ok
            pass

        # payload threats
        body = req.get_body()

        # threat detect - loose and strict
        is_threat = STRUTSHandler.is_threat_in_text(body, STRUTSHandler.loose_tcc)
        if (not is_threat) and STRUTSHandler.flag_STRICT:
            is_threat = STRUTSHandler.is_threat_in_text(body, STRUTSHandler.strict_tcc)

        # verbose print and return verdict
        if is_threat:
            print(SUBTAG+'threat found in payload -> drop')
            return Proxy.Verdict.DROP
        else:
            print(SUBTAG+'payload is clear -> fwd')
            return Proxy.Verdict.FORWARD


#
#    HTTP
# ------------

class HttpHandler:
    #
    #              filter : email / code
    # -----------------------------------------------
    # static marker for imminent data send following a DATA command (SMTP is a delivery protocol only)
    # note: use this filter in only one instance or change to non-static method
    smtp_filter_actives = set()

    @staticmethod
    def filter_http_email_code(proxy, dst_sock, data_bytearray):

        # print('filter_http - excerpt: {:.100}\n'.format(data_str), end='')
        print(MAINTAG+'FILTER - Email/Code Filter, PORT 80 (HTTP, SMTP OR ELSE): ')

        # get header as string
        data_header = decode_to_str(data_bytearray[:4])

        # -- analyse --

        # HTTP - classify content with html support
        if data_header == 'HTTP':
            print(SUBTAG+'http header found.. ', end='')
            # filter : http response
            response = HttpResponseObj(data_bytearray)
            content = response.read_content(as_string=True)  # reads and returns the response body

            if content is None or content == '':
                print('no content -> fwd')
                return Proxy.Verdict.FORWARD
            else:
                return h_proxy_filter_classify_text_w_html_support(proxy, dst_sock, content)  # classify http content

        # SMTP - pry out SMTP traffic over port 80
        elif dst_sock in HttpHandler.smtp_filter_actives or \
                data_header in SMTPHandler.smtp_cmds:

            SMTPHandler.h_handle_smtp(proxy, dst_sock, data_bytearray, HttpHandler.smtp_filter_actives)

            # filter : SMTP over port 80, next msg is DATA

            return Proxy.Verdict.FORWARD

        # all other cases and plain text - try to classify directly, and always filter code
        else:
            print(SUBTAG+'msg isn\'t HTTP response -> classifying full text')
            text = decode_to_str(data_bytearray)
            return h_proxy_filter_classify_text_w_html_support(proxy, dst_sock, text)

    #
    #                filter : content len
    # -----------------------------------------------
    contentlen_field_maxval = 5000 / 8  # field at *8

    @staticmethod
    def filter_http_contentlen(proxy, dst_sock, data_bytearray):

        # print('filter_http - excerpt: {:.100}\n'.format(data_str), end='')
        print(MAINTAG+'FILTER - HTTP: ', end='')

        data_header = decode_to_str(data_bytearray[:4])

        # note: for our case, only responses have an actual data body,
        # so content_len header check is relevant to responses and not requests.
        # https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4

        # http request - don't filter
        if data_header.lower() != 'http':
            print('msg isn\'t HTTP response -> fwd')
            return Proxy.Verdict.FORWARD

        # http response - filter
        else:
            response = HttpResponseObj(data_bytearray)
            content_len_field = response.getheader('Content-Length')
            #print('content len is: ', content_len_field)
            #print('content is: ', response.read_content())
            if content_len_field is None:
                print('content-len header not found -> drop')
                return Proxy.Verdict.DROP
            elif int(content_len_field) > HttpHandler.contentlen_field_maxval:
                print('content-len {} exceeds max -> drop'.format(int(content_len_field)))
                return Proxy.Verdict.DROP

            # content is in accepted length - accept
            print('content-len ok -> fwd')
            return Proxy.Verdict.FORWARD


#
#    FTP
# ------------

class FtpHandler:

    @staticmethod
    def filter_ftp_ctrl(proxy, dst_sock, data_bytearray):
        # print('filterFTP_ctrl - excerpt: {:.100}\n'.format(data_str))
        print(MAINTAG+'FILTER - FTP-CTRL: ')

        data_str = decode_to_str(data_bytearray)

        # ftp cmd : port - setup and add new ftp data connection
        if data_str[:4] == "PORT":
            print('PORT - ftp_data setup -', end='')

            #  note: FTP PORT command sent by an FTP client,
            #  to establish new connection params for a file transfer

            # -- setup - new kernel connection details --

            # server becomes client
            #  the server will act as client, at port 20
            c_addr = dst_sock.getpeername()  # dst_sock is server
            print(' c {}'.format(c_addr), end='')
            c_addr = (c_addr[0], 20)  # set port to 20, FTP active mode

            # client becomes server
            # client sends its preferred ip and port as server for the transfer
            params = re.split('\r\n|,', data_str[5:])
            s_addr = ('{}.{}.{}.{}'.format(params[0], params[1], params[2], params[3]),
                      int(params[4]) * 256 + int(params[5]))
            print(' s {}'.format(s_addr), end='')

            # add new connection to kernel - ftp data
            update_con_to_kernel(c_addr, s_addr, None)

        print(' -> fwd')
        return Proxy.Verdict.FORWARD

    @staticmethod
    def filter_ftp_data(proxy, dst_sock, data_bytearray):
        # print('filterFTP_data - excerpt: {:.100}\n'.format(data_str))

        print('FILTER - FTP-DATA: ', end='')

        flag_exe_dos = b'MZ'  # Mark Zbikowski made ms-dos!
        flag_exe_dos2 = b'ZM'
        flag_exe_posix = b'\x7fELF'

        ftype_flag = data_bytearray[:5]
        print('file signature excerpt: {} :'.format(ftype_flag))

        if ftype_flag[:2] == flag_exe_dos or ftype_flag[:4] == flag_exe_posix or ftype_flag[:2] == flag_exe_dos2:
            # magic number- file is executable - drop
            print(' exe -> drop')
            return Proxy.Verdict.DROP

        print(' non-exe -> fwd')
        return Proxy.Verdict.FORWARD


#
#    SMTP
# ------------

def h_testsome():
    regex_tcc = '/<\w+\s+class\s*?\x3D\s*?[\x22\x27]{}[\x22\x27]\s*?>.*?<command.*?<string/is'
    regex_tcc = '/<\w+\s+class\s*?=\s*?["\']{}["\']\s*?>.*?<command.*?<string/is'
    regex_tcc = '<\w+\s+class\s*?=\s*?["\']{}["\']\s*?>*\s*?<command>*\s*?<string>*'
    text = open('threat_test1').read()
    print('text to check: --->', text)
    is_threat = STRUTSHandler.is_threat_in_text(text, STRUTSHandler.loose_tcc, regex_tcc=regex_tcc)
    print('is_threat:', is_threat)

#h_testsome()