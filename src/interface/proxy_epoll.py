
"""

    Proxy Service Factory
    ============================================

    Enables flow:  Client <--> Proxy <--> Server

    Listens on a listen_port for new connections,
    polls (checks for updates) on any open socket-fd's,
    and forwards data between associated peers

    Supports transparency with FW module's connection table:
    On accepting a new connection:
    * Reads S by key C, from FW, to get C-S pairing
    * Opens a new connection
    * Writes PC (Proxy-as-Client) by key C, to FW, to update C-S-PC in kernel

    References:
    https://github.com/itsyarkee/python_socket_proxy/blob/master/sock_proxy.py#L107
    https://github.com/SietsevanderMolen/python-epoll-proxy/blob/master/proxy.py
    https://docs.python.org/3/library/socket.html
    http://man7.org/linux/man-pages/man7/epoll.7.html
    https://linux.die.net/man/7/socket
    http://man7.org/linux/man-pages/man2/shutdown.2.html
    http://www.unixguide.net/network/socketfaq/2.6.shtml


"""


import select
from parser import *
from proxy_prints import *

# --- kernel and python limitations ---
EPOLLRDHUP = 0x00002000


#
#                   proxy kernel communication helpers
# ----------------------------------------------------------------------------
#

def get_from_kernel_s_by_c(c_addr):
    # get contable, parse and split
    cons_str = h_file__read_str_from_file(fp_cd_conntab)
    cons_str = h_cons__user_entire_str_from_host_entire_str(cons_str)
    cons = h_split_str(cons_str, cons_inline_sep)
    #print(cons)
    #print(c_addr)
    key_ip = c_addr[0]
    key_port = str(c_addr[1])
    # locate connection by C
    matches = [con for con in cons if (con[0] == key_ip and con[1] == key_port)]
    if len(matches)!=1:
        print(SUBTAG2+'proxy get_S_by_C : Error! Invalid entries for connection {} : {} entries found'.format(c_addr, len(matches)))
        return None
    # return s_addr : (s_ip, s_port)
    res = (matches[0][2], int(matches[0][3]))
    return res

# adds or updates a connection to kernel
def update_con_to_kernel(c_addr, s_addr, pc_addr):
    print(SUBTAG2+'update to kernel --> PC {}'.format(pc_addr), end='')
    # case : update pc_port to an existing connection
    cmd = 'U'
    # case : add a new connection (c-s) to kernel
    if pc_addr is None:
        pc_addr = ('0', 0)
        cmd = 'A'
    # setup string and update to kernel
    res = '{} {} {} {} {} {}\n'.format(
        cmd,
        socket.ntohl(ip2int(c_addr[0])), c_addr[1],
        socket.ntohl(ip2int(s_addr[0])), s_addr[1],
        pc_addr[1])
    print(' --> str: {}'.format(res[:-1]))
    h_file__write_str_to_device(fp_cons_update, res)


# --- proxy mirror socket connector ---

class MirrorSocket(object):
    # for each client C, the proxy creates a unique socket connecting to S

    def __init__(self, socket_c):
        print(SECTAG+'proxy MirrorSocket : ')
        self.has_failed = 0
        self.socket_c = socket_c
        addr_c = socket_c.getpeername()

        # get matching S from kernel
        print(SUBTAG2+'get S from kernel.. ', end='')
        self.addr_s = get_from_kernel_s_by_c(addr_c)
        if self.addr_s is None:
            self.has_failed = 1
            print('failed')
            return
        print('ok! found C {}, S {}'.format(addr_c, self.addr_s))

        # -- create pc socket --
        self.socket_pc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # select matching interface ip as src for new PC socket
        ip_pc = eth_net_in if (socket_c.getsockname()[0] == eth_net_out) else eth_net_out
        #ip_pc = eth_list[1] if (socket_c.getsockname()[0] == eth_list[0]) else eth_list[0]
        addr_pc = (ip_pc, 0)
        self.socket_pc.bind(addr_pc)
        addr_pc = self.socket_pc.getsockname()

        # update PC to kernel (send C-S-PC)
        #print(' --- update to kernel --> PC {} --> '.format(addr_pc), end='')
        update_con_to_kernel(addr_c, self.addr_s, addr_pc)


    def connect_now(self):
        if self.has_failed == 1:
            print(SUBTAG+'cant connect to failed socket')
            return
        # try to create new connection: proxy <-> server (dst)
        print(SUBTAG+'connecting to S {} on mirror socket.. '.format(self.addr_s), end='')
        try:
            self.socket_pc.settimeout(2)
            self.socket_pc.connect(self.addr_s)
            self.socket_pc.settimeout(0)
            print('ok!')
            return self.socket_pc
        except Exception as e:
            print('failed!')
            #logging.exception('proxy MirrorSocket : Error connecting socket')
            self.has_failed = 1
            return

    def get_sock(self):
        return self.socket_pc

# ----------------------------------------------------------------------------



# --- proxy server factory ---


class Proxy:

    #                               proxy services
    # ----------------------------------------------------------------------------
    #
    # proxy factory
    #  listen_address is (ip,port)
    #  filter func signature : filter(proxy, dst_sock, data_bytearray)
    def factory(listen_address, filter_func=None):
        print('\n'+MAINTAG+'proxy factory : creating proxy')
        new_proxy = Proxy(listen_address, filter_func)
        return new_proxy
    factory = staticmethod(factory)

    # use as return value for filter function
    # note - APPEND might be used for a filter that wants to accumulate data and then check it
    #        the flag can be implemented to skip send at the filtering stage in proxy's forward-and-receive
    class Verdict:
        DROP = 0
        FORWARD = -1
        APPEND = -2

    #  ----------------------------------------------------------------------------

    #
    #
    #                                 proxy internals
    # ----------------------------------------------------------------------------
    #
    # proxy socket
    class Psock():

        def __init__(self, sock, peer=None):
            self.sock = sock
            self.peer = peer
            self.buf = None  # inbox buf, data waiting to be sent to this socket
            self.latime = time.time()
            self.is_shutdown = False

        def fd(self):
            return self.sock.fileno()

        def fileno(self):
            return self.sock.fileno()

        def get_peer(self):
            return self.peer

        def peer_fd(self):
            if self.peer is not None:
                return self.peer.fileno()
            else:
                return None

        def has_peer(self):
            return self.peer is not None

        def send(self, data, flags=None):
            return self.sock.send(self, data, flags)

        def recv(self, buffersize, flags=None):
            return self.sock.recv(self, buffersize, flags)

        def shutdown(self, how=None):
            return self.sock.shutdown(how)

        def close(self):
            return self.sock.close()

        def buf_is_empty(self):
            return (self.buf is None) or (len(self.buf) == 0)

        def buf_append(self, data_bytearray):
            assert isinstance(data_bytearray, bytearray)
            if self.buf is None:
                self.buf = data_bytearray
            else:
                self.buf.extend(data_bytearray)

        def buf_trim(self, up_to_index):  # index not including
            self.buf = self.buf[up_to_index:]

        def buf_del(self):
            self.buf = None

        def get_desc(self):
            return 'socket : {},{},{}'.format(self.fd(), self.sock.getpeername(), self.sock.getsockname())

        def get_safe_desc(self):
            return 'socket : {}'.format(self.fd())

        def getsockname(self):
            return self.sock.getsockname()

        def getpeername(self):
            return self.sock.getpeername()

    #
    def __init__(self, listen_address, filterfunc):
        # listen_address is (ip,port)
        print('\n'+MAINTAG+'proxy init : data objs.. ', end='')

        # setup proxy object
        self.sock_by_fd = {}         # connections by fd dict (socket_fd <-> python_socket_obj)

        # register filter function
        self.filter_func = filterfunc

        # consts
        self.ttl_secs = 40
        self.batch_size = 4096  # value of bufsize should be a relatively small power of 2, for example, 4096
        self.threshold_buf_size = 200000  # larger size can allow filters to work on whole data units


        # --- init proxy service ---
        print('sockets and epolling.. ')
        # setup the listening socket
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # socket for ipv4, TCP
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #       set SO_REUSEADDR to allow reuse of local addresses, an option at SOL_SOCKET config leve
        try:
            print(SUBTAG+'listening address is {}'.format(listen_address))
            self.listen_socket.bind(listen_address)
        except socket.error as e:
            print(SUBTAG+'error on listen socket {}'.format(e))
            #print(' --- for address {}'.format(listen_address))
            exit(0)

        # set the socket to listen
        self.listen_socket.listen(1) # set socket mode to listen, with backlog 1
        self.listen_socket.setblocking(0) # set timeout to 0.0

        # epoll - newest API for monitoring multiple file descriptors to see if I/O is possible on any of them
        #   create an edge-polling object
        self.epoll = select.epoll()
        #   register our listening socket's fd with the epoll object, for 'read' (incoming) readiness
        self.epoll.register(self.listen_socket.fileno(), select.EPOLLIN)

        # proxy active flag
        self.running = False

        print(SUBTAG+'proxy ready!')

    #
    def accept_new_client(self):
        """
        Accepts new client (socket_C) on listen_socket
        Update contable from kernel to get C-S-'' pairing
        Try to connect to S (C's peer):
        If ok:  add (fd,socket) to sockets_by_fd
                add (socket_C, socket_PC) to sock_to_sock
        """
        print(MAINTAG+'proxy accept_new_client : ')
        # get socket_c -- accepted connection
        socket_c, addr_c = self.listen_socket.accept()
        # create PC (ProxyAsClient) socket, and connect to S
        socket_pc = MirrorSocket(socket_c).connect_now()
        if socket_pc is None:
            # discard connections
            socket_c.send(bytes('FW Proxy says: Cant connect to S\n', 'UTF-8'))
            socket_c.close()
            return
        # --- setup sockets for epoll-ing ---
        # socket_C
        socket_c.setblocking(0) # set to non-block (timeout 0.0)
        self.epoll.register(socket_c.fileno(), select.EPOLLIN)
        # socket_PC
        socket_pc.setblocking(0)  # set to non-block (timeout 0.0)
        self.epoll.register(socket_pc.fileno(), select.EPOLLIN)
        # create Proxy-Sockets
        psock_c = Proxy.Psock(socket_c)
        psock_pc = Proxy.Psock(socket_pc)
        # set sock-peer coupling
        psock_c.peer = psock_pc
        psock_pc.peer = psock_c
        # save to sockets_by_fd
        self.sock_by_fd[psock_c.fd()] = psock_c
        self.sock_by_fd[psock_pc.fd()] = psock_pc

        print(SUBTAG+'connections paired and ready! fd: {} , {}'.format(psock_c.fd(), psock_pc.fd()))

    #
    def sock_receive_and_forward(self, fd):
        #
        #
        # --- receive ---
        print(MAINTAG+'proxy sock_receive_and_forward : receive.. ')
        sock = self.sock_by_fd[fd]
        # check and update - ttl
        if self.h_is_ttl_expired_shutdown_or_update(sock):
            self.h_sock_shutdown_if_lonely_empty(sock.get_peer())
            return
        # check - peer exists
        if not sock.get_peer():
            self.sock_shutdown(fd)
            return

        batch_size = self.batch_size
        threshold_buf_size = self.threshold_buf_size
        nbytes_req = batch_size
        read_data = b''
        buffer = bytearray()  # mutable, faster
        # sock.settimeout(2) # can also use different timeout
        try:
            # receive to buffer in 4096 increments, up to threshold
            # note : socket assumed to be at non-blocking mode
            while True:
                # -- buffer threshold and batch size
                nbytes_left_buf = threshold_buf_size - len(buffer)
                if nbytes_left_buf < batch_size:
                    # from now on, request amount left to fill buffer up to threshold
                    nbytes_req = threshold_buf_size - len(buffer)
                    if nbytes_left_buf <= 0:
                        print(SUBTAG+'receive - buffer filled {}/{}'.format(len(buffer), threshold_buf_size))
                        break
                # -- receive data
                read_data = sock.sock.recv(nbytes_req)  # read in 4096 batches for best hw and network match
                print(SUBTAG+'receive - received/requested {}/{}'.format(len(read_data), nbytes_req))
                if len(read_data) == 0:
                    break  # connection closed, will not get more data - EVER!
                # -- receive buffer append
                buffer += read_data  # extend mutable sequence

        except socket.timeout as e:
            # there's no more data -> timeout exception at non-blocking mode
            # no data left or recv timed out
            print(SUBTAG+'receive - socket recv timed out')
            pass
        except socket.error as e:
            if e.errno == socket.EWOULDBLOCK or e.errno == socket.EAGAIN:
                # read all currently available data : EWOULDBLOCK \ EAGAIN
                print(SUBTAG + 'receive - socket exhausted - no more data in socket')
                pass
            else:
                # serious error on socket
                print(SUBTAG+'receive - ERROR on recv fd {} - {}'.format(fd, e))
                self.sock_shutdown(sock.fd(), also_peer=True, safe_print=True)
                return
        #
        # -- successful receive - wrap ups --
        print(SUBTAG + 'receive - total {} bytes received ok!'.format(len(buffer)))
        # - sock connection hung up - shutdown socket -
        if len(read_data) == 0:
            # peer closed connection, fin arrived after wakeup from EPOLLIN and before reading.
            print(SUBTAG+'receive - SOCKET HANGUP (data_read len 0) - socket shutdown')
            self.sock_shutdown(fd)  # sock buf sender will treat peer socket
        #
        #
        # --- forward ---
        peer = sock.get_peer()
        if len(buffer) != 0:
            print(MAINTAG+'proxy sock_receive_and_forward : forward.. ')

            # ** --- FILTERING ---
            # filter the data (opt with relation to existing socket buffer content)
            # --------------------
            data_bytearray = bytearray(buffer)  # filter function gets a copy for safety
            data_verdict = self.filter_func(self, peer, data_bytearray)
            # --------------------

            if data_verdict == Proxy.Verdict.FORWARD:
                # append buf and try to send
                print(SUBTAG+'forward - FWD - appending {} bytes to peer buffer'.format(len(buffer)))
                peer.buf_append(buffer)
                self.h_sock_buf_sender(peer)  # note: sender will update peer ttl
            elif data_verdict == Proxy.Verdict.DROP:
                # immediately drop connection and any data
                # if fd was already shutdown will only shut peer, else both
                self.sock_shutdown(peer.fd(), also_peer=True)
                return
            elif data_verdict == Proxy.Verdict.APPEND:
                print(SUBTAG+'forward - APPEND - appending {} bytes to peer buffer'.format(len(buffer)))
                peer.buf_append(buffer)
            else:
                print(SUBTAG+'forward - filter func unsupported return value - dropping')
                self.sock_shutdown(peer.fd(), also_peer=True)
                return

        # shutdown lonely, buffer-empty sockets
        self.h_sock_shutdown_if_lonely_empty(peer)


    #
    def sock_send_buffer(self, fd):
        print(MAINTAG+'proxy sock_write_ready_send_buffer : sending saved buffer')
        sock = self.sock_by_fd[fd]
        # report socket
        print(SUBTAG+sock.get_desc())
        # ttl check and update
        if self.h_is_ttl_expired_shutdown(sock):
            # note : ttl will update by sender on successful send
            self.h_sock_shutdown_if_lonely_empty(sock.get_peer())
            return
        # optional: filter the data / as whole
        # verdict = self.filter_func(self, fd, None)
        # send
        self.h_sock_buf_sender(sock)
        # shutdown lonely, buffer-empty sockets
        self.h_sock_shutdown_if_lonely_empty(sock)

    #
    def h_sock_buf_sender(self, sock):
        fd = sock.fd()
        buf = sock.buf
        # safety - check buf not empty
        if sock.buf_is_empty():
            print(SUBTAG+'sender - error! send buffer empty')
            self.epoll.modify(fd, select.EPOLLIN)
            return
        # report buf
        print(SUBTAG + 'sender - buffer excerpt: {}'.format(buf[:min(15, len(buf))]))
        try:  # write to socket
            nbytes_written = sock.sock.send(buf)
            self.h_update_ttl(sock)  # update ttl on any non-error / non-blocking send
            if nbytes_written == 0:  # connection was hanged up
                print(SUBTAG+'sender - send connection was hung up - dropping buffer and shutting it down')
                sock.buf_del()
                self.sock_shutdown(fd)
            if len(buf) > nbytes_written:  # data remains - add leftover to peer's empty send buffer
                print(SUBTAG+'sender - partial send - trim buf and send later')
                sock.buf_trim(nbytes_written)
                self.epoll.modify(fd, select.EPOLLOUT)  # set fd's epoll mask to write availability (to send its buffer in next loops)
            else:
                print(SUBTAG+'sender - buffer all sent')
                sock.buf_trim(nbytes_written)
                self.epoll.modify(fd, select.EPOLLIN)  # set fd's epoll mask to input only
        except socket.error as e:
            if e.errno == socket.EWOULDBLOCK or e.errno == socket.EAGAIN:
                print(SUBTAG+'sender - EWOULDBLOCK or EAGAIN on send socket - will try again later')
                self.epoll.modify(fd, select.EPOLLOUT)
            else:
                #  serious error
                print(SUBTAG+'sender - error sending on socket! - shutdown socket')
                # send error to sender: self.sockets_by_fd[fd].send( bytes("Can't reach server\n", 'UTF-8'))
                self.sock_shutdown(fd)

    #
    def h_sock_shutdown_if_lonely_empty(self, sock):
        # shutdown lonely, buffer-empty sockets
        # print(SUBTAG+'sock shutdown if lonely empty:',sock.get_desc(), sock.buf_is_empty(), len(sock.buf), sock.get_peer())
        if sock.get_peer() is None and sock.buf_is_empty():
            self.sock_shutdown(sock.fd())

    def sock_shutdown(self, fd, also_peer=False, safe_print=False):
        # shutdown the socket, update its corresponding peer socket
        # option: also its peer socket)
        # note: epoll EPOLLHUP will call socket object termination
        print(SECTAG+'proxy sock_shutdown (polite) :')
        sock = self.sock_by_fd[fd]
        if sock.is_shutdown:
            print(SUBTAG2+'socket {} already shutdown'.format(fd))
            return
        self.h_do_socket_shutdown(sock)
        if sock.get_peer() is not None:
            sock.get_peer().peer = None  # set peer lonely
            if also_peer:
                self.h_do_socket_shutdown(sock.get_peer(), safe_print=safe_print)

    def h_do_socket_shutdown(self, sock, safe_print=False):
        print(SUBTAG2+sock.get_safe_desc()) if safe_print else print(SUBTAG2+sock.get_desc())
        self.epoll.modify(sock.fd(), 0)  # clear epol read/write eventmask
        sock.sock.shutdown(socket.SHUT_RDWR)  # polite shutdown
        sock.is_shutdown = True  # for ttl cleanup routine
        self.sock_terminate(sock.fd())  # TODO make sure ttl_cleanup also_terminate=False

    def sock_terminate(self, fd):
        # close the socket, update its corresponding peer socket
        print(SECTAG+'proxy sock_terminate : closing socket ', end='')
        sock = self.sock_by_fd.get(fd, None)
        if sock is None:
            print(SUBTAG2+'error socket {} is None'.format(fd))
            return
        print('fd {} .. '.format(fd), end='')
        # for cases where shutdown event came externally,
        # update peer-socket that this socket is gone
        peer = sock.get_peer()
        if peer is not None:
            peer.peer = None
            # print(SUBTAG + 'peer   : {}'.format(peer.fd()))
        # delete socket
        self.h_socket_delete(sock)
        # done!
        print('done!')

    def h_socket_delete(self, sock):
        fd = sock.fd()  # after close sock,fd becomes -1
        self.epoll.unregister(fd)  # completely remove from epoll
        sock.sock.close()
        del self.sock_by_fd[fd]

    def ttl_cleanup(self):
        print(MAINTAG+'ttl cleanup : {} connections exist'.format(len(self.sock_by_fd) // 2))
        # list of active or shutdown sockets. (no terminated sockets)
        socks_list_copy = list(self.sock_by_fd.values())  # .items() is a view, can't be iterated while del items
        for sock in socks_list_copy:
                self.h_is_ttl_expired_shutdown(sock, also_terminate=False)

        print(MAINTAG+'ttl cleanup : done!')

    def h_update_ttl(self, sock):
        sock.latime = time.time()

    def h_is_ttl_expired_shutdown_or_update(self, sock):
        if self.h_is_ttl_expired_shutdown(sock):
            # ttl expired and socket was shutdown
            return True
        else:
            # update socket time
            sock.latime = time.time()
            return False

    def h_is_ttl_expired_shutdown(self, sock, also_terminate=False):
        if (time.time() - sock.latime) >= self.ttl_secs:
            # ttl expired - socket pair shutdown
            fd = sock.fd()
            peer = sock.get_peer()
            print(SECTAG+'proxy ttl - fd {} timeout expired!'.format(fd))
            self.sock_shutdown(fd)
            if also_terminate:
                self.sock_terminate(fd)
            return True
        return False


    #
    #
    def run_proxy(self):

        def print_wait_msg():
            print('\n'+MAINTAG+'proxy main : waiting for events... ', end='')

        # set to running state
        self.running = True
        listen_fd = self.listen_socket.fileno()

        print('\n'+MAINTAG+'proxy main : ** PROXY STARTING **')
        print_wait_msg()

        # run main proxy loop
        try:
            while self.running:

                # Polls the set of registered file descriptors,
                # and returns a possibly-empty list of (fd, event)
                # for the descriptors that have events or errors to report.
                events = self.epoll.poll(1)  # timeout in secs

                # loop polled events and handle accordingly
                # http://man7.org/linux/man-pages/man2/epoll_ctl.2.html
                for fd, event in events:
                    # ---------------------------------------------------------------------------
                    #
                    # -- event at listening socket --
                    if fd == listen_fd:
                        print('event -->  new connection at listen socket', fd)
                        self.ttl_cleanup()  # cleanup routine to shutdown expired sockets
                        self.accept_new_client()
                        print_wait_msg()
                        continue

                    #
                    # -- skip deleted sockets --
                    if fd not in self.sock_by_fd:
                        # terminated socket or peer may still be on currently polled event list
                        print('event -->  skipping event for non-listed fd', fd)
                        print_wait_msg()
                        continue

                    #
                    # -- events at non-listening socket --

                    # incoming, read ready
                    elif event & select.EPOLLIN:
                        print('event -->  incoming at', fd)
                        self.sock_receive_and_forward(fd)
                        print_wait_msg()

                    # write-ready
                    elif event & select.EPOLLOUT:
                        print('event -->  ready outgoing send at', fd)
                        self.sock_send_buffer(fd)
                        print_wait_msg()

                    # hang up   # shutdown   # error
                    elif event & (EPOLLRDHUP | select.EPOLLERR):
                        print('event -->  hangup, shutdown or error at', fd)
                        self.sock_terminate(fd)
                        print_wait_msg()

                    # ---------------------------------------------------------------------------

                #
                # -- try to send all non-empty buffers --
                # after each polling - attempt sends on all empty buffers
                # update their ttl only if successful
                # sock_send_buffer()



        finally:
            print('\n'+MAINTAG+'proxy main : ** PROXY SHUTDOWN.. **\n')
            self.epoll.unregister(self.listen_socket.fileno())
            self.epoll.close()
            self.listen_socket.shutdown(socket.SHUT_RDWR)
            self.listen_socket.close()


