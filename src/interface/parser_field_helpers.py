from fw_standards import *
from wscm_file_handlers import *
import socket
import struct

# ip and masks helpers

# https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
# https://docs.python.org/2/library/struct.html
# uses: 'I' or !I' etc, when:
#  I : unsigned int, < little endian, > big endian, ! : network (big_endian)
def ip2int(addr):
    return struct.unpack("I", socket.inet_aton(addr))[0]
def int2ip(addr):
    return socket.inet_ntoa(struct.pack("I", addr))


# host will calc own prefix mask - this is for checking
def h_prefix_mask_from_prefix_size(size):
    # size is num of bits from the left that are 1
    bin_str = '{:{}<{}}'.format('','1', size)
    bin_str = bin_str + '{:{}<{}}'.format('','0', 32-size)
    return int(bin_str, 2)


def h_ip_and_pfs__user_str_net_to_host_ints(user_ip_str):
    # expect: <'any'> or <x.x.x.x ip>/<prefix size>

    # resolve as name - 'any'
    if (user_ip_str in user_ip_and_prefix_to_host_ints):
        # prefix size 0 - means compare no bits in address, thus 'any'
        return user_ip_and_prefix_to_host_ints.get(user_ip_str)

    # resolve as address/size format
    strs = user_ip_str.split('/')
    if len(strs)!=2:
        print('error in ip: {}'.format(strs))
        return None, None, None

    # get ip as int
    try: # resolve as ip address
        ip = ip2int(strs[0])
    except OSError as e:
        print('could not resolve ip: {}'.format(strs[0]))
        return None, None, None

    # get prefix mask from size (just for checkup, will not transfer to host)
    try:
        prefix_size = int(strs[1])
        prefix_mask = h_prefix_mask_from_prefix_size(prefix_size)
    except ValueError:
        print('could not resolve prefix size: {}'.format(strs[1]))
        return None, None, None

    # finally convert network to host
    ip = socket.ntohl(ip)
    # prefix_size remains as normal number
    prefix_mask = socket.ntohl(prefix_mask)

    return ip, prefix_size, prefix_mask




def h_ip__user_ip_rep_str_from_host_int_str(ip_str):

    # get numerics from string
    try:
        ip = int(ip_str)
    except ValueError:
        print('could not resolve ip int: {}'.format(ip_str))
        return None

    # convert host to network
    ip = socket.htonl(ip)

    # get ip presentation from net int
    try:
        ip_res = int2ip(ip)
    except OSError as e:
        print('could not resolve ip: {}'.format(ip))
        return None

    return ip_res



def h_ip_and_pfs__host_str_to_user_net_str(host_ip_str, host_prefixsize_str):
    # expect: <host ip int> , <prefix size as normal number>

    # get numerics from strings
    try:
        prefix_size = int(host_prefixsize_str)
    except ValueError:
        print('could not resolve prefix int: {}'.format(host_prefixsize_str))
        return None

    # resolve for special mask value
    if (prefix_size in host_prefix_to_user_ip_and_prefix_str):
        # prefix size 0 - means compare no bits in address, thus 'any'
        return host_prefix_to_user_ip_and_prefix_str.get(prefix_size)

    # double check value range for prefix
    if not (0 <= prefix_size <= 32):
        print('host prefix size not in range: {}'.format(prefix_size))
        return None


    # get ip presentation
    ip_str = h_ip__user_ip_rep_str_from_host_int_str(host_ip_str)

    # ready to make the user string!
    return ip_str + '/' + str(prefix_size)





# port helpers

def h_port__host_int_from_user_str_net(port_str):

    # dict
    if port_str in port_ntov:
        port = port_ntov.get(port_str)
    else:
        # numeric
        try:
            port = int(port_str)
        except ValueError:
            print('could not resolve port int: {}'.format(port_str))
            return None

        # numeric range check
        if not (1 <= port <= 1022 or 1024 <= port <= 65535):
            print('port not in legal range: {}'.format(port_str))
            return None

    # always : numeric return - convert network to host
    #port = socket.ntohs(port)

    return port




def h_port_rule__user_str_net_from_host_str(port_str):

    # host str to int
    try:
        port = int(port_str)
    except ValueError:
        print('could not resolve port int: {}'.format(port_str))
        return None

    # host int to net int - we evaluate in network order
    #port = socket.htons(port)

    # numeric range check
    if not (0 <= port <= 65535):
        print('port not in legal range: {}'.format(port_str))
        return None

    # dict
    if port in port_vton:
        port = port_vton.get(port)

    return port



def h_port_logorcon__user_str_net_from_host_str(port_str):

    # host str to int
    try:
        port = int(port_str)
    except ValueError:
        print('could not resolve port int: {}'.format(port_str))
        return None

    # host int to net int - we evaluate in network order
    #port = socket.htons(port)

    # numeric range check
    if not (0 <= port <= 65535):
        print('port not in legal range: {}'.format(port_str))
        return None


    return port







# reason helpers

def h_reason__user_str_net_from_host_str(reason_str):

    # host str to int
    try:
        reason = int(reason_str)
    except ValueError:
        print('could not resolve reason int: {}'.format(reason_str))
        return None

    # numeric range check
    if not (REASON_ILLEGAL_LIMIT_LOWER < reason < REASON_ILLEGAL_LIMIT_UPPER):
        print('reason not in legal range: {}'.format(reason_str))
        return None

    # dict
    if reason in reason_vton:
        reason = reason_vton.get(reason)

    return reason



# 1to1 vton / ntov generic dictionary parsers


def h_field_1to1__vton_user_str_from_host_str(host_int_str, vton_dict, field_title):
    try:
        if int(host_int_str) in vton_dict:
            return vton_dict.get(int(host_int_str))
        else:
            print(field_title +' entry not supported: {}'.format(host_int_str))
    except ValueError:
        print(field_title +' entry not a number: {}'.format(host_int_str))
    return None



def h_field_1to1__ntov_user_str_to_host_str(user_str, ntov_dict, field_title):

    #print('--> field: {}'.format(user_str))
    #print('--> ntov: {}'.format(ntov_dict))

    if user_str in ntov_dict:
        return ntov_dict.get(user_str)
    else:
        print(field_title +' entry not supported: {}'.format(user_str))
        return None
