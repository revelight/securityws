import ctypes
import socket

retval_ok = 0
retval_err = 1

# char devices and sysfs

# .. not for use - modular preps
cd_rules_path = '/dev/fw_rules'
cd_log_path = '/dev/fw_log'
cd_conntab_path = '/dev/fw_conntab'
sysfs_class_base_path = '/sys/class/fw/'
sysfs_rules_path = sysfs_class_base_path + 'fw_rules' + '/'
sysfs_log_path = sysfs_class_base_path + 'fw_log' + '/'
sysfs_cons_path = sysfs_class_base_path + 'fw_conntab' + '/'

# .. use these - ready file paths (fp)
fp_rules_active = sysfs_rules_path + 'active'
fp_rules_size = sysfs_rules_path + 'rules_size'
fp_log_size = sysfs_log_path + 'log_size'
fp_log_clear = sysfs_log_path + 'log_clear'
fp_cons_update = sysfs_cons_path + 'conntab_update'
fp_cd_rules = cd_rules_path
fp_cd_logs = cd_log_path
fp_cd_conntab = cd_conntab_path



eth_list = ('10.1.1.3', '10.1.2.3')
eth_net_out = eth_list[0]
eth_net_in = eth_list[1]



# ntov == Name to Value
# vton == Value to Name
# all values in NETWORK ORDER


# ip (*not* 1:1)
user_ip_and_prefix_to_host_ints = {'any' : (0,0,0)}
host_prefix_to_user_ip_and_prefix_str = {0 : 'any'}

# protocol 1:1
protocol_ntov = {'ICMP': 1, 'TCP': 6, 'UDP': 17, 'OTHER': 255, 'any': 143}
protocol_vton = dict([[v, k] for k, v in protocol_ntov.items()])

# action 1:1
action_ntov = {'accept': 1, 'drop': 0} # netfilter values
action_vton = dict([[v,k] for k,v in action_ntov.items()])

# ack 1:1
ack_ntov = {'no': 1, 'yes': 2, 'any': 3}
ack_vton = dict([[v,k] for k,v in ack_ntov.items()])


# direction 1:1
direction_ntov = {'in': 1, 'out': 2, 'any': 3}
direction_vton = dict([[v, k] for k, v in direction_ntov.items()])

# port (*not* 1:1)
port_ntov = {'any' : 0, '>1023' : 1023}
port_vton = dict([[v,k] for k,v in port_ntov.items()])

# reason (*not* 1:1)
REASON_ILLEGAL_LIMIT_UPPER = 51
REASON_ILLEGAL_LIMIT_LOWER = -7
reason_vton = {-1 : 'REASON_FW_INACTIVE',
               -2: 'REASON_NO_MATCHING_RULE',
               -3: 'REASON_XMAS_PACKET',
               -4: 'REASON_CONNTABLE_TCP',
               -5: 'REASON_ANOMALY_CASE',
               -6: 'REASON_NO_MATCHING_FILTER',
               }
# .. no need for ntov version - only used in kernel->user


# tcp state 1:1
tcpstate_vton = {

    0 : 'FW_TCP_PENDING_CONNECTION',

    1 : 'FW_TCP_OPEN_SYN_SENT',
    2 : 'FW_TCP_OPEN_WAITING_SYN_ACK',
    3 : 'FW_TCP_OPEN_WAITING_ACK',
    4 : 'FW_TCP_OPEN_SYNACK_SENT',

    5 : 'FW_TCP_ESTABLISHED',

    6 : 'FW_TCP_CLOSE_FIN_SENT',
    7 : 'FW_TCP_CLOSE_WAITING_ACK',
    8 : 'FW_TCP_CLOSE_FIN_ACKED',
    9 : 'FW_TCP_CLOSE_WAITING_FIN',
    10 : 'FW_TCP_CLOSE_WAITING_ACK2',
    11 : 'FW_TCP_CLOSE_FIN2_SENT',

    12 : 'FW_TCP_CLOSED_CONNECTION',
}
# .. no need for ntov version - only used in kernel->user







# rule

rules_inline_sep = ' '

class HostRule:
    name = None                 # up to 20 chars
    direction = None            # dict value
    src_ip = None               # 32 bit unsigned int: 0 to 4,294,967,295
    src_prefix_mask = None
    src_prefix_size = None      # num of obscured bit in a 32 bit address: 0-32
    dst_ip = None
    dst_prefix_mask = None
    dst_prefix_size = None
    protocol = None             # dict value
    src_port = None             # dict value, else: 16 bit unsigned short int: 0-65535 except 0 or 1023
    dst_port = None
    ack = None                  # dict value
    action = None               # dict value

    def asHostStr(self):
        return '{0}{sep}{1}{sep}{2}{sep}{3}{sep}{4}{sep}{5}' \
               '{sep}{6}{sep}{7}{sep}{8}{sep}{9}{sep}{10}\n'.format(
            self.name, self.direction,
            self.src_ip, self.src_prefix_size,
            self.dst_ip, self.dst_prefix_size,
            self.protocol,
            self.src_port, self.dst_port,
            self.ack, self.action,
            sep=rules_inline_sep,
        )




# log
logs_header_line = 'timestamp' + '\t' + \
                   'src_ip' + '\t' + 'dst_ip' + '\t' + \
                   'src_port' + '\t' + 'dst_port' + '\t' + \
                   'protocol' + '\t' + 'hooknum' + '\t' + \
                   'action' + '\t' + 'reason' + '\t' + 'count' + '\n'

logs_inline_sep = '\t'


class HostLog:
    timestamp = None            # system time int format, to be printed as: 03/04/2016 14:05:34  19-chars
    src_ip = None               # 32 bit unsigned int: 0 to 4,294,967,295
    dst_ip = None
    src_port = None             # dict value, else: 16 bit unsigned short int: 0-65535 except 0 or 1023
    dst_port = None
    protocol = None             # dict value
    hooknum = None              # int 0-4
    action = None               # dict value
    reason = None               # dict value, else: rule number
    count = None                # unsigned int


    def asUserStr(self):
        return '{0} {1} {2} {3} {4} {5} {6} {7} {8} {9}\n'.format(
            self.timestamp,
            self.src_ip, self.dst_ip,
            self.src_port, self.dst_port,
            self.protocol, self.hooknum,
            self.action, self.reason, self.count
        )





# connection
cons_header_line = 'c_ip' + '\t' + 'c_port' + '\t' + \
                   's_ip' + '\t' + 's_port' + '\t' + \
                   'c_state' + '\t' + \
                   's_state' + '\t' + \
                   'ps_state' + '\t' + \
                   'pc_state' + '\t' + \
                   'ps_port' + '\t' + \
                   'pc_port' + '\t' + \
                   'timestamp' + '\n'

cons_inline_sep = '\t'


class HostCon:
    a_ip = None               # 32 bit unsigned int: 0 to 4,294,967,295
    a_port = None             # dict value, else: 16 bit unsigned short int: 0-65535 except 0 or 1023
    b_ip = None
    b_port = None
    a_protocol_state = None             # dict value
    b_protocol_state = None             # dict value

    ps_protocol_state = None  # dict value
    pc_protocol_state = None  # dict value

    ps_port = None
    pc_port = None

    timestamp = None            # system time int format, to be printed as: 03/04/2016 14:05:34  19-chars


    def asUserStr(self):
        return '{0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10}\n'.format(
            self.a_ip, self.a_port,
            self.b_ip, self.b_port,
            self.a_protocol_state, self.b_protocol_state,
            self.ps_protocol_state, self.pc_protocol_state,
            self.ps_port, self.pc_port,
            self.timestamp
        )








# other consts


