from parser_field_helpers import *
import re
import time

# RULES


def h_rule__host_line_from_user_line(user_line):

    uline = user_line.split()
    if len(uline)!= 9:
        print('invalid num of arguments in user line: {}'.format(uline))
        return None
    idx = 0


    hrule = HostRule()

    #name
    if len(uline[idx])>20:
        print('rule name too long and will be trunced: {}'.format(uline[idx]))
        # accept trunced name - warning only
    hrule.name = uline[idx][0:20+1]
    idx += 1

    #direction
    hrule.direction = h_field_1to1__ntov_user_str_to_host_str(uline[idx], direction_ntov, "direction")
    if hrule.direction == None:
        return None  # err report done by function
    idx += 1

    #src ip, prefix size, prefix mask
    hrule.src_ip, hrule.src_prefix_size, hrule.src_prefix_mask = \
        h_ip_and_pfs__user_str_net_to_host_ints(uline[idx])
    if hrule.src_ip==None:
        return None #print done by function
    idx += 1

    #dst ip, prefix size, prefix mask
    hrule.dst_ip, hrule.dst_prefix_size, hrule.dst_prefix_mask = \
        h_ip_and_pfs__user_str_net_to_host_ints(uline[idx])
    if hrule.dst_ip==None:
        return None #print done by function
    idx += 1

    # protocol
    hrule.protocol = h_field_1to1__ntov_user_str_to_host_str(uline[idx], protocol_ntov, "protocol")
    if hrule.protocol == None:
        return None  # err report done by function
    idx += 1

    #src port
    hrule.src_port = h_port__host_int_from_user_str_net(uline[idx])
    if hrule.src_port == None:
        return None  # print done by function
    idx += 1

    #dst port
    hrule.dst_port = h_port__host_int_from_user_str_net(uline[idx])
    if hrule.dst_port == None:
        return None  # print done by function
    idx += 1

    #ack
    hrule.ack = h_field_1to1__ntov_user_str_to_host_str(uline[idx], ack_ntov, "ack")
    if hrule.ack == None:
        return None  # err report done by function
    idx += 1

    # action
    hrule.action = h_field_1to1__ntov_user_str_to_host_str(uline[idx], action_ntov, "action")
    if hrule.action == None:
        return None  # err report done by function
    idx += 1

    return hrule.asHostStr()




def h_rule__user_line_from_host_line(host_line):

    hline = host_line.split()
    if len(hline)!= 11:
        print('\ninvalid num of arguments in host line: {}'.format(hline))
        return None
    idx = 0

    entry = ''
    res_user_line = ''

    #name
    if len(hline[idx])>20:
        # accept trunced, warning only
        print('rule name too long and will be trunced: {}'.format(hline[idx]))
    entry = hline[idx][0:20+1]
    idx += 1
    res_user_line += str(entry) #first entry - no leading space

    #direction
    entry = h_field_1to1__vton_user_str_from_host_str(hline[idx], direction_vton, "direction")
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += ' ' + str(entry)

    #src ip, prefix size, prefix mask
    entry = h_ip_and_pfs__host_str_to_user_net_str(hline[idx], hline[idx + 1])
    if entry==None:
        return None # err report done by function
    idx += 2
    res_user_line += ' ' + str(entry)

    #dst ip, prefix size, prefix mask
    entry = h_ip_and_pfs__host_str_to_user_net_str(hline[idx], hline[idx + 1])
    if entry==None:
        return None # err report done by function
    idx += 2
    res_user_line += ' ' + str(entry)

    #protocol
    entry = h_field_1to1__vton_user_str_from_host_str(hline[idx], protocol_vton, "protocol")
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += ' ' + str(entry)

    #src port
    entry = h_port_rule__user_str_net_from_host_str(hline[idx])
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += ' ' + str(entry)

    #dst port
    entry = h_port_rule__user_str_net_from_host_str(hline[idx])
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += ' ' + str(entry)

    #ack
    entry = h_field_1to1__vton_user_str_from_host_str(hline[idx], ack_vton, "ack")
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += ' ' + str(entry)

    # action
    entry = h_field_1to1__vton_user_str_from_host_str(hline[idx], action_vton, "action")
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += ' ' + str(entry)

    res_user_line += '\n'

    # done!
    return res_user_line




# LOGS


def h_log__user_line_from_host_line(host_line):

    hline = host_line.split()
    if len(hline)!= 10:
        print('\ninvalid num of arguments in host line: {}'.format(hline))
        return None
    idx = 0

    entry = ''
    res_user_line = ''

    # timestamp
    try: # numeric system time
        epoch_time = int(hline[idx])
    except ValueError:
        print('could not resolve timestamp int: {}'.format(hline[idx]))
        return None
    entry = time.strftime('%d/%m/%Y %H:%M:%S', time.localtime(epoch_time))
    idx += 1
    res_user_line += str(entry) #first entry - no leading space

    # src ip
    entry = h_ip__user_ip_rep_str_from_host_int_str(hline[idx])
    if entry==None:
        return None # err report done by function
    idx += 1
    res_user_line += logs_inline_sep + str(entry)

    # dst ip
    entry = h_ip__user_ip_rep_str_from_host_int_str(hline[idx])
    if entry==None:
        return None # err report done by function
    idx += 1
    res_user_line += logs_inline_sep + str(entry)

    #src port
    entry = h_port_logorcon__user_str_net_from_host_str(hline[idx])
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += logs_inline_sep + str(entry)

    #dst port
    entry = h_port_logorcon__user_str_net_from_host_str(hline[idx])
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += logs_inline_sep + str(entry)

    #protocol
    entry = h_field_1to1__vton_user_str_from_host_str(hline[idx], protocol_vton, "protocol")
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += logs_inline_sep + str(entry)

    # hooknum
    try:
        entry = int(hline[idx])
    except ValueError:
        print('could not resolve hooknum int: {}'.format(hline[idx]))
        return None

    if not (0<=entry<=4):
        print('hooknum int out of range: {}'.format(hline[idx]))
        return None
    entry = str(entry)
    idx += 1
    res_user_line += logs_inline_sep + str(entry)

    # action
    entry = h_field_1to1__vton_user_str_from_host_str(hline[idx], action_vton, "action")
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += logs_inline_sep + str(entry)

    # reason
    entry = h_reason__user_str_net_from_host_str(hline[idx])
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += logs_inline_sep + str(entry)

    # count
    try:
        entry = int(hline[idx])
    except ValueError:
        print('could not resolve count int: {}'.format(hline[idx]))
        return None
    idx += 1
    res_user_line += logs_inline_sep + str(entry)


    res_user_line += '\n'

    # done!
    return res_user_line




# CONNECTIONS

def h_con__user_line_from_host_line(host_line):

    hline = host_line.split()
    if len(hline)!= 11:
        print('\ninvalid num of arguments in host line: {}'.format(hline))
        return None
    idx = 0

    entry = ''
    res_user_line = ''

    # c ip
    entry = h_ip__user_ip_rep_str_from_host_int_str(hline[idx])
    if entry==None:
        return None # err report done by function
    idx += 1
    res_user_line += str(entry)  #first entry - no leading space

    # c port
    entry = h_port_logorcon__user_str_net_from_host_str(hline[idx])
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += cons_inline_sep + str(entry)

    # s ip
    entry = h_ip__user_ip_rep_str_from_host_int_str(hline[idx])
    if entry==None:
        return None # err report done by function
    idx += 1
    res_user_line += cons_inline_sep + str(entry)

    # s port
    entry = h_port_logorcon__user_str_net_from_host_str(hline[idx])
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += cons_inline_sep + str(entry)

    #protocol state
    entry = h_field_1to1__vton_user_str_from_host_str(hline[idx], tcpstate_vton, "tcpstate")
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += cons_inline_sep + str(entry)

    #protocol state
    entry = h_field_1to1__vton_user_str_from_host_str(hline[idx], tcpstate_vton, "tcpstate")
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += cons_inline_sep + str(entry)

    # protocol state
    entry = h_field_1to1__vton_user_str_from_host_str(hline[idx], tcpstate_vton, "tcpstate")
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += cons_inline_sep + str(entry)

    # protocol state
    entry = h_field_1to1__vton_user_str_from_host_str(hline[idx], tcpstate_vton, "tcpstate")
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += cons_inline_sep + str(entry)

    # port
    entry = h_port_logorcon__user_str_net_from_host_str(hline[idx])
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += cons_inline_sep + str(entry)

    # port
    entry = h_port_logorcon__user_str_net_from_host_str(hline[idx])
    if entry == None:
        return None  # err report done by function
    idx += 1
    res_user_line += cons_inline_sep + str(entry)

    # timestamp
    try: # numeric system time
        epoch_time = int(hline[idx])
    except ValueError:
        print('could not resolve timestamp int: {}'.format(hline[idx]))
        return None
    if epoch_time==0:
        entry = "no timeout"
    else:
        entry = time.strftime('%d/%m/%Y %H:%M:%S', time.localtime(epoch_time))
    idx += 1
    res_user_line += cons_inline_sep + str(entry) #first entry - no leading space


    res_user_line += '\n'

    # done!
    return res_user_line










# Parsing Callers


def h_rules__host_entire_str_from_user_entire_file(f):

    # parse line by line
    host_rules_str = ''
    host_line = None
    for nline, line in enumerate(f):

        #print('read line rules user:  {}'.format(line), end='')

        line = line.rstrip('\n')  # strip ending newline, used to distinguish empty line / EOF
        host_line = h_rule__host_line_from_user_line(line)


        # error check
        if host_line == None:
            print('Error interperting user rules file:  canceling on line: {}'.format(nline))
            return None
        else:
            # line parse ok!
            #print('--> result line host:  {}'.format(host_line), end='')
            # append it
            host_rules_str += host_line

    # report
    print('\n\nparsed host rules are:')
    print_str_table(host_rules_str, rules_inline_sep)

    f.seek(0) # rewind file for producing return val for testing
    return host_rules_str, f.read()



def h_rules__user_entire_str_from_host_entire_str(host_rules_str):

    user_str = ''
    nline = -1;

    host_lines = host_rules_str.splitlines()
    #print(host_lines)

    # parse line by line
    for line in host_lines:
        nline += 1
        #print('read line rules host:  {}'.format(line))

        user_line = h_rule__user_line_from_host_line(line)

        # error check
        if user_line == None:
            #print('Error interperting host rules string:  canceling on line: {}'.format(nline))
            return None
        else:
            # line parse ok!
            #print('--> result line user:  {}'.format(user_line), end='')
            # append it
            user_str += user_line

    if user_str == '':
        print("no lines read")
        return None # no lines read

    # report
    #print('\n\nconverted user rules are:')
    #print(user_str)

    return user_str



def h_logs__user_entire_str_from_host_entire_str(host_log_str):

    user_str = logs_header_line
    nline = -1;

    host_lines = host_log_str.splitlines()
    #print(host_lines)

    # parse line by line
    for line in host_lines:
        nline += 1
        #print('read line logs host:  {}'.format(line))

        user_line = h_log__user_line_from_host_line(line)

        # error check
        if user_line == None:
            print('Error interperting host logs string:  canceling on line: {}'.format(nline))
            return None
        else:
            # line parse ok!
            #print('--> result line user:  {}'.format(user_line), end='')
            # append it
            user_str += user_line

    # report
    print('\n\nconverted user logs are:')
    print_str_table(user_str, logs_inline_sep)

    return user_str




def h_cons__user_entire_str_from_host_entire_str(host_cons_str):

    user_str = cons_header_line
    nline = -1;

    host_lines = host_cons_str.splitlines()
    #print(host_lines)

    # parse line by line
    for line in host_lines:
        nline += 1
        #print('read line cons host:  {}'.format(line))

        user_line = h_con__user_line_from_host_line(line)

        # error check
        if user_line == None:
            print('Error interperting host cons string:  canceling on line: {}'.format(nline))
            return None
        else:
            # line parse ok!
            #print('--> result line user:  {}'.format(user_line), end='')
            # append it
            user_str += user_line

    # report
    #print('\n\nconverted user cons are:')
    #print_str_table(user_str, cons_inline_sep)

    return user_str






# OTHER HELPERS


def h_split_str(str, delim):

    return [re.split('\n|'+delim,line) for line in str.splitlines()]


# word delimiters: \t or space
def print_str_table(str, delim):

    print('\n----table start----')

    striped_str = h_split_str(str, delim)

    #print(striped_str)

    col_width = max(len(word) for line in striped_str for word in line) + 2  # padding
    #print('max word len:{}'.format(col_width))

    for line in striped_str:
        for word in line:
            print ('{:<{width}}'.format(word, width=col_width), end='')
        print()

    print('-----table end-----\n')



def print_line_fixed_col_size(line):
    words = [word for word in re.split(' |\t|\n|/',line)]

    for word in words:
        print('{:<{width}}'.format(word, width=12), end='')
    print()



def print_diffs(str1, str2):
    # handle the case where one string is longer than the other
    maxlen = len(str2) if len(str1) < len(str2) else len(str1)

    print(len(str1), len(str2))

    result1 = ''
    result2 = ''
    # loop through the characters
    for i in range(maxlen):
        # use a slice rather than index in case one string longer than other
        letter1 = str1[i:i + 1]
        letter2 = str2[i:i + 1]
        # create string with differences
        if letter1 != letter2:
            result1 += letter1
            result2 += letter2

    # print out result
    print("\n\nLetters different in string 1:\n", result1)
    print("\n\nLetters different in string 2:\n", result2)