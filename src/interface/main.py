import sys
from parser import *


# char device commands


def fw_load_rules(rules_file_path):
    # parse user rule file to host string
    with fopen_wscm(rules_file_path, 'r') as f:
        if f == None:
            return None

        host_rules_str, user_rules_from_file = h_rules__host_entire_str_from_user_entire_file(f)

    # write str to char device
    h_file__write_str_to_device(fp_cd_rules, host_rules_str)

    # show verify
    fw_show_rules()

    return host_rules_str, user_rules_from_file


def fw_show_rules():
    print("reading host string from fw..")
    str = h_file__read_str_from_file(fp_cd_rules)

    # string check - for testing
    #print(str) # ok in print - not ok as list,
    #print(str.split())
    #fixed rouge bits from C, from snprintf
    #str = str.replace('\x00', '\n')
    #print(str)

    print("parsing host str..")
    res = h_rules__user_entire_str_from_host_entire_str(str)
    if res != None:
        print_str_table(res, rules_inline_sep)


def fw_show_log():
    print("reading host string from fw..")
    str = h_file__read_str_from_file(fp_cd_logs)

    # string check - for testing
    print(str)
    #print(str.split())
    #str = str.replace('\x00', '\n')
    #print(str)

    print("parsing host str..")
    h_logs__user_entire_str_from_host_entire_str(str)



def fw_show_cons():
    print("reading host string from fw..")
    str = h_file__read_str_from_file(fp_cd_conntab)

    # string check - for testing
    print(str)
    #print(str.split())
    #str = str.replace('\x00', '\n')
    #print(str)

    print("parsing host str..")
    user_str = h_cons__user_entire_str_from_host_entire_str(str)

    # print result
    print('\n\nconverted user cons are:')
    print_str_table(user_str, cons_inline_sep)




# sysfs commands

def fw_clear_rules():
    h_file__write_str_to_device(fp_cd_rules, '$clear_rules$')


def fw_clear_log():
    with fopen_wscm(fp_log_clear, 'w') as f:
        with fwrite_wscm(f, '0') as nchars_written:
            #print("wrote {} bytes".format(nchars_written))
            print('clearing logs')
            pass


def fw_get_rule_size():
    with fopen_wscm(fp_rules_size, 'r') as f:
        with fread_wscm(f) as data:
            print("read fw rules size: {}".format(data))


def fw_get_log_size():
    with fopen_wscm(fp_log_size, 'r') as f:
        with fread_wscm(f) as data:
            print("read fw logs size: {}".format(data))


# active mode

def fw_set_active_mode(zero_one):
    # write active mode
    with fopen_wscm(fp_rules_active, 'w') as f:
        with fwrite_wscm(f, zero_one) as nchars_written:
            #print("wrote {} bytes".format(nchars_written))
            pass

    fw_read_active()


def fw_read_active():
    # read active mode
    with fopen_wscm(fp_rules_active, 'r') as f:
        with fread_wscm(f) as data:
            print("fw active status is now: {}".format(data))


def fw_set_active():
    fw_set_active_mode('1')


def fw_set_inactive():
    fw_set_active_mode('0')


# == USER INPUT AND COMMANDS


cmd_txt = \
    '\n< Firewall interface Commands >\n' \
    '\n __Active mode\n' \
    '       on : a0\n' \
    '      off : a1\n' \
    '   status : a?\n' \
    '\n __Rules\n' \
    '     show : rs\n' \
    '    clear : rc\n' \
    '     size : rz\n' \
    '     load : rl <path>\n' \
    '\n __Logs\n' \
    '     show : ls\n' \
    '    clear : lc\n' \
    '     size : lz\n' \
    '\n __Connections\n' \
    '     show : cs\n' \
    '\n __General\n' \
    '     help : help\n' \
    '     exit : exit\n'

cmds_to_funcs_1 = {'a1': fw_set_active,
                   'a0': fw_set_inactive,
                   'a?': fw_read_active,
                   'rs': fw_show_rules,
                   'rc': fw_clear_rules,
                   'rz': fw_get_rule_size,
                   'ls': fw_show_log,
                   'lc': fw_clear_log,
                   'lz': fw_get_log_size,
                   'cs': fw_show_cons,
                   }

cmds_to_funcs_2 = {'rl': fw_load_rules}




def bad_cmd_func():
    print("oops check your command")

def bad_cmd_func2(cmd):
    print("oops check your command")



def get_and_dist_user_cmd():
    # console args / session mode
    argmode = 0
    if argmode == 1:
        cmd_input = sys.argv[1:]  # discard 1st arg is program name
    else:
        # get user input
        cmd_input = input().split(' ')

    if cmd_input[0] == 'exit':
        return 1

    if cmd_input[0] == 'help':
        print(cmd_txt)
        return

    # run the function associated with the command.
    # if not in cmd dict - run a bad cmd func
    if len(cmd_input) == 1:
        cmds_to_funcs_1.get(cmd_input[0], bad_cmd_func)()
        return

    if len(cmd_input) == 2:
        cmds_to_funcs_2.get(cmd_input[0], bad_cmd_func2)(cmd_input[1])
        return

    # wrong num of args
    bad_cmd_func()
    return


def main():
    print('\n\nWelcome to fw interface')
    print(cmd_txt)

    is_quit = False
    while not is_quit:
        is_quit = get_and_dist_user_cmd()

    print('goodbye!\n\n')

main()
