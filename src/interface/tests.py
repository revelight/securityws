from main import *
from parser import *
import difflib


def readwrite():

    str = h_file__read_str_from_file('/home/fw/Desktop/pycharm_ws/interface/logs_host_t')

    h_file__write_str_to_device('/home/fw/Desktop/pycharm_ws/interface/written', str)


def test_logs():

    userfile = h_file__read_str_from_file('/home/fw/Desktop/pycharm_ws/interface/logs_host_t')

    print("read this string from file:")
    print(userfile)

    hostlogs = h_logs__user_entire_str_from_host_entire_str(userfile)



def test_rules():
    hostrules, userfile = fw_load_rules('/home/fw/Desktop/pycharm_ws/interface/rules_t')

    userrules = h_rules__user_entire_str_from_host_entire_str(hostrules)

    print()
    print(userfile)
    print(hostrules)
    print(userrules)

    print_diffs(userfile, userrules)



def test_time():
    epoch_time = int(time.time())
    entry = time.strftime('%d/%m/%Y %H:%M:%S', time.localtime(epoch_time))
    print(epoch_time, entry)



def test_fw_sysfs():
    fw_set_active()
    fw_set_inactive()
    fw_get_log_size()
    fw_get_rule_size()
    fw_clear_log()


# uses: 'I' or !I' etc, when:
#  I : unsigned int, < little endian, > big endian, ! : network (big_endian)
def tip2int(addr):
    return struct.unpack("I", socket.inet_aton(addr))[0]
def tint2ip(addr):
    return socket.inet_ntoa(struct.pack("I", addr))


a = tip2int('127.0.0.1')
print(a)

print(socket.ntohl(a))


#test_rules()
#test_logs()
#readwrite()

#test_fw_sysfs()
#print()

#main()

#fw_show_rules()