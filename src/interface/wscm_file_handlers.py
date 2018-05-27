import os.path


# file handling helpers

# With Statement Context Managers

class fopen_wscm:

    def __init__(self, fpath, mode):
        self.fpath = fpath
        self.mode = mode

    def __enter__(self):

        if not os.path.exists(self.fpath):
            raise Exception('Tried to open non existing file')

        self.openedfile = open(self.fpath, self.mode)
        return self.openedfile

    def __exit__(self, exc_type, exc_value, traceback):

        # report errors
        if (isinstance(exc_value, OSError)
            or isinstance(exc_value, IOError)
            or isinstance(exc_value, EnvironmentError)):

            print ("File Open Exception! " + str(exc_type))

        # close file
        self.openedfile.close()



class fwrite_wscm:
    def __init__(self, file, data):
        self.file = file
        self.data = data

    def __enter__(self):
        return self.file.write(self.data)

    def __exit__(self, exc_type, exc_value, traceback):

        # report errors
        if isinstance(exc_value, Exception):
            print("File Write Exception! " + exc_type)

        return



class fread_wscm:

    def __init__(self, file):
        self.file = file

    def __enter__(self):
        return self.file.read()

    def __exit__(self, exc_type, exc_value, traceback):

        # report errors
        if isinstance(exc_value, Exception):
            print("File Read Exception! " + exc_type)

        return



class freadline_wscm:

    def __init__(self, file):
        self.file = file

    def __enter__(self, data):
        return self.file.readline(data)

    def __exit__(self, exc_type, exc_value, traceback):

        # report errors
        if isinstance(Exception):
            print("File Readline Exception! " + exc_type)

        return





def h_file__read_str_from_file(device_file_path):
    #print('reading from host fw_module..')

    data = None
    with fopen_wscm(device_file_path, 'r') as f:
        with fread_wscm(f) as data:
            pass #print('read ok.')

    return data



def h_file__write_str_to_device(device_file_path, data):
    #print('writing to host fw_module..')

    with fopen_wscm(device_file_path, 'w') as f:
        with fwrite_wscm(f, data) as data:
            pass #print('write ok.')
            return 1

    return None