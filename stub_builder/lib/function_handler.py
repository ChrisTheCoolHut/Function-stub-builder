import r2pipe


def get_funcs(file_name):
    r2_ins = r2pipe.open(file_name, flags=["-2"])
    try:
        r2_ins.cmd('aaa')
    except BrokenPipeError as e:
        print("[-] Error running radare2 commands. Is {} a file?".format(file_name))
        exit(1)


    try:
        func_list = r2_ins.cmdj('aflj')
    except:
        func_list = []

    r2_ins.quit()

    return func_list

def get_func_info_by_name(file_name, func_name):
    func_list = get_funcs(file_name)

    for func in func_list:
        if 'name' in func.keys() and func_name.lower() in func['name'].lower():
            return func
    return None

def get_func_info_by_addr(file_name, func_addr):
    func_list = get_funcs(file_name)

    #Remove any leading 0's
    if "0x" in func_addr:
        func_addr = int(func_addr,16)
    else:
        func_addr = int(func_addr)
    func_addr = str(func_addr)

    for func in func_list:
        #Check for either hex or int repr of address
        if 'offset' in func.keys() and any([func_addr in x for x in [str(func['offset']).lower(), hex(func['offset'])]]):
            return func
    return None

def get_func_args(func):
    arg_list = []
    for var in (func['regvars'] +func['bpvars']) :
        if 'arg' in var['kind']:
            arg_list.append(var)
        elif 'arg' in var['name'] and 'reg' in var['kind']:
            arg_list.append(var)
    return arg_list

