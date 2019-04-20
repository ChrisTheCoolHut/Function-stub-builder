import argparse
from stub_builder.lib import stub_template
from stub_builder.lib import function_handler as fh

code_template = stub_template.code_template
command_template = "LD_PRELOAD=./main_hook.so ./{}"

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--File","-F", help='ELF executable to create stub from', required=True)

    subparsers = parser.add_subparsers(help='Hardcode or automatically use prototypes and addresses')

    parser_abs = subparsers.add_parser('hardcode', help='Use absolute offsets and prototypes')

    parser_abs.add_argument('func_addr', 
            help="Address of given function")
    parser_abs.add_argument('func_args_prototype',
            help="Function prototype arguments as string EX. '(int args, char **argv)'")
    parser_abs.add_argument('func_return_type',
            help="Function return type EX. 'int'")
    parser_abs.set_defaults(func=handle_hardcode)

    parser_rec = subparsers.add_parser('recover',
            help='Use radare2 to recover function address and prototype')

    name_or_addr_subparser = parser_rec.add_subparsers(help='Resolve function by name or address')

    parser_name = name_or_addr_subparser.add_parser('name', help="Use function name")
    parser_name.add_argument('func_name')

    parser_addr = name_or_addr_subparser.add_parser('addr', help="Use function addr")
    parser_addr.add_argument('func_addr')

    parser_rec.set_defaults(func=handle_recover)

    args = parser.parse_args()

    args.func(args)

def handle_hardcode(args):
    args_dict = args.__dict__
    local_string = code_template.format(
            args.func_addr,
            args.func_args_prototype,
            args.func_return_type
            )
    print_results(args.File, local_string)

def handle_recover(args):
    func = None
    
    if 'func_name' in args.__dict__.keys():
        func = fh.get_func_info_by_name(args.File, args.func_name)
    else:
        func = fh.get_func_info_by_addr(args.File, args.func_addr)

    if func is None:
        print("[-] Failed to locate function")
        exit(1)

    if 'nargs' not in func.keys() or func['nargs'] is 0:
        print('[-] No arguments recovered from function')

    func_args = fh.get_func_args(func)
    arg_prototype = "({})".format(','.join([x['type'] for x in func_args]))

    func_addr = hex(func['offset'])

    func_return = "void"

    local_string = code_template.format(
            func_addr,
            arg_prototype,
            func_return
            )
    print_results(args.File, local_string)

def print_results(file_name, local_string):
    print("[+] Modify main_hook.c to call instrumented function")
    print("[+] Compile with \"gcc main_hook.c -o main_hook.so -fPIC -shared -ldl\"")
    command = command_template.format(file_name)
    print("[+] Hook with: {}".format(command))

    with open("main_hook.c", 'w') as f:
        f.write(local_string)
    print("[+] Created main_hook.c")



if __name__ == "__main__":
    main()
