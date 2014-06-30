# Using Electrum Core  (https://github.com/spesmilo/electrum)
#
# Electrum terminal Lite version
#
########################-Deveoper Info-"#################################
# This is made for more devoping frendly code, easyser to understand.	#
# @author Mariogrip, ThomasV						#
# @core https://github.com/spesmilo/electrum 				#
#									#
# licence https://github.com/spesmilo/electrum/blob/master/LICENCE 	#
#########################################################################

# import
from decimal import Decimal
import json
import optparse
import os
import re
import ast
import sys
import time
import traceback

# import electum libs
import simple_config, network, wallet, commands, daemon, util
from commands import known_commands
from wallet import *
from simple_config import *
from network import *
from commands import *
from daemon import *
from util import *


def prompt_password(prompt, confirm=True):
    import getpass
    if sys.stdin.isatty():
        password = getpass.getpass(prompt)
        if password and confirm:
            password2 = getpass.getpass("Confirm: ")
            if password != password2:
                sys.exit("Error: Passwords do not match.")
    else:
        password = raw_input(prompt)
    if not password:
        password = None
    return password


def print_help(parser):
    parser.print_help()
    print_msg("Type 'electrum help <command>' to see the help for a specific command")
    print_msg("Type 'electrum --help' to see the list of options")
    run_command(known_commands['help'])
    sys.exit(1)


def print_help_cb(self, opt, value, parser):
    print_help(parser)


def run_command(cmd, password=None, args=None):
    if args is None:
        args = []  # Do not use mutables as default values!
    if cmd.requires_network and not options.offline:
        network = NetworkProxy(config)
        if not network.start(start_daemon= (True if cmd.name!='daemon' else False)):
            print "Daemon not running"
            sys.exit(1)

        if wallet:
            wallet.start_threads(network)
            wallet.update()
    else:
        network = None

    cmd_runner = Commands(wallet, network)
    func = getattr(cmd_runner, cmd.name)
    cmd_runner.password = password
    try:
        result = func(*args[1:])
    except Exception:
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)


    if cmd.requires_network and not options.offline:
        if wallet:
            wallet.stop_threads()


    if type(result) == str:
        print_msg(result)
    elif result is not None:
        print_json(result)
def arg_parser():
    usage = "%prog [options] command"
    parser = optparse.OptionParser(prog=usage, add_help_option=False)
    return parser


if __name__ == '__main__':

    parser = arg_parser()
    options, args = parser.parse_args()

    cmd = args[0]
    if cmd not in known_commands:
        cmd = 'help'
    cmd = known_commands[cmd]
    config_options = eval(str(options))
    config = SimpleConfig(config_options)

    storage = WalletStorage(config)

    if cmd.name in ['create', 'restore']:
        if storage.file_exists:
            sys.exit("Error: Remove the existing wallet first!")
        if options.password is not None:
            password = options.password
        elif cmd.name == 'restore' and options.mpk:
            password = None
        else:
            password = prompt_password("Password (hit return if you do not wish to encrypt your wallet):")

        if cmd.name == 'restore':
            if options.mpk:
                wallet = Wallet.from_mpk(options.mpk, storage)
            else:
                import getpass
                seed = getpass.getpass(prompt="seed:", stream=None) if options.concealed else raw_input("seed:")
                if not Wallet.is_seed(seed):
                    sys.exit("Error: Invalid seed")
                wallet = Wallet.from_seed(seed, storage)
                wallet.add_seed(seed, password)
                wallet.create_accounts(password)

            if not options.offline:
                network = Network(config)
                network.start()
                wallet.start_threads(network)
                print_msg("Recovering wallet...")
                wallet.restore(lambda x: x)
                if wallet.is_found():
                    print_msg("Recovery successful")
                else:
                    print_msg("Warning: Found no history for this wallet")
            else:
                wallet.synchronize()
                print_msg("Warning: This wallet was restored offline. It may contain more addresses than displayed.")

        else:
            if not config.get('2of3'):
                wallet = Wallet(storage)
                seed = wallet.make_seed()
                wallet.add_seed(seed, password)
                wallet.create_accounts(password)
                wallet.synchronize()
                print_msg("Your wallet generation seed is:\n\"%s\"" % seed)
                print_msg("Please keep it in a safe place; if you lose it, you will not be able to restore your wallet.")
            else:
                wallet = Wallet_2of3(storage)
                cold_seed = wallet.make_seed()
                #wallet.save_seed()
                print_msg("Your cold seed is:\n\"%s\"" % cold_seed)
                print_msg("Please store it on paper. ")
                print_msg("Open this file on your online computer to complete your wallet creation.")


        print_msg("Wallet saved in '%s'" % wallet.storage.path)

        # terminate
        sys.exit(0)


    if cmd.name not in ['create', 'restore'] and cmd.requires_wallet and not storage.file_exists:
        print_msg("Error: Wallet file not found.")
        print_msg("Type 'electrum create' to create a new wallet, or provide a path to a wallet with the -w option")
        sys.exit(0)


    if cmd.requires_wallet:
        wallet = Wallet(storage)
    else:
        wallet = None


    # important warning
    if cmd.name in ['dumpprivkey', 'dumpprivkeys']:
        print_stderr("WARNING: ALL your private keys are secret.")
        print_stderr("Exposing a single private key can compromise your entire wallet!")
        print_stderr("In particular, DO NOT use 'redeem private key' services proposed by third parties.")

    # commands needing password
    if cmd.requires_password:
        if wallet.seed == '':
            seed = ''
            password = None
        elif wallet.use_encryption:
            password = prompt_password('Password:', False)
            if not password:
                print_msg("Error: Password required")
                sys.exit(1)
            # check password
            try:
                seed = wallet.get_seed(password)
            except Exception:
                print_msg("Error: This password does not decode this wallet.")
                sys.exit(1)
        else:
            password = None
            seed = wallet.get_seed(None)
    else:
        password = None

    # add missing arguments, do type conversions
    if cmd.name == 'importprivkey':
        # See if they specificed a key on the cmd line, if not prompt
        if len(args) == 1:
            args.append(prompt_password('Enter PrivateKey (will not echo):', False))

    elif cmd.name == 'signrawtransaction':
        args = [cmd, args[1], json.loads(args[2]) if len(args) > 2 else [] ]

    elif cmd.name == 'createmultisig':
        args = [cmd, int(args[1]), json.loads(args[2])]

    elif cmd.name == 'createrawtransaction':
        args = [cmd, json.loads(args[1]), json.loads(args[2])]

    elif cmd.name == 'listaddresses':
        args = [cmd, options.show_all, options.show_labels]

    elif cmd.name in ['payto', 'mktx']:
        domain = [options.from_addr] if options.from_addr else None
        args = ['mktx', args[1], Decimal(args[2]), Decimal(options.tx_fee) if options.tx_fee else None, options.change_addr, domain]

    elif cmd.name in ['paytomany', 'mksendmanytx']:
        domain = [options.from_addr] if options.from_addr else None
        outputs = []
        for i in range(1, len(args), 2):
            if len(args) < i+2:
                print_msg("Error: Mismatched arguments.")
                sys.exit(1)
            outputs.append((args[i], Decimal(args[i+1])))
        args = ['mksendmanytx', outputs, Decimal(options.tx_fee) if options.tx_fee else None, options.change_addr, domain]

    elif cmd.name == 'help':
        if len(args) < 2:
            print_help(parser)

    # check the number of arguments
    if len(args) - 1 < cmd.min_args:
        print_msg("Not enough arguments")
        print_msg("Syntax:", cmd.syntax)
        sys.exit(1)

    if cmd.max_args >= 0 and len(args) - 1 > cmd.max_args:
        print_msg("too many arguments", args)
        print_msg("Syntax:", cmd.syntax)
        sys.exit(1)

    if cmd.max_args < 0:
        if len(args) > cmd.min_args + 1:
            message = ' '.join(args[cmd.min_args:])
            print_msg("Warning: Final argument was reconstructed from several arguments:", repr(message))
            args = args[0:cmd.min_args] + [message]



    # run the command
    if cmd.name == 'deseed':
        if not wallet.seed:
            print_msg("Error: This wallet has no seed")
        else:
            ns = wallet.storage.path + '.seedless'
            print_msg("Warning: you are going to create a seedless wallet'\nIt will be saved in '%s'" % ns)
            if raw_input("Are you sure you want to continue? (y/n) ") in ['y', 'Y', 'yes']:
                wallet.storage.path = ns
                wallet.seed = ''
                wallet.storage.put('seed', '', True)
                wallet.use_encryption = False
                wallet.storage.put('use_encryption', wallet.use_encryption, True)
                for k in wallet.imported_keys.keys():
                    wallet.imported_keys[k] = ''
                wallet.storage.put('imported_keys', wallet.imported_keys, True)
                print_msg("Done.")
            else:
                print_msg("Action canceled.")

    elif cmd.name == 'getconfig':
        key = args[1]
        out = config.get(key)
        print_msg(out)

    elif cmd.name == 'setconfig':
        key, value = args[1:3]
        try:
            value = ast.literal_eval(value)
        except:
            pass
        config.set_key(key, value, True)
        print_msg(True)

    elif cmd.name == 'password':
        new_password = prompt_password('New password:')
        wallet.update_password(password, new_password)

    else:
        run_command(cmd, password, args)


    time.sleep(0.1)
    sys.exit(0)
