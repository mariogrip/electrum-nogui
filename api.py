# Using Electrum Core  (https://github.com/spesmilo/electrum)
#
# Electrum terminal Lite version
#
########################-Deveoper Info-"#################################
# This is made for more devoping frendly, easyser to understand.		#
# @author Mariogrip, ThomasV											#
# @core https://github.com/spesmilo/electrum 							#
#																		#
# licence https://github.com/spesmilo/electrum/blob/master/LICENCE 		#
#																		#
#########################################################################
#
# API Commands:   #
###################
# daemon() -- Controlls
# contacts() -- Show your list of contacts
# create() -- Create a new wallet
# createmultisig() -- similar to bitcoind\'s command
# createrawtransaction() -- similar to bitcoind\'s command
# deseed() Remove seed from wallet, creating a seedless, watching-only wallet.
# decoderawtransaction() -- similar to bitcoind\'s command
# getbalance(<accout>) -- Return the balance of your wallet, or of one account in your wallet
# getservers() -- Return the list of available servers
# getversion() -- Return the version of your client', 'getversion
# getaddressbalance() -- Return the balance of an address
# getaddresshistory() -- Return the transaction history of a wallet address
# getconfig() -- Return a configuration variable
# getpubkeys() -- Return the public keys for a wallet address
# getrawtransaction() -- Retrieve a transaction
# getmpk() -- Return your wallet\'s master public key
# help() -- Prints this help
# history() -- Returns the transaction history of your wallet
# listaddresses() -- Returns your list of addresses.
# listunspent() -- Returns the list of unspent inputs in your wallet.
# getaddressunspent() -- Returns the list of unspent inputs for an address.
# restore() -- Restore a wallet
# setconfig() -- Set a configuration variable
# setlabel() -- Assign a label to an item
# sendrawtransaction() -- Broadcasts a transaction to the network.
# unfreeze() -- Unfreeze the funds at one of your wallet\'s address
# validateaddress() -- Check that the address is valid
# verifymessage() -- Verifies a signature', verifymessage_syntax
# encrypt() -- encrypt a message with pubkey
# daemon("<stop/status>") -- <stop|status>
# getproof() -- get merkle proof
# getutxoaddress() -- get the address of an unspent transaction output

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
import simple_config, network, wallet, daemon, util
from commands import known_commands
from wallet import *
from simple_config import *
from network import *
from daemon import *
from util import *


class api:
    def __init__(self, callback = None):
        usage = "%prog [options] command"
        parser = optparse.OptionParser(prog=usage, add_help_option=False)
        options, args = parser.parse_args()
        config_options = eval(str(options))
        config = SimpleConfig(config_options)
        storage = WalletStorage(config)
        self.wallet = Wallet(storage)
        network = NetworkProxy(config)
        if not network.start(start_daemon=True):
  	        print "Daemon not running"
        if self.wallet:
            self.wallet.start_threads(network)
            self.wallet.update()
        else:
            network = None
	    if self.wallet:
	 	   self.wallet.stop_threads()
	    if type(result) == str:
	        print_msg(result)
	    elif result is not None:
	        print_json(result)
    #self.wallet = wallet
        self.network = network
        self._callback = callback
        self.password = None

    def _run(self, method, args, password_getter):
        cmd = known_commands[method]
        if cmd.requires_password and self.wallet.use_encryption:
            self.password = apply(password_getter,())
        f = getattr(self, method)
        result = f(*args)
        self.password = None
        if self._callback:
            apply(self._callback, ())
        return result

    def getaddresshistory(self, addr):
        return self.network.synchronous_get([ ('blockchain.address.get_history',[addr]) ])[0]

    def daemon(self, arg):
        if arg=='stop':
            return self.network.stop()
        elif arg=='status':
            return {
                'server':self.network.main_server(),
                'connected':self.network.is_connected()
            }
        else:
            return "unknown command \"%s\""% arg

    def listunspent(self):
        l = copy.deepcopy(self.wallet.get_unspent_coins())
        for i in l: i["value"] = str(Decimal(i["value"])/100000000)
        return l

    def getaddressunspent(self, addr):
        return self.network.synchronous_get([ ('blockchain.address.listunspent',[addr]) ])[0]

    def getutxoaddress(self, txid, num):
        r = self.network.synchronous_get([ ('blockchain.utxo.get_address',[txid, num]) ])
        if r:
            return {'address':r[0] }

    def createrawtransaction(self, inputs, outputs):
        for i in inputs:
            i['prevout_hash'] = i['txid']
            i['prevout_n'] = i['vout']
        outputs = map(lambda x: (x[0],int(1e8*x[1])), outputs.items())
        tx = Transaction.from_io(inputs, outputs)
        return tx

    def signrawtransaction(self, raw_tx, private_keys):
        tx = Transaction(raw_tx)
        self.wallet.signrawtransaction(tx, private_keys, self.password)
        return tx

    def decoderawtransaction(self, raw):
        tx = Transaction(raw)
        return tx.deserialize()

    def sendrawtransaction(self, raw):
        tx = Transaction(raw)
        return self.network.synchronous_get([('blockchain.transaction.broadcast', [str(tx)])])[0]

    def createmultisig(self, num, pubkeys):
        assert isinstance(pubkeys, list)
        redeem_script = Transaction.multisig_script(pubkeys, num)
        address = hash_160_to_bc_address(hash_160(redeem_script.decode('hex')), 5)
        return {'address':address, 'redeemScript':redeem_script}

    def freeze(self,addr):
        return self.wallet.freeze(addr)

    def unfreeze(self,addr):
        return self.wallet.unfreeze(addr)

    def getprivatekeys(self, addr):
        return self.wallet.get_private_key(addr, self.password)

    def dumpprivkeys(self, addresses = None):
        if addresses is None:
            addresses = self.wallet.addresses(True)
        return [self.wallet.get_private_key(address, self.password) for address in addresses]

    def validateaddress(self, addr):
        isvalid = is_valid(addr)
        out = { 'isvalid':isvalid }
        if isvalid:
            out['address'] = addr
        return out

    def getpubkeys(self, addr):
        out = { 'address':addr }
        out['pubkeys'] = self.wallet.getpubkeys(addr)
        return out

    def getbalance(self, account= None):
        if account is None:
            c, u = self.wallet.get_balance()
        else:
            c, u = self.wallet.get_account_balance(account)

        out = { "confirmed": str(Decimal(c)/100000000) }
        if u: out["unconfirmed"] = str(Decimal(u)/100000000)
        return out

    def getaddressbalance(self, addr):
        out = self.network.synchronous_get([ ('blockchain.address.get_balance',[addr]) ])[0]
        out["confirmed"] =  str(Decimal(out["confirmed"])/100000000)
        out["unconfirmed"] =  str(Decimal(out["unconfirmed"])/100000000)
        return out

    def getproof(self, addr):
        p = self.network.synchronous_get([ ('blockchain.address.get_proof',[addr]) ])[0]
        out = []
        for i,s in p:
            out.append(i)
        return out

    def getservers(self):
        while not self.network.is_up_to_date():
            time.sleep(0.1)
        return self.network.get_servers()

    def getversion(self):
        import electrum  # Needs to stay here to prevent ciruclar imports
        return electrum.ELECTRUM_VERSION

    def getmpk(self):
        return self.wallet.get_master_public_keys()

    def getseed(self):
        mnemonic = self.wallet.get_mnemonic(self.password)
        return { 'mnemonic':mnemonic, 'version':self.wallet.seed_version }

    def importprivkey(self, sec):
        try:
            addr = self.wallet.import_key(sec,self.password)
            out = "Keypair imported: ", addr
        except Exception as e:
            out = "Error: Keypair import failed: " + str(e)
        return out

    def sweep(self, privkey, to_address, fee = 0.0001):
        fee = int(Decimal(fee)*100000000)
        return Transaction.sweep([privkey], self.network, to_address, fee)

    def signmessage(self, address, message):
        return self.wallet.sign_message(address, message, self.password)

    def verifymessage(self, address, signature, message):
        return bitcoin.verify_message(address, signature, message)

    def _mktx(self, outputs, fee = None, change_addr = None, domain = None):

        for to_address, amount in outputs:
            if not is_valid(to_address):
                raise Exception("Invalid Bitcoin address", to_address)

        if change_addr:
            if not is_valid(change_addr):
                raise Exception("Invalid Bitcoin address", change_addr)

        if domain is not None:
            for addr in domain:
                if not is_valid(addr):
                    raise Exception("invalid Bitcoin address", addr)

                if not self.wallet.is_mine(addr):
                    raise Exception("address not in wallet", addr)

        for k, v in self.wallet.labels.items():
            if change_addr and v == change_addr:
                change_addr = k

        final_outputs = []
        for to_address, amount in outputs:
            for k, v in self.wallet.labels.items():
                if v == to_address:
                    to_address = k
                    print_msg("alias", to_address)
                    break

            amount = int(100000000*amount)
            final_outputs.append((to_address, amount))

        if fee: fee = int(100000000*fee)
        return self.wallet.mktx(final_outputs, self.password, fee , change_addr, domain)

    def mktx(self, to_address, amount, fee = None, change_addr = None, domain = None):
        tx = self._mktx([(to_address, amount)], fee, change_addr, domain)
        return tx

    def mksendmanytx(self, outputs, fee = None, change_addr = None, domain = None):
        tx = self._mktx(outputs, fee, change_addr, domain)
        return tx

    def payto(self, to_address, amount, fee = None, change_addr = None, domain = None):
        tx = self._mktx([(to_address, amount)], fee, change_addr, domain)
        r, h = self.wallet.sendtx( tx )
        return h

    def paytomany(self, outputs, fee = None, change_addr = None, domain = None):
        tx = self._mktx(outputs, fee, change_addr, domain)
        r, h = self.wallet.sendtx( tx )
        return h

    def history(self):
        balance = 0
        out = []
        for item in self.wallet.get_tx_history():
            tx_hash, conf, is_mine, value, fee, balance, timestamp = item
            try:
                time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
            except Exception:
                time_str = "----"

            label, is_default_label = self.wallet.get_label(tx_hash)

            out.append({'txid':tx_hash, 'date':"%16s"%time_str, 'label':label, 'value':format_satoshis(value)})
        return out

    def setlabel(self, key, label):
        self.wallet.set_label(key, label)

    def contacts(self):
        c = {}
        for addr in self.wallet.addressbook:
            c[addr] = self.wallet.labels.get(addr)
        return c

    def listaddresses(self, show_all = False, show_label = False):
        out = []
        for addr in self.wallet.addresses(True):
            if show_all or not self.wallet.is_change(addr):
                if show_label:
                    item = { 'address': addr }
                    if show_label:
                        label = self.wallet.labels.get(addr,'')
                        if label:
                            item['label'] = label
                else:
                    item = addr
                out.append( item )
        return out

    def help(self, cmd=None):
        if cmd not in known_commands:
            print_msg("\nList of commands:", ', '.join(sorted(known_commands)))
        else:
            cmd = known_commands[cmd]
            print_msg(cmd.description)
            if cmd.syntax: print_msg("Syntax: " + cmd.syntax)
            if cmd.options: print_msg("options:\n" + cmd.options)
        return None

    def getrawtransaction(self, tx_hash):
        if self.wallet:
            tx = self.wallet.transactions.get(tx_hash)
            if tx:
                return tx

        r = self.network.synchronous_get([ ('blockchain.transaction.get',[tx_hash]) ])[0]
        if r:
            return Transaction(r)
        else:
            return "unknown transaction"

    def encrypt(self, pubkey, message):
        return bitcoin.encrypt_message(message, pubkey)

    def decrypt(self, pubkey, message):
        return self.wallet.decrypt_message(pubkey, message, self.password)
