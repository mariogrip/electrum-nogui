# API version 0.1 (This is read only api)
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


#Exsample
import api              # imports the api
from api import *       # imports all funtions

api = api()   			    # bind class
print api.daemon("status")  # Prints daemon status
print api.getbalance()      # Prints balance
print api.getservers()      # Prints all servers in electrum network
