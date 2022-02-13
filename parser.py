import os
import sys
import re
import struct
import sqlite3
import json
import argparse
import pprint
from datetime import datetime


PATH_APPDATA = os.popen("echo %appdata%").read()[:-1]
PATH_USERPROFILE = os.popen("echo %userprofile%").read()[:-1]


BITCOIN_CORE = PATH_APPDATA + "\\Bitcoin\\wallets"
ELECTRUM = PATH_APPDATA + "\\Electrum\\wallets"
BITHER = [PATH_APPDATA + "\\Bither\\address.db", PATH_APPDATA + "\\Bither\\bither.db"]
BITPAY = PATH_USERPROFILE + "\\.bitpay\\app\\Local Storage\\leveldb"


''' Bitcoin Core '''

def extract_Bitcore(file):

	BitCore_Wallets = os.listdir(BITCOIN_CORE)
	ADDRESS_STR = "purpose"
	address = []
	Wallet_Address = {}

	def ConvToUnicode(data):
		res = b""
		for ch in data:
			res += chr(ch).encode() + chr(0x00).encode()
		return res

	def extract_address_description():
		for wallet in BitCore_Wallets:
			wallet_file = "{}\\{}\\wallet.dat".format(BITCOIN_CORE, wallet)
			wallet_dat = open(wallet_file, "rb").read()
			address_idx = [(m.end(0) + 1) for m in re.finditer(rb"purpose", wallet_dat)]
			address_list = []
			for idx in address_idx:
				address_dat = dict()
				address_dat['address'] = wallet_dat[idx:idx+34] if wallet_dat[idx] == ord("3") else wallet_dat[idx:idx+42]
				if address_dat['address'] in address:
					continue
				address.append(address_dat['address'])
				address_idx = [m.start(0) for m in re.finditer(address_dat['address'], wallet_dat)]
				for idx in address_idx:
					if wallet_dat[idx-3:idx-1] == b"\x00\x00":
						_time = struct.unpack("<L", wallet_dat[idx-9:idx-5])[0]
						address_dat['time'] = datetime.fromtimestamp(_time).strftime('%Y-%m-%d %H:%M:%S')
						description_idx = idx + len(address_dat['address']) + 1
						if wallet_dat[description_idx - 1] == b"\x00":
							break 
						address_dat['description'] = wallet_dat[description_idx:].split(b"\x00")[0].decode()
						break

				address_dat['address'] = address_dat['address'].decode()
				address_list.append(address_dat)
			
			Wallet_Address[wallet] = address_list

		return Wallet_Address

	def extract_transaction(wallet_data):
		tx_hist = list()
		tx_idx = re.finditer(ConvToUnicode(b'Date:') + b'.*' + ConvToUnicode(b'Transaction ID') + b'.*?\(', wallet_data)
		for idx in tx_idx:
			transaction_dat = dict()
			tx_data = idx.group().replace(b'\x00', b'')
			tx_hash = tx_data.split(b'Transaction ID: ')[1].split(b'(')[0]
			tx_time = tx_data.split(b'Date: ')[1].split(b'(')[0]
			transaction_dat['hash'] = tx_hash.decode()
			transaction_dat['time'] = tx_time.decode()
			tx_hist.append(transaction_dat)

		return tx_hist

	if file == "None":
		print("[+] Extracting Addresses, Descriptions for Each Wallet in FileSystem")
		Wallet_Info = extract_address_description()
		return Wallet_Info

	else:
		memdump = open(file, "rb").read()
		print("[+] Extracting Transaction History from Memory Dump")
		tx_hist = extract_transaction(memdump)
		return tx_hist



''' Bither '''
def extract_Bither(file):

	Wallet_Address = {}
	HD_Address = ""
	address_list = []
	tx_hist = []

	conn = sqlite3.connect(BITHER[0])
	c = conn.cursor()
	query = "select hd_address from hd_account;"
	for row in c.execute(query):
		hd_address = row[0]

		query = "select address, sort_time from addresses;"
		for row in c.execute(query):
			address_dat = dict()
			address_dat['address'] = row[0]
			#address_dat['time'] = row[1]
			address_dat['time'] = datetime.fromtimestamp(int(str(row[1])[:-3])).strftime('%Y-%m-%d %H:%M:%S')
			address_list.append(address_dat)

		Wallet_Address[hd_address] = address_list


	#return Wallet_Address

	conn = sqlite3.connect(BITHER[1])
	c = conn.cursor()
	query = "select tx_hash, tx_time from txs;"
	for row in c.execute(query):
		tx_dat = dict()
		tx_hash, tx_time = row[0], row[1]
		tx_dat['hash'] = tx_hash
		tx_dat['time'] = datetime.fromtimestamp(int(str(tx_time))).strftime('%Y-%m-%d %H:%M:%S')
		tx_hist.append(tx_dat)


	print("[+] Extracting Addresses, Transaction History in FileSystem")
	return Wallet_Address, tx_hist



def extract_Bitpay(file):

	Wallets = {}
	Wallet_Address = {}
	address = []
	hashes = []
	tx_hist = []



	def extract_wallet(f_data):
		Wallets = {}

		wallet_idx = re.finditer(b"\"walletId\":\".{36}\"", f_data)
		for idx in wallet_idx:
			try:
				wallet_id = f_data[idx.start(0):idx.end(0)].split(b":")[1][1:-1].decode()
				wallet_name = f_data[idx.end(0)+2:].split(b",")[0].split(b":")[1][1:-1].decode()
				Wallets[wallet_id] = wallet_name
			except:
				continue
		return Wallets


	def extract_address_transaction(f_data, Wallets):

		Wallet_Address = {}
		tx_hist = []
		hashes = []
		address = []

		tx_idx = re.finditer(b"txsHistory-.{36}", f_data)
		for idx in tx_idx:
			transaction_dat = dict()
			try:
				wallet_id = f_data[idx.end(0)-36:idx.end(0)].decode()
				if f_data[idx.end(0)+3:idx.end(0)+11] == b'[{"id":"':
					data = f_data[idx.end(0):]
					tx = re.search(b"\"txid\":[0-9a-zA-Z\",:]*\"time\":[0-9]{10}", data)
					tx_data = data[tx.start(0):tx.end(0)]
					
					tx_hash = tx_data.split(b",")[0].split(b":")[1][1:-1].decode()
					if tx_hash in hashes:
						continue
					#hashes.append(tx_hash)
					transaction_dat['hash'] = tx_hash
					tx_time = tx_data.split(b",")[-1].split(b":")[1].decode()
					transaction_dat['time'] = datetime.fromtimestamp(int(tx_time)).strftime('%Y-%m-%d %H:%M:%S')
					#tx_hist.append(transaction_dat)
					
					addr = re.search(b"\"id\":[0-9a-zA-Z\",:{[]*\"address\":\"[0-9a-zA-Z]+\"", data)
					addr_data = data[addr.start(0):addr.end(0)]
					addr_val = addr_data.split(b":")[-1][1:-1].decode()
					#if addr_val not in address:
					#	address.append(addr_val)

					if Wallets[wallet_id] in Wallet_Address.keys():
						Wallet_Address[Wallets[wallet_id]] = list(set(Wallet_Address[Wallets[wallet_id]]+[addr_val]))
					else:
						Wallet_Address[Wallets[wallet_id]] = [addr_val]

					hashes.append(tx_hash)
					tx_hist.append(transaction_dat)
					if addr_val not in address:
						address.append(addr_val)

			except:
				continue


		return Wallet_Address, tx_hist


	if file == "None":
		print("[+] Extracting Addresses, Descriptions, Transaction History in FileSystem")
		Bitpay_log = os.path.join(BITPAY,[file for file in os.listdir(BITPAY) if file.endswith(".log")][0])
		log_data = open(Bitpay_log, "rb").read()
		Wallets = extract_wallet(log_data)
		print(Wallets)
		Wallet_Address, tx_hist = extract_address_transaction(log_data, Wallets)
		print(Wallet_Address)
		print(tx_hist)

	else:
		memdump = open(file, "rb").read()
		print("[+] Extracting Wallets, Addresses Used in Transaction History from Memory Dump")
		Wallets = extract_wallet(memdump)
		Wallet_Address, tx_hist = extract_address_transaction(memdump, Wallets)
		return Wallet_Address, tx_hist


''' Electrum '''


def extract_Electrum(file):

	Electrum_Wallets = os.listdir(ELECTRUM)
	Wallet_Address = {}
	address = []
	hashes = []
	tx_hist = []
	labels = {}


	def extract_label(wallet_dat):

		labels = {}
		labels_dat = []

		# extract label_data

		offsets = re.finditer(b"\"labels\": {", wallet_dat)
		for offset in offsets:
			data_cur = wallet_dat[offset.start():]
			data_cur = data_cur[:re.search(b"[\r\n\t ]*}", data_cur).end()]
			labels_dat.append(data_cur)

		# extract address, label mapping in label_data

		for label_dat in labels_dat:
			labels_cur = re.finditer(b"(\"[0-9a-zA-Z]{34}\": \".+?\")|(\"[0-9a-zA-Z]{42}\": \".+?\")", label_dat)
			for m in labels_cur:
				addr = label_dat[m.start(0)+1:m.end(0)].split(b":")[0][:-1].decode()
				label = label_dat[m.start(0):m.end(0)].split(b":")[1][2:-1].decode()
				if addr not in labels.keys():
					labels[addr] = label
		
		return labels

		

	def extract_address(wallet_dat, labels):

		address_list = []

		# extract payment_requests data

		payment_requests_dat = []

		offsets = re.finditer(b"\"payment_requests\": {", wallet_dat)
		for offset in offsets:
			data_cur = wallet_dat[offset.start():]
			data_cur = data_cur[:re.search(b"}[\r\n\t ]*}", data_cur).end()]
			payment_requests_dat.append(data_cur)

		# extract addresses in payment_requests data

		for payment_dat in payment_requests_dat:
			addrs_cur = re.finditer(b"(?:\"[0-9a-zA-Z]{34}\": {)|(?:\"[0-9a-zA-Z]{42}\": {)", payment_dat)
			for m in addrs_cur:
				address_dat = dict()
				addr = payment_dat[m.start(0)+1:m.end(0)-4]
				if addr in address:
					continue
				address.append(addr)
				address_dat['address'] = addr.decode()
				addr_dat = payment_dat[m.start(0):]
				addr_dat = addr_dat[:re.search(b"}[\r\n\t ]*}", addr_dat).end()]
				addr_time = addr_dat[re.search(b"\"time\": ", addr_dat).end():].split(b",")[0]
				
				address_dat['time'] = datetime.fromtimestamp(int(addr_time.decode())).strftime('%Y-%m-%d %H:%M:%S')
				

				if address_dat['address'] in labels.keys():
					address_dat['label'] = labels[address_dat['address']]

				address_list.append(address_dat)

		return address_list


	def extract_transaction(wallet_dat):

		tx_hist = []
		tx_dats = []
		hashes = []

		offsets = re.finditer(b"\"verified_[0-9a-zA-Z]+\": {", wallet_dat)
		for offset in offsets:
			data_cur = wallet_dat[offset.start():]
			data_cur = data_cur[:re.search(b"[\r\n\t ]*}", data_cur).end()]
			tx_dats.append(data_cur)


		# extract addresses in payment_requests data
		for tx_dat in tx_dats:
			hashes_cur = re.finditer(b"\"[0-9a-zA-Z]+\": ", tx_dat)
			for m in hashes_cur:
				transaction_dat = dict()
				hash_val = tx_dat[m.start(0)+1:m.end(0)-3]
				if hash_val in hashes:
					continue
				hashes.append(hash_val)
				transaction_dat['hash'] = hash_val.decode()
				trans_dat = tx_dat[m.start(0):]
				trans_dat = trans_dat[:re.search(b"[\r\n\t ]*]", trans_dat).end()] 
				tx_times = [trans_dat[m.start(0):m.end(0)-1] for m in re.finditer(b"[0-9]{10},", trans_dat)]
				transaction_dat['time'] = datetime.fromtimestamp(int(tx_times[0].decode())).strftime('%Y-%m-%d %H:%M:%S')
				tx_hist.append(transaction_dat)

		return tx_hist


	if file == "None":
		for wallet in Electrum_Wallets:
			wallet_file = "{}\\{}".format(ELECTRUM, wallet)
			wallet_dat = open(wallet_file, "rb").read()
			print("[+] Extracting Addresses, Descriptions, Transaction History in FileSystem")
			#print("[*] {} Info\n".format(wallet))

			labels = extract_label(wallet_dat)
			#print(labels)
			address_list = extract_address(wallet_dat, labels)
			#print(address_list)
			tx_hist = extract_transaction(wallet_dat)
			#print(tx_hist)
			return labels, address_list, tx_hist

	else:
		memdump = open(file, "rb").read()
		print("[+] Extracting Addresses, Descriptions, Transaction History from Memory Dump")
		#print("[*] Extracting Label Data from Memory Dump")
		labels = extract_label(memdump)
		#print(labels)
		address_list = extract_address(memdump, labels)
		#print(address_list)
		tx_hist = extract_transaction(memdump)
		#print(tx_hist)
		return address_list, tx_hist




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Wallet Property Extractor')

    parser.add_argument('--service',  type=str, choices=["bither", "bitcore", "electrum", "bitpay"],  help='name of the wallet service')
    parser.add_argument('--file',  type=str, default="None",  help='path of target file')
    args = parser.parse_args()

    print("[*] Extracting Bitcoin Wallet Information")

    if args.service == "bitcore":
    	pprint.pprint(extract_Bitcore(args.file))
    elif args.service == "bither":
    	pprint.pprint(extract_Bither(args.file))
    elif args.service == "electrum":
    	pprint.pprint(extract_Electrum(args.file))
    elif args.service == "bitpay":
    	pprint.pprint(extract_Bitpay(args.file))
