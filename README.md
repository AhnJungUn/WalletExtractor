# WalletExtractor



## Introduction
'''
WalletExtractor analyze bitcoin wallet service data related to user behavior on FileSystem / Memory in Windows 10.
'''




## Support Wallet Service
'''
Bitcoin Core, Electrum, Bither, Bitpay
'''




## Usage

### 1. To Extract Bitcoin Wallet Artifacts on File System
```
python3 parser.py --service=[Service Name]
```

### 2. To Extract Bitcoin Wallet Artifacts on Memory Dump
```
python3 parser.py --service=[Service Name] --file=[Path of Memory Dump]
```
