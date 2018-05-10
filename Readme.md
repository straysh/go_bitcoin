# Goals:
1. 
```
      mnemonic
         ↓
wif ↔ privkey → pubkey  
         ↓
      address
```

2. new Transaction()  
->from(utxos)  
->to(address)  
->change(address)  
->format()  
->sign(privKeySets)  
~~->serialize()~~  
->send()  