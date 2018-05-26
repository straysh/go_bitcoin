比特币交易实际上是不依赖"地址"的.支付款项时,我们实际上是把支付的数额和接收者的"赎回脚本"绑定到一起.之后,接收者可以使用"签名脚本"来确认使用权.

### 赎回脚本(输出脚本)
1. P2PKH 支付到公钥地址
```bash OP_DUP OP_HASH160 [20bytes hash] OP_EQUALVERIFY OP_CHECKSIG```
2. P2SH 支付到脚本(通常为多重签名)
```bash OP_HASH160 （0×14)  [20bytes hash] OP_EQUAL```
3. P2WPKH 支付到隔离见证公钥哈希 (locking script or witness program)
```bash 0 [20bytes hash]```
4. P2WSH 支付到隔离见证脚本哈希
```bash 0 [32bytes hash]```

### 签名脚本(输入脚本)
1. P2PKH模式:
```bash [签名的字节数]［签名］0×01 [公钥的字节数] [公钥]```
2. P2SH模式: m-n Multisig
```bash 0×00 [字节数] [签名1] 0×01 …［字节数] [签名m] 0×01 [支付合同脚本的字节数] [m] [字节数]［公钥1］… [字节数]［公钥n］[n] OP_CHECKSIGVERIFY```

隔离见证的见证信息(M-of-N中的N个公钥列表)从何处获取?

#### P2SH地址的格式约定如下：
1. 前导字节(1个字节): prefix = 0×00，表示这是一个P2PKH地址;
2. 公钥的哈希值(20字节): 用hash160算法——RIPEMD160(sha256(公钥))，将公钥转换为一个20字节的数据
3. 校验码(4个字节): 用hash256算法——SHA256(SHA256([0x00] [20字节的哈希值] ))，取前4个字节作为校验码
4. 生成文本格式的地址: 用Base58编码由前三步所得到的25个字节的数据。 由于前导字节为0×00，生成的地址首字母为字符“1”。  

演算对应的脚本的方式：  
“赎回脚本”: OP_DUP OP_HASH160 [20bytes hash] OP_EQUALVERIFY OP_CHECKSIG 
“签名脚本”: [签名] [签名消息的类型(1个字节)] [公钥]

#### P2SH地址的格式约定如下：
1. 前导字节(1个字节):prefix = 0×05，表示这是一个P2SH地址;
2. 合同脚本的哈希值(20字节): 用hash160算法——RIPEMD160(sha256(合同脚本)),生成一个20字节的数据;
3. 校验码(4个字节): 用hash256算法——SHA256(SHA256([0x00] [20字节的哈希值] ))，取前4个字节作为校验码
4. 生成文本格式的地址：用Base58编码由前三步所得到的25个字节的数据。 由于前导字节为0×05，生成的地址首字母为字符“3”

演算对应的脚本的方式：  
“赎回脚本”: OP_HASH160 [20bytes hash] OP_EQUAL
“签名脚本”: [签名1 … 签名n] [合同脚本] OP_CHECKSIGVERIFY 
其中，,m-n多重签名的合同脚本（当n < 16时），m ［公钥1…公钥n］n

================================================================
### P2PKH:
**M-of-N locking script:**
```bash M <Public Key 1> <Public Key 2> ... <Public Key N> N CHECKMULTISIG```
**unlocking script:**
```bash <Signature B> <Signature C>```
**combined validation script:**
```bash <Signature B> <Signature C> 2 <Public Key A> <Public Key B> <Public Key C> 3 CHECKMULTISIG```



### P2SH:
Table 1. Complex script without P2SH
| Locking Script   | 2 PubKey1 PubKey2 PubKey3 PubKey4 PubKey5 5 CHECKMULTISIG |
| ---------------- | --------------------------------------------------------- |
| **Unlocking Script** | **Sig1 Sig2**                                                |

Table 2. Complex script as P2SH

| Redeem Script    | 2 PubKey1 PubKey2 PubKey3 PubKey4 PubKey5 5 CHECKMULTISIG |
| ---------------- | --------------------------------------------------------- |
| **Locking Script**   | **HASH160 <20-byte hash of redeem script> EQUAL**             |
| **Unlocking Script** | **Sig1 Sig2 <redeem script>**    

参考资料:
[比特币系统的脚本（Script)——交易生成和验证的原理（第一部分）（初稿）](https://blog.csdn.net/taifei/article/details/73321293)
[TP's Go Bitcoin Tests - Addresses](http://gobittest.appspot.com/Address)

                             |

