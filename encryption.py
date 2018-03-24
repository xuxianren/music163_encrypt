from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import base64
import binascii
import random


"""
post参数：params encSecKey
加密流程:
    ①将明文先AES加密一次（密钥'0CoJUm6Qyw8W8jud'），
	②随机生成一个16位的密钥，对上一步结果进行AES加密，得到POST参数里的param。
    ③对随机密钥进行RSA加密，得到POST参数里的encSecKey。

RSA:明文:   SecKey(随机生成的16位字符串)
    参数:   e = '010001'
            n = '00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615' \
                'bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf' \
                '695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46' \
                'bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b' \
                '8e289dc6935b3ece0462db0a22b8e7'
    密文:   encSecKey

AES:明文： "{rid:\"\", offset:\"40\", total:\"false\", limit:\"20\", csrf_token:\"\"}"
    偏移量：iv="0102030405060708"
    第一次加密参数：'0CoJUm6Qyw8W8jud'
    第二次加密参数：SecKey
    密文：params
"""


def create_aes_key(size=16):
    # 生成16字节的bytes类型字符串，用于AES的第二次加密
    c = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return bytes(''.join(random.sample(c, size)), encoding='utf-8')


def rsa_encrypt(key):
    e = '010001'
    n = '00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615' \
        'bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf' \
        '695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46' \
        'bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b' \
        '8e289dc6935b3ece0462db0a22b8e7'
    reverse_key = key[::-1]
    pub_key = RSA.construct([int(n, 16), int(e, 16)])
    encrypt_key = pub_key.encrypt(int(binascii.hexlify(reverse_key), 16),
                                   None)[0]
    return format(encrypt_key, 'x').zfill(256)


def aes_encrypt(text, key, iv="0102030405060708"):
    pad = 16 - len(text) % 16
    text = text + pad * chr(pad)
    encryptor = AES.new(key, 2, iv)
    enc_text = encryptor.encrypt(text)
    enc_text_encode = str(base64.b64encode(enc_text))[2:-1]
    return enc_text_encode


def music163_encryt(text):
    """
    :param text: 明文
    :return: 加密后的参数
    """
    assert isinstance(text, str), "密文必需为字符串类型"
    first_aes_key = '0CoJUm6Qyw8W8jud'
    second_aes_key = create_aes_key(16)
    second_aes_key = b'F'*16
    enc_text = aes_encrypt(
        aes_encrypt(text, first_aes_key),
        second_aes_key)
    enc_aes_key = rsa_encrypt(second_aes_key)
    return {'params': enc_text,
            'encSecKey': enc_aes_key,
            }

if __name__ == '__main__':
    # text = {
    #     'username': '邮箱',
    #     'password': '密码',
    #     'rememberLogin': 'true'
    # }
    text = '{"rid":"R_SO_4_4341314","offset":"440","total":"false","limit":"20","csrf_token":""}'
    # print(text)
    print(music163_encryt(text))
    # text = b'F'*16
    # print(rsa_encrypt(text))