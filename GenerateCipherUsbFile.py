from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
import os, base64, psutil

class PrivateKey:
    privatePEM = ""
    @staticmethod
    def create(keyStr):
        new_string = ""
        for i in range(0, len(keyStr), 64):
            if(len(keyStr[i:i+64]) >= 64):
                new_string += keyStr[i:i+64] + '\n'
            else:
                new_string += keyStr[i:i+64]
        private_key = "-----BEGIN PRIVATE KEY-----\n" + new_string
        private_key += "\n-----END PRIVATE KEY-----"
        print(private_key)
        return serialization.load_pem_private_key(private_key.encode('utf-8'), password=None, backend=default_backend())
    
    def __init__(self):
        keyStr = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANWcO5Buo3G9DRQv/cJaBnR/5vr+IxsHO3Fsi47dUTCtvW7yBHMFn4iGAkOoK7hpO+RllsgWWpOLoDu90dCCwCXIC0WmTbq8a/fBidrILpxp9Zp9+60bLyIpwP0XtoseGH5SD4i29oOsXDajdJ/G3vQ7AUMp+a5F+oPSmqCi7Hq9AgMBAAECgYAi+E3ECmjVkPaYLHclnylZXysIQhyrKxbvLa73N4I4LulJRXO3BN+mMRIj01889HVqobr6jLZNW1ljDmNP+GfOOupPir7TdWkUn/ZSRbBYRL+3HuXVhBCNQCPVSEWCxwbjSsCgim74JksmCfUTX6RhOeUGZLn+b5/qGf9kBBaVHQJBAPhLwFq0m3QpIRZnU5WRbuC6olpJVrTUIHbXEyunmzSZk4rsDhKTHqP74YnIFu3a9eQHBaNjlUGyE8d7oyBgFe8CQQDcPPf3xGaAGxYEbCHisLJjsrRolUoQ+xRjmWXsRyzjCZxnjhrdSJXYXJoskZyooduwCwHnc3LD8k68dwL2bMYTAkAZtqaV/iw3LGc7zbmPPL9x0IItvXiYQ3uVMxLOK45cNSdddLLEY64Bp30k6q7NNSbP1ZZU5GQ5qHp55yjummTLAkEAgRSu1SXkWZMGfYMO/TlI5MwZlu5g4cD2+0UuCqTQtySr6bnNHwLq6EumBRc29VMgWnapIAl3K0c6RJWQQ/QOxwJBAOEIS57GWAVKvkC8srE5WVRE1MjEB3JnwbkALrH7e3TrWO+XePzV1OLaYPcbUYJ+VglShgkYcZn6tUv0kdJfkJI="
        self.privatePEM = self.create(keyStr)

def detect_usb_drive():
    partitions = psutil.disk_partitions(all=True)
    for partition in partitions:
        if "removable" in partition.opts and os.path.exists(partition.device):
            return partition.device
    return None

def write_to_usb_drive(usb_drive, filename, content):
    if not usb_drive:
        print("未找到U盘")
        return
    file_path = os.path.join(usb_drive, filename)
    try:
        with open(file_path, 'w') as file:
            file.write(content)
        print(f"已成功写入文件到U盘 {usb_drive}")
    except Exception as e:
        print(f"写入文件时发生错误: {e}")

def encryptData(publicKey, plainText):
    try:
        recipient_public_key = serialization.load_pem_public_key(publicKey.encode('utf-8'), backend=default_backend())
        ciphertext = recipient_public_key.encrypt(plainText.encode('utf-8'), padding.PKCS1v15())
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        print(f"加密时发生错误: {e}")
        return None
    
def createPublicKey(privateKey: RSAPrivateKey):
    public_key = privateKey.public_key()
    publicKey = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return publicKey

def decryptRSA(privateKey: RSAPrivateKey, ciphertext):
    try:
        ciphertext = base64.b64decode(ciphertext.encode('utf-8'))
        plainText = privateKey.decrypt(ciphertext, padding.PKCS1v15())
        return plainText.decode('utf-8')
    except Exception as e:
        print(f"解密时发生错误: {e}")
        return None
    
if __name__ == "__main__":
    # 无限循环来保持控制台窗口打开
    while True:
        plainText = input("请输入MAC地址：")
        private_key = PrivateKey()
        if private_key.privatePEM:
            publicKey = createPublicKey(private_key.privatePEM)
            cipherText = encryptData(publicKey, plainText)
            usb_drive = detect_usb_drive()
            print(f"加密的MAC：{cipherText}")
            if usb_drive:
                filename = "EncryptDebugFile.txt"
                content = cipherText
                write_to_usb_drive(usb_drive, filename, publicKey)
                decryptedText = decryptRSA(private_key.privatePEM, cipherText)
                if decryptedText:
                   print(f"MAC{decryptedText} 加密成功！")
            else: print("请插入U盘再试！")
