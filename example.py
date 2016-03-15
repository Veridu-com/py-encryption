from src.PyEncryption import PyEncryption, InvalidCipherTextException, CryptoTestFailedException, CannotPerformOperationException
import sys

pyEnc = PyEncryption()

try:
    key = pyEnc.createNewRandomKey()
except (CryptoTestFailedException, CannotPerformOperationException) as e:
    print('Cannot safely create a key')
    sys.exit(1)

message = 'ATTACK AT DAWN'

try:
    cipherText = pyEnc.encrypt(message, key)
except (CryptoTestFailedException, CannotPerformOperationException) as e:
    print('Cannot safely perform encryption')
    sys.exit(1)

try:
    plainText = pyEnc.decrypt(cipherText, key)
except InvalidCipherTextException as e:
    # Either:
    #   1. The ciphertext was modified by the attacker,
    #   2. The key is wrong, or
    #   3. cipherText is not a valid ciphertext or was corrupted.
    # Assume the worst.
    print('DANGER! DANGER! The ciphertext has been tampered with!')
    sys.exit(1)
except (CryptoTestFailedException, CannotPerformOperationException) as e:
    print('Cannot safely perform decryption')
    sys.exit(1)
