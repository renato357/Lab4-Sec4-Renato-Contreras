from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes

def get_input_with_adjustment(prompt, target_size, description):
    user_input = input(f"{prompt} ({description}): ").encode()

    if len(user_input) < target_size:
        padding = get_random_bytes(target_size - len(user_input))
        adjusted_key = user_input + padding
    elif len(user_input) > target_size:
        adjusted_key = user_input[:target_size]
    else:
        adjusted_key = user_input

    print(f"Clave ajustada: {adjusted_key.decode(errors='ignore')}")
    return adjusted_key

def get_strict_input(prompt, expected_size, description):
    while True:
        user_input = input(f"{prompt} ({description}): ").encode()
        if len(user_input) == expected_size:
            return user_input
        print(f"Error: La entrada debe tener exactamente {expected_size} bytes.")

# Funciones de cifrado y descifrado para cada algoritmo
def encrypt_des(plaintext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_text = plaintext + b" " * (8 - len(plaintext) % 8)
    return cipher.encrypt(padded_text)

def decrypt_des(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext)
    return decrypted_text.rstrip()

def encrypt_aes(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = plaintext + b" " * (16 - len(plaintext) % 16)
    return cipher.encrypt(padded_text)

def decrypt_aes(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext)
    return decrypted_text.rstrip()

def encrypt_3des(plaintext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_text = plaintext + b" " * (8 - len(plaintext) % 8)
    return cipher.encrypt(padded_text)

def decrypt_3des(ciphertext, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_text = cipher.decrypt(ciphertext)
    return decrypted_text.rstrip()


def main():
    print("Bienvenido al encriptador y desencriptador")
    
    # Seleccionar algoritmo
    print("\nQue algoritmo quieres usar? Se ocupa el modo CBC en cada uno.")
    print("1. DES")
    print("2. AES-256")
    print("3. 3DES")
    
    while True:
        algorithm_choice = input("Seleccione un algoritmo (1, 2 o 3): ")
        if algorithm_choice in ['1', '2', '3']:
            break
        print("Error: Debe seleccionar 1, 2 o 3.")

    if algorithm_choice == '1':
        key_size = 8
        iv_size = 8
        algorithm_name = "DES"
    elif algorithm_choice == '2':
        key_size = 32
        iv_size = 16
        algorithm_name = "AES-256"
    else:
        key_size = 24
        iv_size = 8
        algorithm_name = "3DES"

    # Entrada de datos
    print(f"\n--- {algorithm_name} ---")
    plaintext = input("Ingrese texto a cifrar: ").encode()
    
    key = get_input_with_adjustment("Ingrese la clave", key_size, f"{key_size} bytes requeridos para {algorithm_name}")
    iv = get_strict_input("Ingrese el Vector de Inicializacion (IV)", iv_size, f"{iv_size} bytes requeridos para {algorithm_name}")

    print("\nDatos capturados correctamente.")
    print(f"Texto a procesar: {plaintext.decode(errors='ignore')}")
    print(f"Clave final utilizada: {key.decode(errors='ignore')}")
    print(f"IV final utilizado: {iv.decode(errors='ignore')}")

    # Cifrado y descifrado
    if algorithm_choice == '1':
        encrypted_text = encrypt_des(plaintext, key, iv)
        decrypted_text = decrypt_des(encrypted_text, key, iv)
    elif algorithm_choice == '2':
        encrypted_text = encrypt_aes(plaintext, key, iv)
        decrypted_text = decrypt_aes(encrypted_text, key, iv)
    else:
        encrypted_text = encrypt_3des(plaintext, key, iv)
        decrypted_text = decrypt_3des(encrypted_text, key, iv)

    print("\nTexto cifrado (hexadecimal):", encrypted_text.hex())
    print("Texto descifrado:", decrypted_text.decode(errors='ignore'))

if __name__ == "__main__":
    main()
