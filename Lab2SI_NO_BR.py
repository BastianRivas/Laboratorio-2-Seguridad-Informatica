#Laboratorio 2 de seguridad informatica
#Integrantes: Nicolás Osorio y Bastián Rivas

from cryptography.fernet import Fernet
import hashlib

def generar_clave_secreta():
    # Generar una clave secreta Fernet válida
    return Fernet.generate_key()

def cifrar_y_generar_hash(clave_secreta, mensaje_original):
    # Cifra el mensaje
    cipher_suite = Fernet(clave_secreta)
    mensaje_cifrado = cipher_suite.encrypt(mensaje_original.encode())

    # Calcula el hash del mensaje original
    hash_original = hashlib.sha256(mensaje_original.encode()).hexdigest()

    # Escribe el mensaje cifrado y el hash en el archivo de salida
    with open('mensajeseguro.txt', 'wb') as archivo_salida:
        archivo_salida.write(mensaje_cifrado + b'\n' + hash_original.encode())

    with open('mensajedeentrada.txt', 'w') as archivo_entrada:
        archivo_entrada.write(mensaje_original)

    print("Mensaje cifrado y hash calculado. Clave secreta:", clave_secreta)

def descifrar_y_verificar(clave_secreta):
    # Lee el mensaje cifrado y el hash desde el archivo de entrada seguro
    with open('mensajeseguro.txt', 'rb') as archivo_seguro:
        contenido = archivo_seguro.read().split(b'\n')
        mensaje_cifrado = contenido[0]
        hash_original = contenido[1]

    # Descifra el mensaje cifrado
    cipher_suite = Fernet(clave_secreta)
    mensaje_descifrado = cipher_suite.decrypt(mensaje_cifrado)

    # Calcula el hash del mensaje descifrado
    hash_calculado = hashlib.sha256(mensaje_descifrado).hexdigest()

    # Compara el hash original y el hash calculado para verificar la integridad
    if hash_original.decode() == hash_calculado:
        print("El mensaje es auténtico y no ha sido modificado.")
        with open('mensajedeentrada.txt', 'w') as archivo_entrada:
            archivo_entrada.write(mensaje_descifrado.decode())
    else:
        print("El mensaje ha sido modificado.")

def main():
    opcion = input("Elija una opción (cifrar/verificar): ").lower()

    if opcion == 'cifrar':
        clave_secreta = generar_clave_secreta()
        mensaje_original = input("Ingrese el mensaje que desea cifrar: ")
        cifrar_y_generar_hash(clave_secreta, mensaje_original)
    elif opcion == 'verificar':
        clave_secreta = input("Ingrese la clave secreta: ").encode()
        descifrar_y_verificar(clave_secreta)
    else:
        print("Opción no válida. Por favor, elija 'cifrar' o 'verificar'.")

if __name__ == "__main__":
    main()






