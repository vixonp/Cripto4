from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad
# get_random_bytes ya no es necesario para el relleno
# from Crypto.Random import get_random_bytes 
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
import binascii

# --- MODIFICACIÓN 1: Relleno predecible con bytes nulos ---

def creacion_Clave(Key, Cifrado):
    if Cifrado == 1 : 
        Tamaño_bytes = 8
    elif Cifrado == 2 : 
        Tamaño_bytes = 32
    elif Cifrado == 3 : 
        Tamaño_bytes = 24
    else:
        # Manejo para cifrado no válido
        return None

    if len(Key) < Tamaño_bytes : 
        # Rellena con bytes nulos (b'\x00') para ser predecible
        Key += b'\x00' * (Tamaño_bytes - len(Key))
    elif len(Key) > Tamaño_bytes :
        Key = Key[:Tamaño_bytes]

    return Key

def Encriptacion_DES(Key , Vector_IV, Texto) : 
    
    if len(Vector_IV) < 8 : 
        # Rellena con bytes nulos (b'\x00')
        Vector_IV += b'\x00' * (8  - len(Vector_IV))
        
    elif len(Vector_IV) > 8 : 
        Vector_IV = Vector_IV[:8]
        
    Cifrado = DES.new(Key, DES.MODE_CBC,iv = Vector_IV)
    Texto_Con_Padding = pad(Texto,DES.block_size)
    Texto_Cifrado = Cifrado.encrypt(Texto_Con_Padding)
    
    return Texto_Cifrado,Vector_IV

def Encriptacion_3DES(Key , Vector_IV, Texto) : 
    
    if len(Vector_IV) < 8 : 
        # Rellena con bytes nulos (b'\x00')
        Vector_IV += b'\x00' * (8  - len(Vector_IV)) 
        
    elif len(Vector_IV) > 8 : 
        Vector_IV = Vector_IV[:8]
    
    Cifrado = DES3.new(Key, DES3.MODE_CBC,iv = Vector_IV)
    Texto_Con_Padding = pad(Texto,DES3.block_size)
    Texto_Cifrado = Cifrado.encrypt(Texto_Con_Padding)
    
    return Texto_Cifrado,Vector_IV
    
def Encriptacion_AES_256(Key , Vector_IV, Texto) :     
    
    if len(Vector_IV) < 16 : 
        # Rellena con bytes nulos (b'\x00')
        Vector_IV += b'\x00' * (16  - len(Vector_IV)) 
        
    elif len(Vector_IV) > 16 : 
        Vector_IV = Vector_IV[:16]
    
    Cifrado = AES.new(Key, AES.MODE_CBC,iv = Vector_IV)
    Texto_Con_Padding = pad(Texto,AES.block_size)
    Texto_Cifrado = Cifrado.encrypt(Texto_Con_Padding)
    return Texto_Cifrado,Vector_IV

# --- Funciones de Descifrado (sin cambios) ---

def Desencriptacion_DES(Key, Vector_IV, Texto_Cifrado):
    descifrado = DES.new(Key, DES.MODE_CBC, iv=Vector_IV)
    texto_plano = unpad(descifrado.decrypt(Texto_Cifrado), DES.block_size)
    return texto_plano


def Desencriptacion_3DES(Key, Vector_IV, Texto_Cifrado):
    descifrado = DES3.new(Key, DES3.MODE_CBC, iv=Vector_IV)
    texto_plano = unpad(descifrado.decrypt(Texto_Cifrado), DES3.block_size)
    return texto_plano   
    
def Desencriptacion_AES_256(Key, Vector_IV, Texto_Cifrado):
    descifrado = AES.new(Key, AES.MODE_CBC, iv=Vector_IV)
    texto_plano = unpad(descifrado.decrypt(Texto_Cifrado), AES.block_size)
    return texto_plano    
    
    
# --- MODIFICACIÓN 2: Bucle principal mejorado ---
    
while 1 :
    
    print("\n" + "="*30)
    print("Ingrese tipo de Cifrado")
    print("[1] Para DES")
    print("[2] Para AES-256")
    print("[3] para 3DES")
    print("Cualquier otro valor para Salir")
    
    try:
        Cifrado = int(input("Seleccione Cifrado: "))
    except ValueError:
        print("Entrada no válida. Saliendo.")
        break

    # Sale del bucle si la opción no es válida
    if Cifrado not in [1, 2, 3] :
        print("Saliendo del programa.")
        break
    
    print("\n¿La clave y el IV están en texto plano (UTF-8) o en Hexadecimal?")
    print("[1] Texto (ej: 'clave')")
    print("[2] Hexadecimal (ej: '636c617665')")
    tipo_entrada = input("Seleccione tipo de entrada: ")
    
    Key_input = input("Ingrese clave a Para cifrar : \n")
    Vector_input = input("ingrese valor del vector IV : \n")
    Texto_input = input("ingrese texto a para cifrar : \n")

    try:
        if tipo_entrada == '2':
            # Si es Hex, DECODIFICAMOS de hex a bytes
            Key = binascii.unhexlify(Key_input)
            Vector = binascii.unhexlify(Vector_input)
        else:
            # Si es Texto, CODIFICAMOS de utf-8 a bytes (como antes)
            Key = Key_input.encode('utf-8')
            Vector = Vector_input.encode('utf-8')
            
        Texto = Texto_input.encode('utf-8')
        
    except binascii.Error as e:
        print(f"\n--- ERROR: Hexadecimal inválido. ---")
        print(f"Detalle: {e}")
        print("Por favor, inténtelo de nuevo.\n")
        continue # Reinicia el bucle
    except Exception as e:
        print(f"Error inesperado: {e}")
        continue
        
    # Procesa la clave para que tenga el tamaño correcto
    Valided_Key = creacion_Clave(Key,Cifrado)
    
    if Cifrado == 1 :
        C_Text,Vector_IV = Encriptacion_DES(Valided_Key,Vector,Texto)
        Texto_Original = Desencriptacion_DES(Valided_Key,Vector_IV,C_Text)
    elif Cifrado == 3 : 
        C_Text,Vector_IV = Encriptacion_3DES(Valided_Key,Vector,Texto)
        Texto_Original = Desencriptacion_3DES(Valided_Key,Vector_IV,C_Text)
    elif Cifrado == 2 :  
        C_Text,Vector_IV = Encriptacion_AES_256(Valided_Key,Vector,Texto)
        Texto_Original = Desencriptacion_AES_256(Valided_Key,Vector_IV,C_Text)
    
    
    # --- MODIFICACIÓN 3: Etiquetas de impresión corregidas ---
    print("\n--- Resultados ---")
    print("Llave Final (Hex) :", binascii.hexlify(Valided_Key))
    print("Llave Final (Bytes) :", Valided_Key)   
    print("Vector IV Final (Hex) :", binascii.hexlify(Vector_IV))
    print("Vector IV Final (Bytes) :", Vector_IV)
    print("Texto Cifrado (Hex) :", binascii.hexlify(C_Text))
    print("Texto Cifrado (Bytes) :", C_Text)
    print("Texto Descifrado (Hex) :", binascii.hexlify(Texto_Original))
    print("Texto Descifrado (Bytes) :", Texto_Original)
    print("="*30)