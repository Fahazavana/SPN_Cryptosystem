# Defining the Sbox in hexa-decimal
# Define the Sbox for encryption
# The 0x at the beging mean that we work in Hexadecimal basis
S_BOX = {0: 0xE, 
        1: 0x4, 
        2: 0xD, 
        3: 0x1, 
        4: 0x2, 
        5: 0xF, 
        6: 0xB, 
        7: 0x8, 
        8: 0x3,
        9: 0xA, 
        0xA: 0x6, 
        0xB: 0xC, 
        0xC: 0x5, 
        0xD: 0x9, 
        0xE: 0x0, 
        0xF: 0x7}

# Define_the inverse of S_box for de_encryption
S_BOX_INV = {0xE: 0, 
            0x4: 1, 
            0xD: 2, 
            0x1: 3, 
            0x2: 4, 
            0xF: 5, 
            0xB: 6, 
            0x8: 7,
            0x3: 8, 
            0xA: 9, 
            0x6: 0xA, 
            0xC: 0xB, 
            0x5: 0xC, 
            0x9: 0xD, 
            0x0: 0xE, 
            0x7: 0xF}

# Define the permutation box
P_BOX = {0: 0, 
         1: 4, 
         2: 8, 
         3: 12, 
         4: 1, 
         5: 5, 
         6: 9, 
         7: 13,
         8: 2, 
         9: 6, 
         10: 10, 
         11: 14, 
         12: 3, 
         13: 7, 
         14: 11, 
         15: 15}

KEY = "00111010100101001101011000111111"

def normalize(bitstrem,length):
    entry = str(bitstrem)
    entry=entry.replace('0b', '')
    k = len(entry)
    if k<length:
        t = length - k
        entry = '0'*t + entry
    return entry

def create_subKey(KEY):
    """
    Create 5 keys such that :
    K_1 : 0->15
    K_2 : 4->29
    K_3 : 8->23
    K_4 : 12->27
    K_5 : 16->31
    """
    return [int(x,2) for x in [KEY[0:16], KEY[4:20], KEY[8:24], KEY[12:28], KEY[16:32]]]

def apply_SBox(msg,s_box):
    string_msg = normalize(bin(msg),16)
    block = [string_msg[0:4], string_msg[4:8], string_msg[8:12], string_msg[12:16]]
    sboxed = ''
    for i in range(4):
        tmp = s_box[int(block[i],2)]
        tmp = bin(tmp)
        tmp = normalize(tmp, 4)
        sboxed +=tmp
    return int(sboxed,2) 

def apply_PBox(s,p_box):
        s = normalize(bin(s),16)    
        tmp=['']*16
        for i in range(0,16):
            tmp[i]= s[p_box[i]]
        msg = int(''.join(tmp),2)
        return msg



def encryption_round(msg,sub_key,s_box,p_box):
        # msg XOR Key_i
        msg = msg ^ sub_key
        # Apply S_box
        msg = apply_SBox(msg, s_box)
        # Applying the permutation
        msg = apply_PBox(msg, p_box)
        return msg

def de_encryption_round(msg,sub_key,p_box,s_box):
        # msg XOR Key_i
        msg = msg ^ sub_key
        # Applying the permutation
        msg = apply_PBox(msg, p_box)
        # Apply s_box the inverse
        msg = apply_SBox(msg, s_box) 
        return msg 


def encryption(msg,key):
    subKey = create_subKey(key)
    # Three first round
    for Round in range(0,3):
        msg=encryption_round(msg, subKey[Round], S_BOX, P_BOX)
    # K4 XOR msg
    msg = msg ^ subKey[3]
    msg = apply_SBox(msg, S_BOX)
    # K5 XOR msg
    msg = msg ^ subKey[4]
    return msg


def de_encryption(msg,key):
    # Get five key
    subKey = create_subKey(key)
    # msg XOR K5 to cancel it
    msg = msg ^ subKey[4]
    # Inversing the S_Box round 4
    msg =  apply_SBox(msg, S_BOX_INV)
    # Inverting the process from round 4 to 2
    for Round in range(3,0,-1):
        msg=de_encryption_round(msg,subKey[Round],P_BOX,S_BOX_INV)
    # Cancel the first Key :
    msg = msg ^ subKey[0]
    return msg


def test():
    print("\n                      S.P.N.")
    print('======================================================')
    print("The output will be writen in binary mode.\n")
    x = int('111',2)
    print('======================================================')
    print("32-bits Key      : {}\n".format(bin(int(KEY,2))))
    print('======================================================')
    print("Plain text       : {}\n".format(bin(x)))
    print('======================================================')
    y = encryption(x, KEY)
    print("Ciphered text    : {}\n".format(bin(y)))
    print('======================================================')
    z= de_encryption(y, KEY)
    print("De_Ciphered text : {}\n".format(bin(z)))
    print('======================================================')

if __name__ == '__main__':
    test()
    #############Encrypt file###############
    # read a file in binary mode
    print("\n======================================")
    print("|        FILE ENCRYPTION TEST        |")
    print("======================================\n")
    plain_file = open("SPN_test/plain_text.txt","r")
    ciphered_file = open("SPN_test/ciphered_text.txt","wb")
    while True:
        char = plain_file.read(1)
        
        if not char:
            break
        elif char=="\n" : ciphered_file.write("\n".encode("ascii"))
        else:
            char = (ord(char))
            char = encryption(char, KEY)
            ciphered_file.write("\\".encode("ascii")+ hex(char).encode("ascii"))
    plain_file.close()
    ciphered_file.close()
    print("Encryption Finished")
    #############Decrypt file###############
    # read a file in binary mode
    print("\n======================================")
    print("|        FILE DECRYPTION TEST        |")
    print("======================================\n")
    ciphered_file = open("SPN_test/ciphered_text.txt","r")
    plain_file = open("SPN_test/plain_text2.txt","w")
    while True:
        #char = ciphered_file.read(1)
        L = ciphered_file.readline()
        L=L.split(chr(92))
        if L==['']:
            break
        for x in L:
            if x ==chr(10)  : plain_file.write(chr(10))
            if x=='n' : print("n")
            elif x == '\\' : continue
            elif x == '' : continue
            else :
                if x[-1]=='\n': 
                    char=x[:-1]
                    if char == '':
                        continue
                    char = int(char,16)
                    char=de_encryption(char, KEY)
                    plain_file.write(chr(char)+chr(10))
                else :
                    char = int(x,16)
                    char=de_encryption(char, KEY)
                    plain_file.write(chr(char))
    plain_file.close()
    ciphered_file.close()
    print("Decryption Finished")