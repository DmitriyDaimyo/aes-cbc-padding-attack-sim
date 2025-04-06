import socket
import time

host = "0.0.0.0"  #choose address
port = 00000 #choose port


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))



mes = '2\n' #request to be sent to server
sock.sendall(mes.encode())
time.sleep(0.5)

response = sock.recv(2024) #A response containing an AES_CBC encrypted message

#Depending on the response format, you should extract the encrypted part
original_code = response.decode()[16:80]

#A ist type is more suitable for modification in this case
formated_code = list(response.decode()[16:80])


#This is the central part of the code where the AES-CBC padding attack is implemented. It is necessary for the server to return a padding error
i2 = 0
last_b = 0
counter = 0
byte_array = []
iv_array = []
print("STARTLOOP1")
#START LOOP
flag = 0

#In this loop, we modify the bytes of the first encrypted block (which will be XORed with the decrypted second block) to find a case where a padding error does not occur
for l in range(16):
    for k in range(16):
        formated_code[30-counter*2] = hex(k)[2]
        for d in range(16):
            formated_code[31-counter*2] = hex(d)[2]
            changed_code = "".join(formated_code)

            #Send the modyfied encrypted message
            mes = '{"token": "'+changed_code+'"}\n'
            sock.sendall(mes.encode())
            time.sleep(0.4)

            #Check for the error
            response = sock.recv(1024)
            if response[0] == 86:
            
                b1 = changed_code[31-counter*2]
                b2 = changed_code[30-counter*2]
                b = b2+b1
                b = int(b,16)
                #i2 is the resulting byte after the decryption operation but before the XOR operation
                i2 = b^(counter+1)

                b1 = original_code[31-counter*2]
                b2 = original_code[30-counter*2]
                b = b2+b1
                b = int(b,16)

                #last_b is the byte of plaintext
                last_b = i2^b

                flag = 1

                byte_array.append(last_b)
                iv_array.append(i2)
                break
            
        if flag==1:
            flag = 0
            break

    #In this loop, we modify the first block to produce valid padding during the next decryption cycle
    for pos in range(counter+1):

        changed = (counter+2)^iv_array[pos]
        string_changed = hex(changed)

        if len(string_changed) == 4:
            formated_code[30-pos*2] = string_changed[2]
            formated_code[31-pos*2] = string_changed[3]

        if len(string_changed) == 3:
            formated_code[30-pos*2] = '0'
            formated_code[31-pos*2] = string_changed[2]
        
    counter+=1
    if counter == 16:

        break

#Show the plaintext of the second block
print("plaintext_of_second_block: ", byte_array)


sock.close()
exit()