from numpy import *

file_name = 'mbr.bin'
Byte_chunk = 480


with open(file_name, 'rb') as f:
    binary_data = f.read().hex()
    # hex_data = binary_data.hex()
    # process binary_data here
    print(binary_data)
    print("#########################")
    print(len(binary_data)) 
    

print("#########################")


i = 0
k = 0
j = 480
m=0 
n=2

data_chunk = []

chunk_arr =[]

while i < 480:
    print("-----------------")
    # print("chunk ID: " + str(k))
    chunk = binary_data[i:j]  


    while m < Byte_chunk:
        print("chunk ID: " + str(k))
        print("seperate into 2")
        chunk_chunk = chunk[m:n]
        chunk_arr.append(chunk_chunk)
        print (chunk_chunk)
        print (chunk_arr)
        m = m +2
        n = n +2
        k = k+1

    # data_chunk.append(chunk)
    # print("chuck: "+ str(chunk))

    # print("data chunk: " + str(data_chunk[0]))
    i = i + 480
    j = j + 480
    # k = k+1
