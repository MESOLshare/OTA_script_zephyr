from numpy import *

# values in HEX format
start = "F9"
ver_sion = "10"
command = "06"


inital_list = []
data_chunk = []
chunk_arr =[]

#############
CMD_list = ("Open", "Close", "Ack", "Busy", "Reay", "Chunk", "Validate")

# Open = 1
# Close = 2
# Ack = 3
# Busy = 4
# Ready = 5
# Chunk = 6
# Validate = 7
#############

#CRC
crctable= [0x00, 0x91, 0xE3, 0x72, 0x07, 0x96,
                                     0xE4, 0x75, 0x0E, 0x9F, 0xED, 0x7C, 0x09, 0x98, 0xEA, 0x7B, 0x1C,
                                     0x8D, 0xFF, 0x6E, 0x1B, 0x8A, 0xF8, 0x69, 0x12, 0x83, 0xF1, 0x60,
                                     0x15, 0x84, 0xF6, 0x67, 0x38, 0xA9, 0xDB, 0x4A, 0x3F, 0xAE, 0xDC,
                                     0x4D, 0x36, 0xA7, 0xD5, 0x44, 0x31, 0xA0, 0xD2, 0x43, 0x24, 0xB5,
                                     0xC7, 0x56, 0x23, 0xB2, 0xC0, 0x51, 0x2A, 0xBB, 0xC9, 0x58, 0x2D,
                                     0xBC, 0xCE, 0x5F, 0x70, 0xE1, 0x93, 0x02, 0x77, 0xE6, 0x94, 0x05,
                                     0x1E, 0x6B, 0xFA, 0x88, 0x19, 0x62, 0xF3, 0x81, 0x10, 0x65, 0xF4,
                                     0x7E, 0xEF, 0x9D, 0x0C, 0x79, 0xE8, 0x9A, 0x0B, 0x6C, 0xFD, 0x8F,
                                     0x86, 0x17, 0x48, 0xD9, 0xAB, 0x3A, 0x4F, 0xDE, 0xAC, 0x3D, 0x46,
                                     0xD7, 0xA5, 0x34, 0x41, 0xD0, 0xA2, 0x33, 0x54, 0xC5, 0xB7, 0x26,
                                     0x53, 0xC2, 0xB0, 0x21, 0x5A, 0xCB, 0xB9, 0x28, 0x5D, 0xCC, 0xBE,
                                     0x2F, 0xE0, 0x71, 0x03, 0x92, 0xE7, 0x76, 0x04, 0x95, 0xEE, 0x7F,
                                     0x0D, 0x9C, 0xE9, 0x78, 0x0A, 0x9B, 0xFC, 0x6D, 0x1F, 0x8E, 0xFB,
                                     0x6A, 0x18, 0x89, 0xF2, 0x63, 0x11, 0x80, 0xF5, 0x64, 0x16, 0x87,
                                     0xD8, 0x49, 0x3B, 0xAA, 0xDF, 0x4E, 0x3C, 0xAD, 0xD6, 0x47, 0x35,
                                     0xA4, 0xD1, 0x40, 0x32, 0xA3, 0xC4, 0x55, 0x27, 0xB6, 0xC3, 0x52,
                                     0x20, 0xB1, 0xCA, 0x5B, 0x29, 0xB8, 0xCD, 0x5C, 0x2E, 0xBF, 0x90,
                                     0x01, 0x73, 0xE2, 0x97, 0x06, 0x74, 0xE5, 0x9E, 0x0F, 0x7D, 0xEC,
                                     0x99, 0x08, 0x7A, 0xEB, 0x8C, 0x1D, 0x6F, 0xFE, 0x8B, 0x1A, 0x68,
                                     0xF9, 0x82, 0x13, 0x61, 0xF0, 0x85, 0x14, 0x66, 0xF7, 0xA8, 0x39,
                                     0x4B, 0xDA, 0xAF, 0x3E, 0x4C, 0xDD, 0xA6, 0x37, 0x45, 0xD4, 0xA1,
                                     0x30, 0x42, 0xD3, 0xB4, 0x25, 0x57, 0xC6, 0xB3, 0x22, 0x50, 0xC1,
                                     0xBA, 0x2B, 0x59, 0xC8, 0xBD, 0x2C, 0x5E, 0xCF]

def make_CRC( input_data, count):
    fcs = 0xFF
    i = 0
    
    for i in range (count):
        
        fcs = crctable[fcs ^ int(input_data[i], base = 16)]

    return((0xFF - fcs))

def file_split(file):

    print("########## file_split #############")

    Byte_chunk = 480
    arr_len = 240

    with open(file, 'rb') as f:
        binary_data = f.read().hex()
        # hex_data = binary_data.hex()
        # process binary_data here
        print("File contant:")
        # print(binary_data)
        # print("#########################")
        print("File length: ", end ="")
        print(len(binary_data)) 

    print("#########################")

    file_size = len(binary_data)

    i = 0
    k = 0
    j = 480

    m = 0 
    n = 2
    p = 1

    data_chunk = []
    chunk_arr =[]

    while i < file_size:
        chunk = binary_data[i:j] 
        print("chunk ID: " + str(k))
        # print("chunk: "+ str(chunk))

        while m < Byte_chunk:
            # print("-----------------------------")
            # print("m: " + str(m))
            # print("chunk chuck ID: " + str(p))
            # print("seperate into 2")
            chunk_chunk = chunk[m:n]
            chunk_arr.append(chunk_chunk)
            # print("Chunk_arr: " + str(chunk_arr))

            # print("loop: " + str(arr_len))
            # print("-----------------------------")

            # Byte_chunk = Byte_chunk + 480

            if (len(chunk_arr) == arr_len):
                
                print("into loop")
                print("Chunk_arr: " + str(chunk_arr))
                # Byte_chunk = Byte_chunk + 480
                # arr_len =arr_len + 240

            m = m + 2
            n = n + 2
            p = p + 1

        #     # chunk_arr.append(inital_list)
        #     # data_chunk.extend(inital_list) 
        #     # data_chunk.extend(chunk_arr) 

        i = i + 480
        j = j + 480
        k = k+1


# if __name__ == "__main__":

#     file_name = 'mbr.bin'

#     file_split(file_name)
#     Byte_chunk = 480

#     inital_list.append(start)
#     inital_list.append(ver_sion)
#     inital_list.append(command)

#     print("inital_list: " + str(inital_list))

#     with open(file_name, 'rb') as f:
#         binary_data = f.read().hex()
#         # hex_data = binary_data.hex()
#         # process binary_data here
#         print("File contant:")
#         # print(binary_data)
#         # print("#########################")
#         print("File length: ", end ="")
#         print(len(binary_data)) 

#     print("#########################")

#     file_size = len(binary_data)

#     data_chunk = []
#     chunk_arr =[]

#     while i < file_size:
    
#         chunk = binary_data[i:j]  
#         # print("chuck: "+ str(chunk))

#         while m < Byte_chunk:
#             # print("-----------------------------")
#             # print("chunk chuck ID: " + str(p))
#             # print("seperate into 2")
#             chunk_chunk = chunk[m:n]
#             chunk_arr.append(chunk_chunk)

#             arr_len = 240
            
#             # print("m: " + str(m))
#             # print("loop: " + str(arr_len))
#             # print("-----------------------------")

#             m = m + 2
#             n = n + 2
#             p = p + 1

#             if (len(chunk_arr) == arr_len):
                
#                 print("into loop")
#                 print("chunk_arr: ")

#                 # chunk_arr.append(inital_list) extend
#                 data_chunk.extend(inital_list) 
#                 data_chunk.extend(chunk_arr) 

#                 print (chunk_arr)

#                 print ("data chunk: " + str(data_chunk))
#                 print("length of chunk_arr: " + str(len(chunk_arr)))
                
#                 crc = make_CRC(data_chunk, len(data_chunk))
#                 crc_str = '{:02X}'.format(crc)
#                 print("crc: " + str(crc_str))
#                 data_chunk.append(crc_str)
#                 print ("data chunk last: " + str(data_chunk))

#         i = i + 480
#         j = j + 480
#         k = k+1

#     #############################################
#     # print("\n")
#     # for t in range(10):
#     #     print("loop " + str(t))
#     #     print(data_chunk[t])
#     #     print("\n")

if __name__ == "__main__":

    file_name = 'mbr.bin'
    file_split(file_name)
    print("\n*************END***************")
