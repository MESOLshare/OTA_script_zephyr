from numpy import *
import hashlib

# values in HEX format
start       = "F9"
ver_sion    = "10"

inital_list = []
data_chunk = []
Chunk_arr =[]
CMD_arr = []

inital_list.append(start)
inital_list.append(ver_sion)

#############
FW_type     = ["MBR", "Bootloader", "Zephyr"]
CMD_list    = ["Open", "Close", "Ack", "Busy", "Reay", "Chunk", "Validate"]

CMD_Open        = 0x01
CMD_Close       = 0x02
CMD_Ack         = 0x03
CMD_Busy        = 0x04
CMD_Ready       = 0x05
CMD_Chunk       = 0x06
CMD_Validation  = 0x07

FW_type_MBR     = 0x01
FW_type_BOOT    = 0x02
FW_type_Zephyr  = 0x03

global file_size
global genHash
global binary_data
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

def gen_hash(filename):

    hash_hex = hashlib.md5(filename.encode('UTF-8')).hexdigest()
    # print("Generated hash: " + str (hash_hex)) 
    hash_arr = [hash_hex[i:i + 2] for i in range(0, len(hash_hex), 2)]
    # print("hash arr: " + str(hash_arr))
    # 55813fbbc9e7d100ede7dd191b504347
    return hash_arr

def file_split(file):

    global file_size
    global binary_data 

    print("########## file_split #############")

    start_index = 0
    end_index   = 240
    Chunk_ID    = 1

    with open(file, 'rb') as f:
        binary_data = f.read().hex()
        # hex_data = binary_data.hex()
        # process binary_data here
        print("File contant:")
        # print(binary_data)
        # print("#########################")
        print("File length: ", end ="")
        print(len(binary_data))

    print("###################################")

    file_size= len(binary_data)

    # sep_binary_data = [binary_data[i:i + 2] for i in range(0, len(binary_data), 2)]
    # # print("Seperated data: " + str(sep_binary_data))
    # print("Length of seperated data: " + str(len(sep_binary_data)))
    # print("Seperated data index 0: " + str(sep_binary_data[0]))

    # while start_index < len(sep_binary_data):
        
    #     data_chunk.extend(inital_list)                          # 3 bytes
    #     # print("data_chunk ID: " + str(Chunk_ID))           
    #     chunk_arr = sep_binary_data[start_index:end_index]      # 240 bytes
    #     # print("chunk_arr: " + str(chunk_arr))

    #     data_chunk.extend(chunk_arr)                            # 243 bytes
    #     # print("data_chunk: " + str(data_chunk))

    #     start_index = start_index + 240
    #     end_index   = end_index + 240
    #     Chunk_ID    = Chunk_ID + 1

    #     chunk_arr.clear()
    #     data_chunk.clear()

def get_fW_type(fw_type):

    set_FW_type = 0x00

    if   (fw_type == FW_type[0]):
        # print("Param: " + str(fw_type))

        set_FW_type = ''.join(f'{FW_type_MBR:04X}')
        set_FW_type = [set_FW_type[i:i + 2] for i in range(0, len(set_FW_type), 2)]

        return set_FW_type
        
    elif (fw_type == FW_type[1]):
        # print("Param: " + str(fw_type))

        set_FW_type = ''.join(f'{FW_type_BOOT:04X}')
        set_FW_type = [set_FW_type[i:i + 2] for i in range(0, len(set_FW_type), 2)]

        return set_FW_type

    elif (fw_type == FW_type[2]):
        # print("Param: " + str(fw_type))

        set_FW_type = ''.join(f'{FW_type_Zephyr:04X}')
        set_FW_type = [set_FW_type[i:i + 2] for i in range(0, len(set_FW_type), 2)]

        return set_FW_type
    
    else:

        return 0

def CMD_packet(CMD_list_params):

    global file_size
    global genHash
    global binary_data

    # print(str(CMD_list_params))
    if   (CMD_list_params == CMD_list[0]): # open
        print(str(CMD_list_params))
        # Open
        # |  CMD  | Chunk ID | FW type | FW size | FW hash MD5 |
        # |  4bit | 12bit    | 2byte   | 4byte   | 32byte      |

        Chunk_ID = 0
        CMD_open_pckt = []

        CMD_Chunk_ID = ( (Chunk_ID << 4) & 0xfff0) | (CMD_Open & 0x0f)
        # CMD_Chunk_ID_hex = CMD_Chunk_ID.to_bytes(2, 'big')
        CMD_Chunk_ID = ''.join(f'{CMD_Chunk_ID:04X}')
        
        CMD_Chunk_ID = [CMD_Chunk_ID[i:i + 2] for i in range(0, len(CMD_Chunk_ID), 2)]
        # print("CMD_Chunk_ID: " + str(CMD_Chunk_ID))

        CMD_open_pckt.extend(inital_list)       # 3 byte
        Chunk_arr.extend(CMD_Chunk_ID)          # 3 + 2 byte

        set_fw = get_fW_type("MBR")
        # print("SET FW: " + str(set_fw))

        Chunk_arr.extend(set_fw)                # 5 + 2 byte
        # print(str(Chunk_arr))

        file_size = ''.join(f'{file_size:08X}')
        file_size = [file_size[i:i + 2] for i in range(0, len(file_size), 2)]
        # print("File size: " + str(file_size))

        Chunk_arr.extend(file_size)             # 7 + 4 byte
        # print(str(Chunk_arr))
        
        Chunk_arr.extend(genHash)          
        # print("all data: " +str(Chunk_arr))
        
        CMD_open_pckt_len = ''.join(f'{len(Chunk_arr):02X}')
        # print("length: " + str(CMD_open_pckt_len))

        CMD_open_pckt.append(CMD_open_pckt_len)
        # print("CMD_open_pckt: " +str(CMD_open_pckt))

        CMD_open_pckt.extend(Chunk_arr)
        # print("CMD_Open_packet: " + str(CMD_open_pckt))

        crc = make_CRC(CMD_open_pckt, len(CMD_open_pckt))
        crc_str = '{:02X}'.format(crc)
        CMD_open_pckt.append(crc_str)
        print("CMD_Open_packet: " + str(CMD_open_pckt))

    elif (CMD_list_params == CMD_list[1]): # close
        print(str(CMD_list_params))
        # close
        # |  CMD  | Chunk ID |
        # |  4bit | 12bit    |
        Chunk_ID = 0
        CMD_close_pckt = []

        CMD_close_pckt.extend(inital_list)
        # print("inital_list: " + str(inital_list))

        CMD_Chunk_ID = ( (Chunk_ID << 4) & 0xfff0) | (CMD_Close & 0x0f)
        # CMD_Chunk_ID_hex = CMD_Chunk_ID.to_bytes(2, 'big')
        CMD_Chunk_ID = ''.join(f'{CMD_Chunk_ID:04X}')
        CMD_Chunk_ID = [CMD_Chunk_ID[i:i + 2] for i in range(0, len(CMD_Chunk_ID), 2)]

        # print("Chunk + CMD: " + str(CMD_Chunk_ID))

        close_pckt_len = ''.join(f'{len(CMD_Chunk_ID):02X}')

        CMD_close_pckt.append(close_pckt_len)
        CMD_close_pckt.extend(CMD_Chunk_ID)


        # print("CMD_Close_packet: " + str(CMD_close_pckt))

        crc = make_CRC(CMD_close_pckt, len(CMD_close_pckt))
        crc_str = '{:02X}'.format(crc)
        # print("crc: " + crc_str)
        CMD_close_pckt.append(crc_str)
        print("CMD_Close_packet: " + str(CMD_close_pckt))

    elif (CMD_list_params == CMD_list[2]): # ack
        print(str(CMD_list_params))
        # Ack
        # |  CMD  | Chunk ID | Command | Status |
        # |  4bit | 12bit    | 1byte   | 1byte  |
        CMD_ack_packet = []

    elif (CMD_list_params == CMD_list[3]): # Busy
        print(str(CMD_list_params))
        # Busy
        # |  CMD  | Chunk ID |
        # |  4bit | 12bit    |
        CMD_busy_packet = []

    elif (CMD_list_params == CMD_list[4]): # ready
        print(str(CMD_list_params))
        # Ready
        # |  CMD  | Chunk ID |
        # |  4bit | 12bit    |
        CMD_ready_packet = []

    elif (CMD_list_params == CMD_list[5]): # Chunk
        print(str(CMD_list_params))
        # Chunk
        # |  CMD  | Chunk ID | Chunk data |
        # |  4bit | 12bit    | N-2        |
        
        start_index = 0
        end_index   = 240
        Chunk_ID    = 1

        CMD_chunk_pckt = []

        print("file size: " + str(file_size) )

        binary_data_arr = [binary_data[i:i + 2] for i in range(0, len(binary_data), 2)]
        print("Seperated data: " + str(binary_data_arr))
        print("Length of seperated data: " + str(len(binary_data_arr)))
        print("Seperated data index 0: " + str(binary_data_arr[0]))

        while start_index < len(binary_data_arr):
            print("into index loop")
            CMD_chunk_pckt.extend(inital_list)                          # 3 bytes
            # print("Chunk_packet ID: " + str(Chunk_packet))           
            chunk_arr = binary_data_arr[start_index:end_index]      # 240 bytes
            # print("chunk_arr: " + str(chunk_arr))

            chunk_packet_len = ''.join(f'{len(chunk_arr):02X}')
            # print("packet length: " + str(chunk_packet_len))
            CMD_chunk_pckt.append(chunk_packet_len) 

            CMD_chunk_pckt.extend(chunk_arr)                            # 243 bytes
            # print("Chunk_packet: " + str(Chunk_packet))

            crc = make_CRC(CMD_chunk_pckt, len(CMD_chunk_pckt))
            crc_str = '{:02X}'.format(crc)
            # print("CRC: " + str(crc_str))
            CMD_chunk_pckt.append(crc_str)
            # print("Chunk_packet: " + str(CMD_chunk_pckt))

            start_index = start_index + 240
            end_index   = end_index + 240
            Chunk_ID    = Chunk_ID + 1

            chunk_arr.clear()
            CMD_chunk_pckt.clear()

    elif (CMD_list_params == CMD_list[6]): # validation
        print(str(CMD_list_params))
        # Validation
        # |  CMD  | Chunk ID |
        # |  4bit | 12bit    |

if __name__ == "__main__":

    file_name = 'mbr.bin'
    file_split(file_name)

    genHash = gen_hash(file_name)

    # CMD_packet("Close")
    # CMD_packet("Chunk")
    CMD_packet("Open")

    print("\n*************END***************")

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