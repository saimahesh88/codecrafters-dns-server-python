import socket

class header():

    def __init__(self,
        packet_id_ID,
        query_indicator_QR,
        opcode_OPCODE,
        authoritative_answer_AA,
        truncation_TC,
        recursion_desired_RD,
        recursion_available_RA,
        reserved_Z,
        response_code_RCODE,
        question_count_QDCOUNT,
        answer_record_count_ANCOUNT,
        authority_record_count_NSCOUNT,
        additional_record_count_ARCOUNT):

        self.packet_id_ID = packet_id_ID
        self.query_indicator_QR = query_indicator_QR
        self.opcode_OPCODE = opcode_OPCODE
        self.authoritative_answer_AA = authoritative_answer_AA
        self.truncation_TC = truncation_TC
        self.recursion_desired_RD = recursion_desired_RD
        self.recursion_available_RA = recursion_available_RA
        self.reserved_Z = reserved_Z
        self.response_code_RCODE = response_code_RCODE
        self.question_count_QDCOUNT = question_count_QDCOUNT
        self.answer_record_count_ANCOUNT = answer_record_count_ANCOUNT
        self.authority_record_count_NSCOUNT = authority_record_count_NSCOUNT
        self.additional_record_count_ARCOUNT = additional_record_count_ARCOUNT
    
    def write_header(self):
        flags = (
            (self.query_indicator_QR << 15)
            | (self.opcode_OPCODE << 11)
            | (self.authoritative_answer_AA << 10)
            | (self.truncation_TC << 9)
            | (self.recursion_desired_RD << 8)
            | (self.recursion_available_RA << 7)
            | (self.reserved_Z << 4)
            | (self.response_code_RCODE)
        )

        headermsg = (
            (self.packet_id_ID << 80)
            | (flags << 64)
            | (self.question_count_QDCOUNT << 48)
            | (self.answer_record_count_ANCOUNT << 32)
            | (self.authority_record_count_NSCOUNT << 16)
            | self.additional_record_count_ARCOUNT
        )

        return headermsg.to_bytes(12, byteorder="big") # big-endian format
    
    def question(self):
        name_QNAME_label_1 = "codecrafters"
        name_QNAME_label_2 = "io"
        type_QTYPE = 1
        class_QCLASS = 1

        question_msg = (
            len(name_QNAME_label_1).to_bytes(length=1, byteorder="big") + name_QNAME_label_1.encode() +
            len(name_QNAME_label_2).to_bytes(length=1, byteorder="big") + name_QNAME_label_2.encode() + 
            b"\x00" + type_QTYPE.to_bytes(2,byteorder="big")+
            class_QCLASS.to_bytes(2,byteorder="big")
        )

        return question_msg


    def answer(self):
        name_NAME_label_1 = "codecrafters"
        name_NAME_label_2 = "io"
        type_TYPE = 1
        class_CLASS = 1
        ttl_TTL = 60
        length_RDLENGTH = 4
        data_RDATA = b"\x08"+b"\x08"+b"\x08"+b"\x08"

        answer = (
            len(name_NAME_label_1).to_bytes(length=1, byteorder="big") + name_NAME_label_1.encode() +
            len(name_NAME_label_2).to_bytes(length=1, byteorder="big") + name_NAME_label_2.encode() + 
            b"\x00" + type_TYPE.to_bytes(2,byteorder="big")+
            class_CLASS.to_bytes(2,byteorder="big") + 
            ttl_TTL.to_bytes(4,byteorder="big") +
            length_RDLENGTH.to_bytes(2,byteorder="big") +
            data_RDATA
        ) 
        return answer


    def fullmsg(self):
        headermsg=self.write_header()
        fullmsg = headermsg + self.question() + self.answer()
        return fullmsg 




def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment this block to pass the first stage
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            print(buf)
            packet_id_ID_byte = buf[0:2]
            packet_id_ID = int.from_bytes(packet_id_ID_byte, byteorder='big')
            packet_flags_byte = buf[2:4]
            packet_flags = int.from_bytes(packet_flags_byte,byteorder="big")
            opcode = (packet_flags >> 11) & (0xF) # returns decimal
            recursion_desired_RD = (packet_flags >> 8) & 1
            #question_count_QDCOUNT_byte = buf[4:6]
            question_count_QDCOUNT = 1#int.from_bytes(question_count_QDCOUNT_byte, byteorder='big')
            #print(question_count_QDCOUNT)
            #answer_record_count_ANCOUNT_byte = buf[6:8]
            answer_record_count_ANCOUNT = 1#int.from_bytes(answer_record_count_ANCOUNT_byte,byteorder="big")
            #print(answer_record_count_ANCOUNT)
            #authority_record_count_NSCOUNT_byte = buf[8:10]
            authority_record_count_NSCOUNT = 1#int.from_bytes(authority_record_count_NSCOUNT_byte,byteorder="big")
            #additional_record_count_ARCOUNT_byte = buf[10:-1]
            additional_record_count_ARCOUNT = 1 #int.from_bytes(answer_record_count_ANCOUNT_byte,byteorder="big")
            response = header(packet_id_ID,1,opcode,0,0,recursion_desired_RD,0,0,0 if opcode==0 else 4,question_count_QDCOUNT,answer_record_count_ANCOUNT,authority_record_count_NSCOUNT,additional_record_count_ARCOUNT).fullmsg()
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
