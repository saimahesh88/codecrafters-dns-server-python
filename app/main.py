import socket

class dns_message():
    
    def __init__(self):
        self.headermsg = b""
        pass
    
    def header(self):
        packet_id_ID = 1234
        query_indicator_QR = 1
        opcode_OPCODE = 0
        authoritative_answer_AA = 0
        truncation_TC = 0
        recursion_desired_RD = 0
        recursion_available_RA = 0
        reserved_Z = 0
        response_code_RCODE = 0
        question_count_QDCOUNT = 0
        answer_record_count_ANCOUNT = 0
        authority_record_count_NSCOUNT = 0
        additional_record_count_ARCOUNT = 0

        flags = (
            (query_indicator_QR << 15)
            | (opcode_OPCODE << 11)
            | (authoritative_answer_AA << 10)
            | (truncation_TC << 9)
            | (recursion_desired_RD << 8)
            | (recursion_available_RA << 7)
            | (reserved_Z << 4)
            | (response_code_RCODE)
        )

        headermsg = (
            (packet_id_ID << 80)
            | (flags << 64)
            | (question_count_QDCOUNT << 48)
            | (answer_record_count_ANCOUNT << 32)
            | (authority_record_count_NSCOUNT << 16)
            | additional_record_count_ARCOUNT
        )

        self.headermsg = headermsg.to_bytes(12, byteorder="big") # big-endian format
    
    def fullmsg(self):
        self.header()
        fullmsg = self.headermsg
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
    
            response = dns_message().fullmsg()
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
