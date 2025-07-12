import socket
import argparse

# ------------------------------
# 1. Encoding / Decoding Helpers
# ------------------------------


def encode_domain(domain):
    parts = domain.split(".")
    encoded = b""
    for part in parts:
        encoded += bytes([len(part)]) + part.encode()
    encoded += b"\x00"
    return encoded


def parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
# If the length byte represents an actual label length (0-63), the two MSBs will be 00.
# If the length byte is part of a pointer for name compression, the two MSBs will be 11 (C0).
        if (length & 0xC0) == 0xC0:
            # Name compression
            if not jumped:
                original_offset = offset + 2
            pointer = ((length & 0x3F) << 8) | data[offset + 1] #This pointer value is an offset from the beginning of the DNS message where the actual, uncompressed form of the domain name (or part of it) can be found.offset is 14 bits for the compression pointer.
            offset = pointer
            jumped = True
        else:
            offset += 1
            labels.append(data[offset : offset + length].decode())
            offset += length

    domain = ".".join(labels)
    return domain, (original_offset if jumped else offset)


# ------------------------------
# 2. DNS Query Parser
# ------------------------------


def parse_dns_query(data):
    transaction_id = data[0:2]
    flags = data[2:4]
    qdcount = int.from_bytes(data[4:6], "big")

    questions = []
    offset = 12

    for _ in range(qdcount):
        domain, offset = parse_name(data, offset)
        qtype = int.from_bytes(data[offset : offset + 2], "big")
        qclass = int.from_bytes(data[offset + 2 : offset + 4], "big")
        questions.append({"domain": domain, "qtype": qtype, "qclass": qclass})
        offset += 4

    return {
        "transaction_id": transaction_id,
        "flags": flags,
        "qdcount": qdcount,
        "questions": questions,
        "query_end": offset,
        "original_query": data,
    }


# ------------------------------
# 3. DNS Builders
# ------------------------------


def build_response_header(parsed_query, ancount):
    transaction_id = parsed_query["transaction_id"]
    flags_raw = int.from_bytes(parsed_query["flags"], "big")

    opcode = (flags_raw >> 11) & 0xF
    rd = (flags_raw >> 8) & 0x1
    rcode = 0 if opcode == 0 else 4

    qr, aa, tc, ra = 1, 0, 0, 1
    flags = (
        (qr << 15)
        | (opcode << 11)
        | (aa << 10)
        | (tc << 9)
        | (rd << 8)
        | (ra << 7)
        | (rcode & 0xF)
    )
    flags_bytes = flags.to_bytes(2, "big")
    qdcount = len(parsed_query["questions"]).to_bytes(2, "big")
    ancount_bytes = ancount.to_bytes(2, "big") if rcode == 0 else (0).to_bytes(2, "big")
    nscount = arcount = (0).to_bytes(2, "big")

    return transaction_id + flags_bytes + qdcount + ancount_bytes + nscount + arcount


def build_question_section(parsed_query):
    q_section = b""
    for q in parsed_query["questions"]:
        q_section += encode_domain(q["domain"])
        q_section += q["qtype"].to_bytes(2, "big")
        q_section += q["qclass"].to_bytes(2, "big")
    return q_section


def build_answer_section(parsed_query, ip="8.8.8.8", ttl=60):
    answers = []
    for q in parsed_query["questions"]:
        if q["qtype"] == 1 and q["qclass"] == 1:  # Only A IN
            name = b"\xc0\x0c"  # Pointer to domain at offset 12
            type_bytes = q["qtype"].to_bytes(2, "big")
            class_bytes = q["qclass"].to_bytes(2, "big")
            ttl_bytes = ttl.to_bytes(4, "big")
            rdata = bytes(map(int, ip.split(".")))#converts ip address n str to bytes
            rdlength = len(rdata).to_bytes(2, "big")
            answers.append(
                name + type_bytes + class_bytes + ttl_bytes + rdlength + rdata
            )
    return b"".join(answers)


# ------------------------------
# 4. Main Server
# ------------------------------


def main():
    print("Starting DNS server on 127.0.0.1:2053")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    parser = argparse.ArgumentParser()
    parser.add_argument("--resolver", nargs="*")
    args = parser.parse_args()

    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)
            parsed = parse_dns_query(data)

            answers = build_answer_section(parsed)
            header = build_response_header(
                parsed, ancount=len(answers) // 16
            )  # Each A record = 16 bytes
            question = build_question_section(parsed)

            print("Preparing the request...")
            resolver_addr, resolver_port = args.resolver[0].split(":")
            resolver_dest = (resolver_addr, int(resolver_port)) #tuple of IP address and port which is used to establish connections in python
            
            print("Sending request....")
            udp_socket.sendto(data,resolver_dest)
            data_from_server, addr_of_server = udp_socket.recvfrom(1024)

            #TODO: understand the reason for below line
            #answers = answers[:-5] + data_from_server[-5:]

            print("Preparing response...")
            response = header + question + answers

            print("Sending response...")
            udp_socket.sendto(response, addr)

            print("Reply has been sent")

        except Exception as e:
            print(f"Error: {e}")
            break


if __name__ == "__main__":
    main()