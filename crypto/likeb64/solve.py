import base64


def solve():
    # The ciphertext from target.txt
    encoded_str = "IREHWYJZMEcGCODGMMbTENDDGcbGEMJZGEbGEZTFGYaGKNRTMIcGIMBSGRQTSNDDGAaWGYZRHEbGCNRQMUaDOMbEMRTGEYJYGUaWGOJQMYZHa==="

    # The custom alphabet provided in the hint
    custom_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"

    # Standard Base32 alphabet (RFC 4648)
    standard_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    # Create a translation table to map custom characters to standard Base32 characters
    trans_table = str.maketrans(custom_alphabet, standard_alphabet)

    # Translate the encoded string
    # Note: The padding '=' remains the same
    translated_str = encoded_str.translate(trans_table)

    try:
        # Decode using standard Base32
        decoded_bytes = base64.b32decode(translated_str)
        print(f"Flag: {decoded_bytes.decode('utf-8')}")
    except Exception as e:
        print(f"Error decoding: {e}")


if __name__ == "__main__":
    solve()
