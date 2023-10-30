# Ghidra Python Script for Decrypting/Encrypting a uint using applyXORandNOT function , this sample of this ransom has this algo of how the decrypt the strings dynamically

def applyXORandNOTToUInt(data):
    # XOR the value with 0x10035fff
    data = data ^ 0x10035fff
    # Apply bitwise NOT operation to invert all the bits
    data = ~data
    # Mask out to only 32-bits to simulate uint
    data &= 0xFFFFFFFF
    return data

# Example
encrypted_uint = 0xef90a045  # Your encrypted uint( as an example you can put the encrypted strings  there)
decrypted_uint = applyXORandNOTToUInt(encrypted_uint)
print("Decrypted UInt:", hex(decrypted_uint))





