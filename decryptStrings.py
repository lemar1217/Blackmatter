# Ghidra Python Script for Decrypting/Encrypting a uint using applyXORandNOT function , this sample of this ransom has this algo of how the decrypt the strings dynamically

def applyXORandNOTToUInt(data):
    # XOR the value with  the key = 0x10035fff
    data = data ^ 0x10035fff
    # Apply bitwise NOT operation to invert all the bits
    data = ~data
    # Mask out to only 32-bits to simulate uint
    data &= 0xFFFFFFFF
    return data

# Example
encrypted_uint_str = askString("Enter encrypted uint", "Enter the encrypted 32-bit hexadecimal value:")
encrypted_uint = int(encrypted_uint_str, 16)
decrypted_uint = applyXORandNOTToUInt(encrypted_uint)
print("Decrypted UInt:", hex(decrypted_uint))





