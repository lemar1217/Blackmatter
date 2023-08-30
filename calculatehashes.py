#These two functions, `calc_mod_hash` and `calc_func_hash`, are custom hashing algorithms designed for quick data lookup and identification of module and function names, respectively. 
#They are not cryptographic hash functions and shouldn't be used for secure data hashing


def calc_mod_hash(modname):
    mask = 0xFFFFFFFF
    h = 0
    for c in modname + "\x00":
	cc = ord(c)
	if (0x40 < cc and cc < 0x5b):
	    cc = (cc | 0x20) & mask
	h = (h >> 0xd) | (h << 0x13)
	h = (h + cc) & mask

    return h


def calc_func_hash(modhash, funcname):
    mask = 0xFFFFFFFF
    h = modhash
    for c in funcname + "\x00":
	cc = ord(c)
	h = (h >> 0xd) | (h << 0x13)
	h = (h + cc) & mask

    return h



