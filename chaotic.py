import random
import math
from bitstring import BitArray

def initialize_chaotic_variables():
    x0 = random.uniform(0.0, 1.0)
    r = random.uniform(0.0, 1.0)
    return x0, r

def chaotic_map(x0: float, r: float, n_iterations=100) -> list:
    x = [x0]
    for i in range(n_iterations):
        if 0.0 < x[i] < 0.5:
            x.append((4 * math.sin(2 * math.pi * x[i] * r) + x[i]) % 1)
        elif 0.5 <= x[i] < 1.0:
            x.append((4 * math.sin(2 * math.pi * x[i] * r) + (1 - x[i])) % 1)
    return x

def float_to_binary(nums: list) -> list:
    binary_strings = []
    for i in range(len(nums)):
        binary_strings.append(BitArray(float=nums[i], length=32).bin)
    return binary_strings

def concatenate_least_bits(binary_strings: list, key_size: int = 128) -> str:
    S = len(binary_strings)       # Number of binary strings
    N = len(binary_strings[0])    # Length of each binary string (32 bits)
    L = math.ceil(key_size / S)   # Bits to extract from each string

    extracted_bits = "".join(bin_str[-L:] for bin_str in binary_strings)

    if len(extracted_bits) > key_size:
        key = extracted_bits[:key_size]
    else:
        key = extracted_bits.ljust(key_size, '0')

    return key

def key_generation(algorithm: str = "chaotic_map", key_size: int= 128):
    match algorithm:
        case "chaotic_map":
            x0, r = initialize_chaotic_variables()
            n = random.randint(10, 1000)  # Number of iterations
            x_nums = chaotic_map(x0=x0, r=r, n_iterations=n)
            binary_strings = float_to_binary(x_nums)
            key = concatenate_least_bits(binary_strings, key_size)

            return key

def main():
    binary_key = key_generation()
    print("Generated Binary Key:", binary_key)

if __name__ == "__main__":
    main()