from reliable_socket import reliable_socket
from utility import get_max_32bit_integer

content = "Based on your input, get a random alpha numeric string. The random string generator creates a series of numbers and letters that have no pattern. These can be helpful for creating security codes.\
With this utility you generate a 16 character output based on your input of numbers and upper and lower case letters.  Random strings can be unique. Used in computing, a random string generator can also be called a random character string generator. This is an important tool if you want to generate a unique set of strings. The utility generates a sequence that lacks a pattern and is random.\
Throughout time, randomness was generated through mechanical devices such as dice, coin flips, and playing cards. A mechanical method of achieving randomness can be more time and resource consuming especially when a large number of randomized strings are needed as they could be in statistical applications.  Computational random string generators replace the traditional mechanical devices. \
Possible applications for a random string generator could be for statistical sampling, simulations, and cryptography.  For security reasons, a random string generator can be useful./" \
          "The generation of this type of random string can be a common or typical task in computer programming.  Some forms of randomness concern hash or seach algorithms.  Another task that is random concerns selecting music tracks."


def sender():
    conn = reliable_socket()
    conn.set_sequence_number(get_max_32bit_integer() - 30)
    conn.connect(("localhost", 9002))
    conn.sendall(content)


sender()
