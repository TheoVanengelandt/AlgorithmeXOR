# code written by theo vanengelandt
# source:
# https://idafchev.github.io/crypto/2017/04/13/crypto_part1.html

import string
import itertools
from unittest import result

possible_key = list(string.ascii_lowercase)

# Open the file, read each lignes and add the result into file
filename = input('Enter a filename: ')
f = open('./files/'+filename, 'r', errors='ignore')
if f.mode == 'r':
    file = f.read().lower()
    f.close()
# print(file)


def xor(str1,  str2):
    if len(str1) != len(str2):
        raise "XOR EXCEPTION: Strings are not of equal length!"

    s1 = bytearray(str1)
    s2 = bytearray(str2)

    result = bytearray()

    for i in range(len(s1)):
        result.append(s1[i] ^ s2[i])

    return str(result)


def single_byte_xor(plaintext, key):
    if len(key) != 1:
        raise "KEY LENGTH EXCEPTION: In single_byte_xor key must be 1 byte long!"

    return xor(plaintext, key*len(plaintext))


# open french dictionary
f = open('./ressources/liste_francais.txt', 'r')
file = f.read().lower()
f.close()

digraphs = []
for digraph in itertools.product(string.ascii_lowercase, repeat=2):
    d = ''.join(digraph)
    if file.count(d) == 0:
        digraphs.append(d)

# print("Digraphs: ", digraphs)


def has_nonprintable_characters(text):
    for char in text:
        if char not in string.printable:
            return True
    return False


def has_vowels(text):
    vowels = list("eyuioa")
    for char in vowels:
        if char in text:
            return True
    return False


def has_forbidden_digraphs(text):
    forbidden_digraphs = ['cj', 'fq', 'gx', 'hx', 'jf', 'jq', 'jx', 'jz', 'qb',
                          'qc', 'qj', 'qk', 'qx', 'qz', 'sx', 'vf', 'vj', 'vq',
                          'vx', 'wx', 'xj', 'zx']
    for digraph in forbidden_digraphs:
        if digraph in text:
            return True
    return False


def has_necessary_percentage_frequent_characters(text, p=38):
    most_frequent_characters = list("etaoin")

    cnt = 0
    for char in most_frequent_characters:
        cnt += text.count(char)

    percent_characters = float(cnt)*100/len(text)

    # The most_frequent_characters shoud be more than 38% of the text.
    # For short messages this value may need to be lowered.
    if (percent_characters < p):
        return False
    return True


def has_french_words(text):
    most_frequent_words = ['le', 'et', 'a', 'ça', 'pour',
                           'toi', 'avec', 'dit', 'cela', 'ils',
                           'mais', 'il', 'de', 'pas',
                           'elle', 'quoi', 'leurs', 'peut',
                           'qui', 'avoir', 'voudrait', 'sa', 'faire',
                           'sur', 'savoir', 'vais', 'un', 'temps',
                           'que', 'dont', 'où', 'ici', 'années', 'pense',
                           'quand', 'ou', 'est', 'donc', 'or', 'ni', 'car',
                           'mais', 'certains', 'personnes', 'prendre', 'dehors',
                           'dedans', 'juste', 'voir', 'lui', 'ton', 'ta',
                           'viens', 'pourrait', 'maintenant', 'plutôt', 'comme',
                           'autre', 'comment', 'alors', 'son', 'sa', 'sort',
                           'deux', 'plus', 'ceux-ci', 'veut', 'chemin',
                           'regarde', 'premièrement', 'aussi', 'nouveau',
                           'à cause', 'jour', 'moins', 'utiliser', 'homme',
                           'trouver', 'là', 'chose', 'donner', 'plusieurs']

    for word in most_frequent_words:
        if word in text:
            return True
    return False


def is_french(input_text):
    text = input_text.lower()

    if has_nonprintable_characters(text):
        return False

    # If the text contains one of the most frequent french words
    # it is very likely that it's an french text
    if has_french_words(text):
        return True

    if not has_vowels(text):
        return False

    if has_forbidden_digraphs(text):
        return False

    if not has_necessary_percentage_frequent_characters(text):
        return False

    return True


def break_single_byte_xor(ciphertext):
    keys = []
    plaintext = []

    for key in range(256):
        text = single_byte_xor(ciphertext, chr(key))
        if is_french(text):
            keys.append(chr(key))
            plaintext.append(text)

    # There might be more than one string that match the rules of the is_french function.
    # Return all those strings and their corresponding keys and inspect visually to
    # determine which is the correct plaintext.
    return keys, plaintext


msg = 'Cela est un message secret!'
key = '\x0f'
ciphertext = single_byte_xor(msg, key)

k, pt = break_single_byte_xor(ciphertext)
print("Keys: ", k)
print("Plaintexts: ", pt)
