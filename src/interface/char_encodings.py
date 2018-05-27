


#
#                master encoding helper
# -----------------------------------------------
# unified all encoding settings for all modules
#
#


# -- from python's .encode at https://docs.python.org/3/howto/unicode.html
# The errors argument specifies the response when the input string can’t be
# converted according to the encoding’s rules.
# Legal values for this argument are:
# 'strict' (raise a UnicodeDecodeError exception),
# 'replace' (use U+FFFD, REPLACEMENT CHARACTER),
# 'ignore' (just leave the character out of the Unicode result),
# 'backslashreplace' (inserts a \xNN escape sequence).


def decode_to_str(text, encoding='utf-8', errors='replace'):
    return text.decode(encoding=encoding, errors=errors)