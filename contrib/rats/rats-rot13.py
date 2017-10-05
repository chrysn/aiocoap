import string
source = string.ascii_lowercase + string.ascii_uppercase
dest = string.ascii_lowercase[13:] + string.ascii_lowercase[:13] + string.ascii_uppercase[13:] + string.ascii_uppercase[:13]
replacement = dict(zip(map(ord, source), map(ord, dest)))

@rats.pure
def rotated(original: str) -> str:
    return original.translate(replacement)
