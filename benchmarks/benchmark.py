import os.path
import zenroom
import json


def import_script(name):
    filename = os.path.join(
        os.path.dirname(__file__),
        "contracts",
        "%s.lua" % name
    )
    file = open(filename, 'r')
    res = file.read()
    file.close()
    return res


GENKEY = import_script("genkey")
SIGN = import_script("sign")
VERIFY = import_script("verify")

def parse_output(output):
    return json.loads(output.decode('utf-8'))

def genkey():
    output, _ = zenroom.execute(GENKEY)
    return parse_output(output)


def sign(keys, message):
    output, _ = zenroom.execute(
        SIGN,
        json.dumps(keys),
        json.dumps({"message": message})
    )
    out = parse_output(output)
    return out['r'], out['s']


def verify(keys, r, s, message):
    output, errors = zenroom.execute(
        VERIFY,
        json.dumps(keys),
        json.dumps({
            "message": message,
            "r": r,
            "s": s,
        })
    )
    return parse_output(output)['verified']


message = "This is a message"
keys = genkey()
r, s = sign(keys, message)
assert(verify(keys, r, s, message))


if __name__ == "__main__":
    import timeit

    genkey_ms = timeit.timeit(
        "genkey()",
        setup="from __main__ import genkey",
        number=1000
    )
    print("Gen Keys: %f ms" % genkey_ms)

    sign_ms = timeit.timeit(
        "sign(keys, message)",
        setup="from __main__ import keys, message, sign",
        number=1000
    )
    print("Sign message: %f ms" % sign_ms)

    verify_ms = timeit.timeit(
        "verify(keys, r, s, message)",
        setup="from __main__ import r, s, keys, message, verify",
        number=1000
    )
    print("Verify message: %f ms" % verify_ms)
