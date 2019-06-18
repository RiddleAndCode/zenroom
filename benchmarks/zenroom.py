import ctypes
import os.path
import sys

__MAX_STRING__ = 1048576

_python_version = '.'.join(map(str, sys.version_info[:3]))
_zenroom_so = os.path.join(
    os.path.dirname(__file__),
    "..",
    "build",
    "python3",
    "_zenroom_%s.so" % _python_version
)
if not os.path.isfile(_zenroom_so):
    _zenroom_so = os.path.join(
        os.path.dirname(__file__),
        "..",
        "build",
        "python3",
        "_zenroom.so"
    )
_zenroom = ctypes.CDLL(_zenroom_so)


def _exec(func, script, keys, data, conf, verbosity):
    stdout_buf = ctypes.create_string_buffer(b"\000", __MAX_STRING__)
    stdout_len = ctypes.c_size_t(__MAX_STRING__)
    stderr_buf = ctypes.create_string_buffer(b"\000", __MAX_STRING__)
    stderr_len = ctypes.c_size_t(__MAX_STRING__)

    script = script.encode() if isinstance(script, str) else script
    conf = conf.encode() if isinstance(conf, str) else conf
    keys = keys.encode() if isinstance(keys, str) else keys
    data = data.encode() if isinstance(data, str) else data

    func(
        script,
        conf,
        keys,
        data,
        verbosity,
        ctypes.byref(stdout_buf),
        stdout_len,
        ctypes.byref(stderr_buf),
        stderr_len
    )
    return stdout_buf.value, stderr_buf.value


def zencode(script, keys=None, data=None, conf=None, verbosity=1):
    return _exec(
        _zenroom.zencode_exec_to_buf,
        script,
        keys,
        data,
        conf,
        verbosity
    )


def execute(script, keys=None, data=None, conf=None, verbosity=1):
    return _exec(
        _zenroom.zenroom_exec_tobuf,
        script,
        keys,
        data,
        conf,
        verbosity
    )
