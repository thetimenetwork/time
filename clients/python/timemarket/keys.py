"""Where a script gets its signing key from: only from where you tell it to look, by a call you write.

A signing key is its seed: 32 bytes, written as 64 lowercase hexadecimal characters. Whoever reads it
can spend what the account holds, up to the account's daily limit if it has one. So:

- This package never looks for a key by itself. There is no default file, no default variable and no
  search: a key is read by one of the three functions below, called by you, from the place you name.
- A key is never written in a script, never passed on a command line (other users of the machine can
  read command lines) and never committed to a repository.
- Nothing here prints a key or puts one in an error message. The functions return a ``Seed``, which
  does not show its value when it is printed, logged or shown in a traceback.

The three places: the operating system's key store (``seed_from_key_store``), an environment variable
(``seed_from_env``), a file only its owner can read (``seed_from_file``).
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys

_SEED = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}")
_FORM = "a signing key is 64 lowercase hexadecimal characters (its 32-byte seed)"


class Seed:
    """A signing key, held so that it does not show: printing, logging or formatting it gives no part of it.

    ``wire.sign_action`` and ``wire.public_key`` take it as it is. It cannot be pickled or copied
    into text by accident; ``reveal()`` gives the 32 bytes to code that asks for them by name.
    """

    __slots__ = ("_value",)

    def __init__(self, value: bytes):
        if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
            raise ValueError("A signing key is its seed: 32 bytes")
        object.__setattr__(self, "_value", bytes(value))

    def reveal(self) -> bytes:
        """The 32 bytes of the key. Only signing needs them."""
        return self._value

    def __repr__(self) -> str:
        return "<signing key: not shown>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return repr(self)

    def __setattr__(self, name, value):
        raise AttributeError("A signing key is not changed")

    def __reduce__(self):
        raise TypeError("A signing key is not written out: read it again from where it is kept")


def _seed(text, where: str) -> Seed:
    """The key in ``text``, or a refusal that names ``where`` and never repeats the text."""
    text = text.strip() if isinstance(text, str) else ""
    if not _SEED.fullmatch(text):
        raise ValueError(f"{where} does not hold a signing key: {_FORM}")
    return Seed(bytes.fromhex(text))


def seed_from_env(name: str) -> Seed:
    """The signing key in the environment variable ``name``, which you choose and whatever starts the script sets.

    Raises ``RuntimeError`` if the variable is not set and ``ValueError`` if it does not hold a key.
    The value is never put into a message.
    """
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
        raise ValueError("The name of an environment variable is letters, digits and _")
    value = os.environ.get(name)
    if value is None:
        raise RuntimeError(f"The environment variable {name} is not set: it holds the signing key of the script's account")
    return _seed(value, f"The environment variable {name}")


def seed_from_file(path) -> Seed:
    """The signing key in the file ``path``, which you name: one line of 64 lowercase hexadecimal characters.

    Where the system has file modes (Linux, macOS), the file must be a regular file that only its
    owner can read or write (``chmod 600``): a file that its group or anyone else can read is refused,
    so that a key does not stay readable by accident. On Windows there are no such modes and nothing
    is checked: use the key store there (``seed_from_key_store``).
    """
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{path} is not a regular file")
    if os.name == "posix" and info.st_mode & 0o077:
        raise PermissionError(
            f"{path} can be read or written by others (mode {stat.S_IMODE(info.st_mode):o}): run chmod 600 on it, and treat the key as seen if others use this machine"
        )
    if info.st_size > 4096:
        raise ValueError(f"{path} does not hold a signing key: {_FORM}")
    with open(path, "r", encoding="ascii", errors="replace") as file:
        return _seed(file.read(), str(path))


def _windows_credential(target: str) -> tuple[str, str]:
    """(user name, secret) of the generic credential ``target`` in the Windows Credential Manager."""
    import ctypes
    from ctypes import wintypes

    class Credential(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(Credential))]
    library.CredReadW.restype = wintypes.BOOL
    library.CredFree.argtypes = [ctypes.c_void_p]
    library.CredFree.restype = None
    found = ctypes.POINTER(Credential)()
    if not library.CredReadW(target, 1, 0, ctypes.byref(found)):  # 1: a generic credential
        raise LookupError(f"Windows error {ctypes.get_last_error()}")
    try:
        blob = ctypes.string_at(found.contents.CredentialBlob, found.contents.CredentialBlobSize)
        return found.contents.UserName or "", blob.decode("utf-16-le", errors="replace")
    finally:
        library.CredFree(found)


def seed_from_key_store(service: str, account: str) -> Seed:
    """The signing key that the operating system's key store keeps under ``service`` and ``account``.

    The key store keeps the key encrypted under your login and gives it to programs you run. You put
    the key there yourself, once (the README says how), under names you choose; this function reads
    it and never writes.

    - macOS: the login keychain, read with ``security find-generic-password -s <service> -a <account> -w``.
    - Linux: the Secret Service (GNOME Keyring, KWallet), read with ``secret-tool lookup service <service> account <account>``.
    - Windows: the Credential Manager, a generic credential whose address is ``service`` and whose
      user name is ``account``.

    Raises ``RuntimeError`` if the system has no key store this function can read or the entry is not
    there, and ``ValueError`` if the entry does not hold a key. What the key store answered is never
    put into a message.
    """
    for name, value in (("service", service), ("account", account)):
        if not isinstance(value, str) or not _NAME.fullmatch(value):
            raise ValueError(f"{name} is a name of letters, digits and . _ @ - that begins with a letter or a digit")
    where = f"The key store entry {service} / {account}"
    if sys.platform == "win32":
        try:
            user, secret = _windows_credential(service)
        except (LookupError, OSError):
            raise RuntimeError(f"{where} was not found in the Windows Credential Manager (a generic credential)") from None
        if user != account:
            raise RuntimeError(f"{where} was not found: the credential {service} is for another user name")
        return _seed(secret, where)
    if sys.platform == "darwin":
        tool, command = "/usr/bin/security", ["find-generic-password", "-s", service, "-a", account, "-w"]
    else:
        tool, command = shutil.which("secret-tool"), ["lookup", "service", service, "account", account]
    if not tool or not os.path.isfile(tool):
        raise RuntimeError(
            "This system has no key store this package can read: on Linux install secret-tool (libsecret-tools); or use seed_from_env"
        )
    try:
        answer = subprocess.run([tool, *command], capture_output=True, text=True, timeout=30, check=False, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError(f"{where} could not be read: the key store did not answer") from None
    if answer.returncode != 0 or not answer.stdout.strip():
        raise RuntimeError(f"{where} was not found, or the key store is locked")
    return _seed(answer.stdout, where)
