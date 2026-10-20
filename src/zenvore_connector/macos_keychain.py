"""Login Keychain access through Security.framework; no secrets in process arguments."""
import ctypes
from ctypes import POINTER, byref, c_int32, c_uint32, c_void_p
import hashlib

SERVICE = b"com.zenvore.biometricconnector"
NOT_FOUND = -25300
DUPLICATE = -25299


def account_for(directory, filename):
    # Distinct state directories and installation/device credentials cannot collide.
    return hashlib.sha256((str(directory.resolve()) + "\0" + filename).encode()).hexdigest().encode()


class Keychain:
    def __init__(self):
        self.security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        self.core = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.find = self.security.SecKeychainFindGenericPassword
        self.find.argtypes = [c_void_p, c_uint32, c_void_p, c_uint32, c_void_p,
                              POINTER(c_uint32), POINTER(c_void_p), POINTER(c_void_p)]
        self.find.restype = c_int32
        self.add = self.security.SecKeychainAddGenericPassword
        self.add.argtypes = [c_void_p, c_uint32, c_void_p, c_uint32, c_void_p,
                             c_uint32, c_void_p, POINTER(c_void_p)]
        self.add.restype = c_int32
        self.modify = self.security.SecKeychainItemModifyAttributesAndData
        self.modify.argtypes = [c_void_p, c_void_p, c_uint32, c_void_p]
        self.modify.restype = c_int32
        self.free = self.security.SecKeychainItemFreeContent
        self.free.argtypes = [c_void_p, c_void_p]
        self.free.restype = c_int32
        self.core.CFRelease.argtypes = [c_void_p]
        self.core.CFRelease.restype = None

    @staticmethod
    def check(status):
        if status:
            raise RuntimeError("macOS Keychain unavailable (status " + str(status) + ")")

    def load(self, account):
        size, data = c_uint32(), c_void_p()
        status = self.find(None, len(SERVICE), SERVICE, len(account), account,
                           byref(size), byref(data), None)
        if status == NOT_FOUND:
            return None
        self.check(status)
        try:
            return ctypes.string_at(data, size.value)
        finally:
            self.free(None, data)

    def save(self, account, data):
        status = self.add(None, len(SERVICE), SERVICE, len(account), account, len(data), data, None)
        if status != DUPLICATE:
            self.check(status)
            return
        item = c_void_p()
        self.check(self.find(None, len(SERVICE), SERVICE, len(account), account, None, None, byref(item)))
        try:
            self.check(self.modify(item, None, len(data), data))
        finally:
            self.core.CFRelease(item)
