import os
import win32file


# ### IOCTL defs


FILE_DEVICE_UNKNOWN = 0x00000022
FILE_ANY_ACCESS = 0


# noinspection PyPep8Naming
def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method


METHOD_BUFFERED = 0
METHOD_IN_DIRECT = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER = 3


# noinspection PyPep8Naming
def TAP_CONTROL_CODE(request, method):
    return CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)


TAP_IOCTL_GET_MAC = TAP_CONTROL_CODE(1, METHOD_BUFFERED)
TAP_IOCTL_SET_MEDIA_STATUS = TAP_CONTROL_CODE (6, METHOD_BUFFERED)


# ### TAP methods


def tap_open_adapter(dev_name):
    filename = "\\\\.\\Global\\%s.tap" % dev_name
    # handle = open(filename, "r+b")
    handle = win32file.CreateFile(filename,
                                  win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                  win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                                  None, win32file.OPEN_EXISTING,
                                  win32file.FILE_ATTRIBUTE_SYSTEM,  # | win32file.FILE_FLAG_OVERLAPPED,
                                  None)
    win32file.DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS, "\x01\x00\x00\x00", 4)
    return handle


def tap_get_mac(handle):
    return win32file.DeviceIoControl(handle, TAP_IOCTL_GET_MAC, "\x00\x00\x00\x00\x00\x00", 6)


class TAPException(Exception):
    pass


class TAPReadException(TAPException):
    pass


def tap_read_packet(handle):
    l, p = win32file.ReadFile(handle, 2000)
    if l:
        raise TAPReadException("Error %d while reading" % l)
    return p


def tap_write_packet(handle, packet):
    return win32file.WriteFile(handle, packet)


def tap_close(handle):
    win32file.CloseHandle(handle)
