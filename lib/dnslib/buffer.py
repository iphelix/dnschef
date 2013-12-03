
import struct

class Buffer(object):

    """
    A simple data buffer - supports packing/unpacking in struct format 

    >>> b = Buffer()
    >>> b.pack("!BHI",1,2,3)
    >>> b.offset
    7
    >>> b.append("0123456789")
    >>> b.offset
    17
    >>> b.offset = 0
    >>> b.unpack("!BHI")
    (1, 2, 3)
    >>> b.get(5)
    '01234'
    >>> b.get(5)
    '56789'
    >>> b.update(7,"2s","xx")
    >>> b.offset = 7
    >>> b.get(5)
    'xx234'
    """

    def __init__(self,data=""):
        """
            Initialise Buffer from data
        """
        self.data = data
        self.offset = 0

    def remaining(self):
        """
            Return bytes remaining
        """
        return len(self.data) - self.offset

    def get(self,len):
        """
            Gen len bytes at current offset (& increment offset)
        """
        start = self.offset
        end = self.offset + len
        self.offset += len
        return self.data[start:end]

    def pack(self,fmt,*args):
        """
            Pack data at end of data according to fmt (from struct) & increment
            offset
        """
        self.offset += struct.calcsize(fmt)
        self.data += struct.pack(fmt,*args)

    def append(self,s):
        """
            Append s to end of data & increment offset
        """
        self.offset += len(s)
        self.data += s

    def update(self,ptr,fmt,*args):
        """
            Modify data at offset `ptr` 
        """
        s = struct.pack(fmt,*args)
        self.data = self.data[:ptr] + s + self.data[ptr+len(s):]

    def unpack(self,fmt):
        """
            Unpack data at current offset according to fmt (from struct)
        """
        return struct.unpack(fmt,self.get(struct.calcsize(fmt)))

if __name__ == '__main__':
    import doctest
    doctest.testmod()
