import struct

class MemoryAbstractor(object):
    def __init__(self, memory_dump_file, base_offset = 0x0):
        self.memory = open(memory_dump_file, mode='rb')
        self.base_offset = base_offset

    def read_at_offset(self, offset, size):
        self.memory.seek(self.base_offset + offset, 0)
        return self.memory.read(size)

class RawMemoryAbstractor(MemoryAbstractor):
    def __init__(self, memory_dump_file):
        MemoryAbstractor.__init__(self, memory_dump_file, 0x0)

class VMCBAbstractor(MemoryAbstractor):
    def __init__(self, memory_dump_file, base_offset):
        MemoryAbstractor.__init__(self, memory_dump_file, base_offset)

    def get_field(self, field):
        offset, size = field
        raw = super(VMCBAbstractor, self).read_at_offset(offset, size)
        if size == 1:
            return struct.unpack('<B', raw)[0]
        elif size == 2:
            return struct.unpack('<H', raw)[0]
        elif size == 4:
            return struct.unpack('<I', raw)[0]
        elif size == 8:
            return struct.unpack('<Q', raw)[0]
        return None
