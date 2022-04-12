import re
class Bytes():
    def __init__(self, byte):
        self.byte = byte

    def bcontains(self, b) -> bool:
        try:
            a = re.findall(b.decode(), self.byte.decode())
            if len(a) != 0:
                return True
            return False
        except Exception:
            return False

    def bicontains(self, b) -> bool:
        try:
            a = re.findall(b.decode(), self.byte.decode(), flags=re.IGNORECASE)
            if len(a) != 0:
                return True
            return False
        except Exception:
            return False
        
    def bstartsWith(self, b) -> bool:
        try:
            if self.byte.decode().startswith(b.decode()):
                return True
            else:
                return False
        except:
            return False

if __name__ == '__main__':
    a = Bytes(b'abc')
    #print(bytes('abc'))
    print(a.bstartsWith(b'ab'))