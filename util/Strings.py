import re
class Strings():
    def __init__(self, str):
        self.str = str
    
    def contains(self, j) -> bool:
        try:
            a = re.findall(j, self.str)
            if len(a) != 0:
                return True
            return False
        except:
            return False
        
    def icontains(self, j) -> bool:
        try:
            a = re.findall(j, self.str, flags=re.IGNORECASE)
            if len(a) != 0:
                return True
            return False
        except:
            return False
        
    def startsWith(self, i) -> bool:
        try:
            return self.str.startswith(i)
        except:
            return False
        
    def endsWith(self, i) -> bool:
        try:
            return self.str.endswith(i)
        except:
            return False
    
if __name__ == '__main__':
    a = Strings('1A23')
    print(a.substr(2,1))