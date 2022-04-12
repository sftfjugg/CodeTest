import urllib.parse

class UrlType():
    def __init__(self, url):
        self.url = urllib.parse.urlparse(url)
    
    @property
    def scheme(self):
        return self.url.scheme
    
    @property
    def domain(self):
        try:
            return self.url.netloc.split(':')[0]
        except:
            return self.url.netloc
    
    @property
    def host(self):
        return self.url.netloc
    
    @property
    def port(self):
        try:
            return self.url.netloc.split(':')[1]
        except:
            return '8080'
    
    @property
    def path(self):
        return self.url.path
    
    @property
    def query(self):
        return self.url.query
    
    @property
    def fragment(self):
        return self.url.fragment