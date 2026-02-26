import base64,hmac,hashlib

class YoyoRequestSigner:
    def __init__(self,yoyo_type: str):
        encryp_keys = {
                # find yourself :)
            }
        self.privateKey = encryp_keys[yoyo_type]["private"]
        self.publicKey = encryp_keys[yoyo_type]["public"]
        self.interestingHeaders=["Content-Length","Content-MD5","Content-Type","Date","Yoyo-Token"]
        pass
    
    def signString(self, stringToSign):
        try:
            key_bytes = self.privateKey.encode('utf-8')
            str_bytes = stringToSign.encode('utf-8')
            
            hmac_sha1_hash = hmac.new(key_bytes, str_bytes, hashlib.sha1).digest()
            
            encoded_hash = base64.b64encode(hmac_sha1_hash).decode('utf-8')
            
            return encoded_hash
        except Exception as e:
            print(f"Failed to generate HMAC: {e}")
            return None
        
    def getSignedRequestString(self, httpMethod, headers):
        stringToSign = self.createStringToSign(httpMethod,headers)
        signedString = self.signString(stringToSign)
        return signedString
    
    def createStringToSign(self, httpMethod, headers: dict):
        httpMethod = httpMethod.upper()
        stringToSign = httpMethod
        
        for i in self.interestingHeaders:
            value = headers.get(i,None)
            
            if value is None:
                value = ""
                
            stringToSign+=f"\n{value}"

        return stringToSign
        
    def getSignedHeaders(self, httpMethod, headers):
        signedRequestString = self.getSignedRequestString(httpMethod,headers)
        return "Yoyo " + self.publicKey + ":" + signedRequestString
    
    def sign(self, httpMethod, headers: dict):
        authToken = self.getSignedHeaders(httpMethod,headers)
        headers.update({"Authorization":authToken})
        return headers