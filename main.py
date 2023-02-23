from Crypto.Cipher import DES3
from fastapi import FastAPI, Header
from pydantic import BaseModel
from typing import Union
import base64

class Request(BaseModel):
    accountid: str
    amount: str
    authmodel: str
    bvn: Union[str, None] = None
    cardname: Union[str, None] = None
    cardno: str
    cardphonenumber: str
    cardphonetype: Union[str, None] = None
    cardzip: Union[str, None] = None
    chargetoken: str
    country: str
    currency: str
    cvv: str
    email: str
    expirymonth: str
    expiryyear: str
    institution: Union[str, None] = None
    institutionid: Union[str, None] = None
    mcc: str
    merchantaddress: str
    merchantid: str
    merchantname: str
    mpgsmid: str
    password: Union[str, None] = None
    pin: str
    publictoken: str
    pwcMerchantId: str
    responseurl: str
    transactionreference: str
    trxreference: str
    vpcmerchant: str
    vpcrouting: str

class EncryptedResponse(BaseModel):
    accountid: str
    amount: str
    authmodel: str
    bvn: Union[str, None] = None
    cardname: Union[str, None] = None
    cardno: str
    cardphonenumber: str
    cardphonetype: Union[str, None] = None
    cardzip: Union[str, None] = None
    chargetoken: str
    country: str
    currency: str
    cvv: str
    email: str
    expirymonth: str
    expiryyear: str
    institution: Union[str, None] = None
    institutionid: Union[str, None] = None
    mcc: str
    merchantaddress: str
    merchantid: str
    merchantname: str
    mpgsmid: str
    password: Union[str, None] = None
    pin: str
    publictoken: str
    pwcMerchantId: str
    responseurl: str
    transactionreference: str
    trxreference: str
    vpcmerchant: str
    vpcrouting: str

app = FastAPI()

IntegerValueKeyArray = [
    "accountid",
    "amount",
    "cardno",
    "cardphonenumber",
    "chargetoken",
    "cvv",
    "expirymonth",
    "expiryyear",
    "mcc",
    "pin",
    "pwcMerchantId",
    "bvn",
    "cardzip",
    "vpcrouting"
]

def encrypt_data(key, value):
    
    blockSize = 8
    padDiff = blockSize - (len(value) % blockSize)
    
    cipher = DES3.new(key, DES3.MODE_ECB)
    
    value = "{}{}".format(value, "".join(chr(padDiff) * padDiff))
    test = value.encode('utf-8')
    
    encrypted = base64.b64encode(cipher.encrypt(test)).decode("utf-8")
    
    return encrypted

@app.get("/")
async def root():
    return {"message": "Endpoint is up"}


@app.post("/encrypt")
async def formatRequest(request:Request, Token: str = Header(...)):
    
    if not Token:
        return {
                "message": "Encryption key not provided. Please check your header."
            }
    
    req = request.dict()

    for key in IntegerValueKeyArray:
        data = req[key]
        req[key] = encrypt_data(Token, data)

    encrypted_response = EncryptedResponse(**req)
    return encrypted_response


