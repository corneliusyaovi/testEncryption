from Crypto.Cipher import DES3
from fastapi import FastAPI, Header
from pydantic import BaseModel
from typing import List, Union
import json
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
    "cardzip"
]

def encrypt_vpcrouting(key, value):
    
    key_bytes = key.encode('utf-8')
    value_byte = value.encode('utf-8')

    if len(value_byte) % 8 != 0:
        value_byte += b"\0" * (8 - len(value_byte) % 8)

    cipher = DES3.new(key_bytes, DES3.MODE_ECB)
    encrypted_bytes = cipher.encrypt(value_byte)

    encrypted_base64 = base64.b64encode(encrypted_bytes)

    encrypted = encrypted_base64.decode('utf-8')
    
    return encrypted

@app.get("/")
async def root():
    return {"message": "Endpoint is up"}


@app.post("/encrypt")
async def encrypt(request:Request, Token: str = Header(...)):
    
    if not Token:
        return {
                "message": "Encryption key not provided. Please check your header."
            }
    
    req = request.dict()
    cipher = DES3.new(Token.encode(), DES3.MODE_ECB)

    for key in IntegerValueKeyArray:
        value = int(req[key])
        value_bytes = value.to_bytes(8, byteorder='big')
        padded_value_bytes = value_bytes.ljust(len(value_bytes) + (8 - len(value_bytes) % 8), b"\0")
        encrypted_value_bytes = cipher.encrypt(padded_value_bytes)
        encrypted_value_str = encrypted_value_bytes.hex()
        req[key] = encrypted_value_str

    for key in req:
        if req.get("vpcrouting") is not None:
            req["vpcrouting"] = encrypt_vpcrouting(Token, req["vpcrouting"])
    
    encrypted_response = EncryptedResponse(**req)
    return encrypted_response


