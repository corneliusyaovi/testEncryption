from Crypto.Cipher import DES3
from fastapi import FastAPI, Header
from pydantic import BaseModel
from typing import Dict, Union
import json
import uvicorn

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
    vpcrouting: Dict[str, int] = None

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
    vpcrouting: Dict[str, int] = None

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

@app.post("/encrypt")
async def encrypt(request:Request, Token: str = Header(...)):

    req = request.dict()
    cipher = DES3.new(Token.encode(), DES3.MODE_ECB)

    for key in IntegerValueKeyArray:
        value = int(req[key])
        value_bytes = value.to_bytes(8, byteorder='big')
        padded_value_bytes = value_bytes.ljust(len(value_bytes) + (8 - len(value_bytes) % 8), b"\0")
        encrypted_value_bytes = cipher.encrypt(padded_value_bytes)
        encrypted_value_str = encrypted_value_bytes.hex()
        req[key] = encrypted_value_str

    
    encrypted_response = EncryptedResponse(**req)
    return encrypted_response
