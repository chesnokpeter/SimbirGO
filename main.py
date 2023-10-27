from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException

from pydantic import BaseModel
import inspect, re
from typing import Literal

from models import User, BaseUser, AdminUser, BaseAdminUser, Transport, BaseTransport, AdminTransport, BaseAdminTransport, Rent, AdminRent, BaseAdminRent

app = FastAPI()

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title = "SimbirGo API",
        version = "1.0",
        description = "",
        routes = app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "Bearer Auth": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "Enter: **'Bearer &lt;JWT&gt;'**, where JWT is the access token"
        }
    }

    # Get all routes where jwt_optional() or jwt_required
    api_router = [route for route in app.routes if isinstance(route, APIRoute)]

    for route in api_router:
        path = getattr(route, "path")
        endpoint = getattr(route,"endpoint")
        methods = [method.lower() for method in getattr(route, "methods")]

        for method in methods:
            # access_token
            if (
                re.search("jwt_required", inspect.getsource(endpoint)) or
                re.search("fresh_jwt_required", inspect.getsource(endpoint)) or
                re.search("jwt_optional", inspect.getsource(endpoint))
            ):
                openapi_schema["paths"][path][method]["security"] = [
                    {
                        "Bearer Auth": []
                    }
                ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

class Settings(BaseModel):
    authjwt_secret_key: str = "2rewerf346t4tgdry3565ehs56hy"
    authjwt_denylist_enabled: bool = True
    authjwt_denylist_token_checks: set = {"access"}

@AuthJWT.load_config
def get_config():
    return Settings()

denylist = set()

@AuthJWT.token_in_denylist_loader
def check_if_token_in_denylist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in denylist

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )


@app.post('/api/Account/SignUp')
def signup(base: BaseUser):
    user = User(base.username, base.password)
    a = user.signup()
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )


@app.post('/api/Account/SignIn')
def signin(base: BaseUser, Authorize: AuthJWT = Depends()):
    user = User(base.username, base.password)
    a = user.signin()
    if not a[2]: return JSONResponse(
        status_code=a[1],
        content={"msg":a[0]}
    )
    access_token = Authorize.create_access_token(subject=base.username)
    return {"access_token": access_token}

@app.post('/api/Account/SignOut')
def signout(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    user = User(userjwt)
    a = user.signout()
    if a:
        jti = Authorize.get_raw_jwt()['jti']
        denylist.add(jti)
        a = ['Выход произошён успешно', 200]
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.get('/api/Account/Me')
def getmeuser(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}

@app.put('/api/Account/Update')
def updateuser(base: BaseUser, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userusername = Authorize.get_jwt_subject()
    user = User(userusername)
    a = user.update(base.username, base.password) 
    return JSONResponse(
        status_code=a[1],
        content={"msg":a[0]}
    )


@app.get('/api/Admin/Account')
def adminuserlist(start: int = 0, count: int = 0, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.listuser(start, count)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.get('/api/Admin/Account/{id}')
def userbyid(id: int = 0, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.userbyid(id)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.post('/api/Admin/Account/')
def addadminuser(base: BaseAdminUser, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.adduseradmin(base.username, base.password, base.isAdmin, base.balance)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.put('/api/Admin/Account/{id}')
def addadminuser(base: BaseAdminUser, Authorize: AuthJWT = Depends(), id:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.edituseradmin(base.username, base.password, base.isAdmin, base.balance, id)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.delete('/api/Admin/Account/{id}')
def addadminuser(Authorize: AuthJWT = Depends(), id:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.deleteuseradmin(id)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.get('/api/Transport/{id}')
def gettransport(id:int=0):
    tr = Transport(id)
    a = tr.gettransportbyid()
    return a

@app.put('/api/Transport/{id}')
def puttransport(base: BaseTransport, Authorize: AuthJWT = Depends(), id:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = Transport(userjwt)
    a = tr.edittransport(
            base.canBeRented,
            base.transportType,
            base.model,
            base.color,
            base.identifier,
            base.description,
            base.latitude,
            base.longitude,
            base.minutePrice, 
            base.dayPrice,
            id
        )
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.delete('/api/Transport/{id}')
def dettransport(Authorize: AuthJWT = Depends(), id:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = Transport(userjwt)
    a = tr.deletetransportbyid(id)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.post('/api/Transport')
def addtransport(base: BaseTransport, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = Transport(userjwt)
    a = tr.addtransport(
            base.canBeRented,
            base.transportType,
            base.model,
            base.color,
            base.identifier,
            base.description,
            base.latitude,
            base.longitude,
            base.minutePrice, 
            base.dayPrice,
        )
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )


@app.post('/api/Payment/Hesoyam/{accountId}')
def hesoyam(Authorize: AuthJWT = Depends(), accountId:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.addbalance(accountId)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )


@app.get('/api/Admin/Transport')
def admintransportlist(start: int = 0, count: int = 10, transportType:str = 'ALL', Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = AdminTransport(userjwt)
    a = tr.admintrlist(start, count, transportType)
    return a

@app.get('/api/Admin/Transport/{id}')
def admintrbyid(id: int = 0, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = AdminTransport(userjwt)
    a = tr.admintrbyid(id)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.post('/api/Admin/Transport')
def addtransport(base: BaseAdminTransport, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = AdminTransport(userjwt)
    a = tr.addtransport(
            base.ownerid,
            base.canBeRented,
            base.transportType,
            base.model,
            base.color,
            base.identifier,
            base.description,
            base.latitude,
            base.longitude,
            base.minutePrice, 
            base.dayPrice,
        )
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )


@app.put('/api/Admin/Transport/{id}')
def edittransport(base: BaseAdminTransport, Authorize: AuthJWT = Depends(), id: int = 0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = AdminTransport(userjwt)
    a = tr.edittransport(
            base.ownerid,
            base.canBeRented,
            base.transportType,
            base.model,
            base.color,
            base.identifier,
            base.description,
            base.latitude,
            base.longitude,
            base.minutePrice, 
            base.dayPrice,
            id
        )
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.delete('/api/Admin/Transport/{id}')
def dettransport(Authorize: AuthJWT = Depends(), id:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = AdminTransport(userjwt)
    a = tr.deletetransportbyid(id)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )


@app.get('/api/Rent/Transport')
def rentlist(lat:float, long:float, radius:float, type:str):
    rent = Rent()
    a = rent.rentrad(lat, long, radius, type)
    return a


@app.post('/api/Rent/New/{transportId}')
def newrent(rentType:Literal["Minutes", 'Days'], transportId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = Rent(userjwt)
    a = rent.rentnew(transportId, rentType)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.get('/api/Rent/{rentId}')
def getinforentid(rentId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = Rent(userjwt)
    a = rent.inforentid(rentId)
    return a

@app.get('/api/RentMyHistory')
def getmyrenthistory(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = Rent(userjwt)
    a = rent.myhistory()
    return a

@app.get('/api/Rent/TransportHistory/{transportId}')
def gettrhistory(transportId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = Rent(userjwt)
    a = rent.trhistory(transportId)
    return a

@app.post('/api/Rent/End/{rentid}')
def endrent(rentid:int, lat:float, long:float, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = Rent(userjwt)
    a = rent.rentend(rentid, lat, long)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.get('/api/Admin/Rent/{rentid}')
def rentidinfoadmin(rentid:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.inforentid(rentid)
    return a

@app.get('/api/Admin/Rent/UserHistory/{userId}')
def rentuserinfoadmin(userId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.inforentuser(userId)
    return a

@app.get('/api/Admin/Rent/TransportHistory/{transportId}')
def renttrinfoadmin(transportId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.inforenttr(transportId)
    return a


@app.post('/api/Admin/Rent')
def addadminrent(base: BaseAdminRent, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.addrent(base.transportId,
        base.userId, base.timeStart,
        base.timeEnd, base.priceOfUnit,
        base.priceType, base.finalPrice)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.post('/api/Admin/Rent/End/{rentid}')
def endadminrent(rentid:int, lat:float, long:float, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.rentend(rentid, lat, long)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.put('/api/Admin/Rent/{id}')
def putadminrentid(base:BaseAdminRent, id:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.putadminrentid(id, base.transportId,
        base.userId, base.timeStart,
        base.timeEnd, base.priceOfUnit,
        base.priceType, base.finalPrice)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

@app.delete('/api/Admin/Rent/{rentId}')
def deladminrent(rentId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.deladminrent(rentId)
    return JSONResponse(
        status_code=a[1],
        content=a[0]
    )

