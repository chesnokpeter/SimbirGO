from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException

from pydantic import BaseModel
import inspect, re
from typing import Literal
from datetime import timedelta

from models import User, BaseUser, AdminUser, BaseAdminUser, Transport, BaseTransport, AdminTransport, BaseAdminTransport, Rent, AdminRent, BaseAdminRent

app = FastAPI(title='SimbirGoAPI')

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
    authjwt_access_token_expires = timedelta(days=1)


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


@app.post('/api/Account/SignUp', tags=["Account"])
def signup(base: BaseUser):
    user = User(base.username, base.password)
    a = user.signup()
    return JSONResponse(
        status_code=a[1],
        content={"msg" : a[0]}
    )


@app.post('/api/Account/SignIn', tags=["Account"])
def signIn(base: BaseUser, Authorize: AuthJWT = Depends()):
    user = User(base.username, base.password)
    a = user.signin()
    if not a[2]: return JSONResponse(
        status_code=a[1],
        content={"msg":a[0]}
    )
    access_token = Authorize.create_access_token(subject=base.username)
    return {"access_token": access_token}

@app.post('/api/Account/SignOut', tags=["Account"])
def signOut(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    user = User(userjwt)
    a = user.signout()
    if a[0]:
        jti = Authorize.get_raw_jwt()['jti']
        denylist.add(jti)
        return JSONResponse(
            status_code=200,
            content={"msg":"Выход произошён успешно"}
        )
    return JSONResponse(
        status_code=a[2],
        content={"msg":a[1]}
    )

@app.get('/api/Account/Me', tags=["Account"])
def getMeUser(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}

@app.put('/api/Account/Update', tags=["Account"])
def updateUser(base: BaseUser, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userusername = Authorize.get_jwt_subject()
    user = User(userusername)
    a = user.update(base.username, base.password) 
    return JSONResponse(
        status_code=a[1],
        content={"msg":a[0]}
    )


@app.get('/api/Admin/Account', tags=["AdminAccount"])
def adminUserList(start: int = 0, count: int = 0, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.listuser(start, count)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return a

@app.get('/api/Admin/Account/{id}', tags=["AdminAccount"])
def userById(id: int = 0, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.userbyid(id)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return a

@app.post('/api/Admin/Account/', tags=["AdminAccount"])
def addAdminUser(base: BaseAdminUser, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.adduseradmin(base.username, base.password, base.isAdmin, base.balance)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    if a == 409: return JSONResponse( status_code=409, content={"msg":"Сущность уже создана"} )
    return a

@app.put('/api/Admin/Account/{id}', tags=["AdminAccount"])
def editAdminUserById(base: BaseAdminUser, Authorize: AuthJWT = Depends(), id:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.edituseradmin(base.username, base.password, base.isAdmin, base.balance, id)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    if a == 409: return JSONResponse( status_code=409, content={"msg":"Сущность уже создана"} )
    return a

@app.delete('/api/Admin/Account/{id}', tags=["AdminAccount"])
def addAdminUser(Authorize: AuthJWT = Depends(), id:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.deleteuseradmin(id)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return JSONResponse( status_code=200, content={"msg":"Сущность удалена успешно"} )

@app.post('/api/Payment/Hesoyam/{accountId}', tags=["Payment"])    
def hesoyam(Authorize: AuthJWT = Depends(), accountId:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    adminuser = AdminUser(userjwt)
    a = adminuser.addbalance(accountId)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    if a == 404: return JSONResponse( status_code=404, content={"msg":"Пользователь не найден"} )
    return JSONResponse( status_code=200, content={"msg":"Денежные единицы добавлены успешно"} )

@app.get('/api/Transport/{id}', tags=["Transport"])
def getTransport(id:int):
    tr = Transport(id)
    a = tr.gettransportbyid()
    return a

@app.put('/api/Transport/{id}', tags=["Transport"])
def putTransport(base: BaseTransport, Authorize: AuthJWT = Depends(), id:int=0):
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
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не найден"} )
    if a == 404: return JSONResponse( status_code=404, content={"msg":"Транспорт не найден"} )
    if a == 400: return JSONResponse( status_code=400, content={"msg":"Транспорт не этого пользователя"} )
    return a

@app.delete('/api/Transport/{id}', tags=["Transport"])
def deleteTransport(Authorize: AuthJWT = Depends(), id:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = Transport(userjwt)
    a = tr.deletetransportbyid(id)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не найден"} )
    if a == 404: return JSONResponse( status_code=404, content={"msg":"Транспорт не найден"} )
    if a == 400: return JSONResponse( status_code=400, content={"msg":"Транспорт не этого пользователя"} )
    return JSONResponse( status_code=200, content={"msg":"Транспорт успешно удалён"} )

@app.post('/api/Transport', tags=["Transport"])
def addTransport(base: BaseTransport, Authorize: AuthJWT = Depends()):
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
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не найден"} )
    return a


@app.get('/api/Admin/Transport', tags=["AdminTransport"])
def adminTransportList(start: int = 0, count: int = 10, transportType:str = 'ALL', Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = AdminTransport(userjwt)
    a = tr.admintrlist(start, count, transportType)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return a

@app.get('/api/Admin/Transport/{id}', tags=["AdminTransport"])
def adminTrById(id: int = 0, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = AdminTransport(userjwt)
    a = tr.admintrbyid(id)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return a


@app.post('/api/Admin/Transport', tags=["AdminTransport"])
def adminAddTransport(base: BaseAdminTransport, Authorize: AuthJWT = Depends()):
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
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    if a == 404: return JSONResponse( status_code=404, content={"msg":"Пользователь не найден"} )
    return JSONResponse( status_code=200, content={"msg":"Транспорт добавлен успешно"} )


@app.put('/api/Admin/Transport/{id}', tags=["AdminTransport"])
def adminEditTransport(base: BaseAdminTransport, Authorize: AuthJWT = Depends(), id: int = 0):
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
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    if a == 404: return JSONResponse( status_code=404, content={"msg":"Пользователь или транспорт не найден"} )
    return JSONResponse( status_code=200, content={"msg":"Транспорт успешно обновлен"} )


@app.delete('/api/Admin/Transport/{id}', tags=["AdminTransport"])
def adminDeleteTransport(Authorize: AuthJWT = Depends(), id:int=0):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    tr = AdminTransport(userjwt)
    a = tr.deletetransportbyid(id)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    if a == 404: return JSONResponse( status_code=404, content={"msg":"Транспорт не найден"} )
    return JSONResponse( status_code=200, content={"msg":"Транспорт успешно удалён"} )


@app.get('/api/Rent/Transport', tags=["Rent"])
def rentList(lat:float, long:float, radius:float, type:str):
    rent = Rent()
    a = rent.rentrad(lat, long, radius, type)
    return a


@app.post('/api/Rent/New/{transportId}', tags=["Rent"])
def newRent(rentType:Literal["Minutes", 'Days'], transportId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = Rent(userjwt)
    a = rent.rentnew(transportId, rentType)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь или транспорт не найден"} )
    if a == 405: return JSONResponse( status_code=405, content={"msg":"Транспорт не может быть арендован или транспорт этого пользователя"} )
    if a == 400: return JSONResponse( status_code=405, content={"msg":"Данный транспорт арендовать нельзя"} )
    return JSONResponse( status_code=200, content={"msg":"Аренда успешно добавлена"} )


@app.get('/api/Rent/MyHistory', tags=["Rent"])    # ПОПРАВИТЬ, КОНФЛИКТ
def getMyRentHistory(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = Rent(userjwt)
    a = rent.myhistory()
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь или аренда не найдены"} )
    return a


@app.get('/api/Rent/{rentId}', tags=["Rent"])
def getInfoRentId(rentId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = Rent(userjwt)
    a = rent.inforentid(rentId)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь или транспорт не найден"} )
    if a == 405: return JSONResponse( status_code=405, content={"msg":"Транспорт не этого пользователя"} )
    return a



@app.get('/api/Rent/TransportHistory/{transportId}', tags=["Rent"])
def getTrHistory(transportId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = Rent(userjwt)
    a = rent.trhistory(transportId)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не найден"} )
    if a == 405: return JSONResponse( status_code=405, content={"msg":"Транспорт не этого пользователя"} )
    if a == 404: return JSONResponse( status_code=404, content={"msg":"Транспорт не найден"} )
    return a

@app.post('/api/Rent/End/{rentid}', tags=["Rent"])
def endRent(rentid:int, lat:float, long:float, Authorize: AuthJWT = Depends()):
    print('этот роут не тестировался')
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = Rent(userjwt)
    a = rent.rentend(rentid, lat, long)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не найден"} )
    if a == 405: return JSONResponse( status_code=405, content={"msg":"Аренда или транспорт не этого пользователя"} )
    if a == 404: return JSONResponse( status_code=404, content={"msg":"Транспорт или аренда не найдены"} )
    return JSONResponse( status_code=200, content={"msg":"Аренда успешно завершена"} )


@app.get('/api/Admin/Rent/{rentid}', tags=["AdminRent"])
def rentIdInfoAdmin(rentid:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.inforentid(rentid)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return a

@app.get('/api/Admin/Rent/UserHistory/{userId}', tags=["AdminRent"])
def rentUserInfoAdmin(userId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.inforentuser(userId)
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return a

@app.get('/api/Admin/Rent/TransportHistory/{transportId}', tags=["AdminRent"])
def renTtrInfoAdmin(transportId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.inforenttr(transportId)
    return a


@app.post('/api/Admin/Rent', tags=["AdminRent"])
def addAdminRent(base: BaseAdminRent, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.addrent(base.transportId,
        base.userId, base.timeStart,
        base.timeEnd, base.priceOfUnit,
        base.priceType, base.finalPrice)
    if a == 404: return JSONResponse( status_code=400, content={"msg":"Транспорт или пользователь не найдены"} )
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return JSONResponse( status_code=200, content={"msg":"Аренда успешно дабавлена"} )


@app.post('/api/Admin/Rent/End/{rentid}', tags=["AdminRent"])
def endAdminRent(rentid:int, lat:float, long:float, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.rentend(rentid, lat, long)
    if a == 404: return JSONResponse( status_code=400, content={"msg":"Транспорт или пользователь или аренда не найдены"} )
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return JSONResponse( status_code=200, content={"msg":"Аренда успешно закончена"} )


@app.put('/api/Admin/Rent/{id}', tags=["AdminRent"])
def putAdminRentId(base:BaseAdminRent, id:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.putadminrentid(id, base.transportId,
        base.userId, base.timeStart,
        base.timeEnd, base.priceOfUnit,
        base.priceType, base.finalPrice)
    if a == 404: return JSONResponse( status_code=400, content={"msg":"Транспорт или пользователь или аренда не найдены"} )
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return JSONResponse( status_code=200, content={"msg":"Аренда успешно изменена"} )


@app.delete('/api/Admin/Rent/{rentId}', tags=["AdminRent"])
def delAdminRent(rentId:int, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    userjwt = Authorize.get_jwt_subject()
    rent = AdminRent(userjwt)
    a = rent.deladminrent(rentId)
    if a == 404: return JSONResponse( status_code=400, content={"msg":"Аренда не найдена"} )
    if a == 401: return JSONResponse( status_code=401, content={"msg":"Пользователь не является администратором или не найден"} )
    return JSONResponse( status_code=200, content={"msg":"Аренда успешно удалена"} )


