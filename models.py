import psycopg2
from psycopg2.extras import RealDictCursor, RealDictRow

from pydantic import BaseModel
from typing import Literal
import datetime

DATABASENAME = 'SimbirGO'
USER = 'postgres'
PASSWORD = ''
HOST = 'localhost'

conn = psycopg2.connect(dbname=DATABASENAME, user=USER, password=PASSWORD, host=HOST)

c = conn.cursor()
c.execute("""
CREATE OR REPLACE FUNCTION calculate_distance(s_lat double precision, s_lng double precision, e_lat double precision, e_lng double precision) 
RETURNS double precision AS 
$$
DECLARE
    R CONSTANT double precision := 6373.0;
    s_lat_rad double precision := radians(s_lat);
    s_lng_rad double precision := radians(s_lng);
    e_lat_rad double precision := radians(e_lat);
    e_lng_rad double precision := radians(e_lng);
    d double precision;
BEGIN
    d := sin((e_lat_rad - s_lat_rad) / 2)^2 + cos(s_lat_rad) * cos(e_lat_rad) * sin((e_lng_rad - s_lng_rad) / 2)^2;
    RETURN 2 * R * asin(sqrt(d));
END;
$$
LANGUAGE plpgsql;""")
conn.commit()   
c.execute("""
CREATE TABLE IF NOT EXISTS "user" (
    "id" SERIAL PRIMARY KEY,
    "username" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "isAdmin" BOOLEAN NOT NULL DEFAULT false,
    "balance" NUMERIC NOT NULL DEFAULT 0
);""")
conn.commit()
c.execute("""
CREATE TABLE IF NOT EXISTS "transport" (
    "id" SERIAL PRIMARY KEY,
    "ownerid" BIGINT NOT NULL,
    "canBeRented" BOOLEAN NOT NULL DEFAULT true,
    "transportType" TEXT NOT NULL,
    "model" TEXT NOT NULL,
    "color" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "description" TEXT,
    "latitude" NUMERIC NOT NULL,
    "longitude" NUMERIC NOT NULL,
    "minutePrice" NUMERIC,
    "dayPrice" NUMERIC
);
""")
conn.commit()   
c.execute("""
CREATE TABLE IF NOT EXISTS "rent" (
    "id" SERIAL PRIMARY KEY,
    "transportId" INTEGER NOT NULL,
    "userId" INTEGER NOT NULL,
    "timeStart" TEXT NOT NULL,
    "timeEnd" TEXT,
    "priceOfUnit" NUMERIC NOT NULL,
    "priceType" TEXT NOT NULL,
    "finalPrice" INTEGER DEFAULT 0
);
""")
conn.commit()   
c.close()


class BaseUser(BaseModel):
    username: str
    password: str

class BaseAdminUser(BaseModel):
    username: str
    password: str
    isAdmin: bool
    balance: float

class BaseTransport(BaseModel):
    canBeRented: bool
    transportType: Literal['Car', 'Bike', 'Scooter']
    model: str
    color: str
    identifier: str
    description: str = None
    latitude: float
    longitude: float
    minutePrice: float = None
    dayPrice: float = None

class BaseAdminTransport(BaseModel):
    ownerid: int
    canBeRented: bool
    transportType: Literal['Car', 'Bike', 'Scooter']
    model: str
    color: str
    identifier: str
    description: str = None
    latitude: float
    longitude: float
    minutePrice: float = None
    dayPrice: float = None

class BaseAdminRent(BaseModel):
    transportId:int
    userId:int
    timeStart:str
    timeEnd:str = None
    priceOfUnit:float
    priceType:Literal['Minutes', 'Days']
    finalPrice:int = 0



class User():
    def __init__(self, username:str, password:str=None) -> None:
        self.username = username
        self.password = password
    def signup(self) -> list:
        c = conn.cursor()
        c.execute('SELECT id FROM "user" WHERE username = %s', [self.username])
        a = c.fetchall()
        if a: c.close(); return ['Пользователь уже зерегестрирован', 401]
        c.execute('INSERT INTO "user" (username, password) VALUES (%s, %s)', [self.username, self.password])
        conn.commit()
        c.close()
        return ['Пользователь успешно зарегестрирован', 200]

    def signin(self) -> list[str, int, bool]:
        c = conn.cursor()
        c.execute('SELECT id FROM "user" WHERE username = %s AND password = %s', [self.username, self.password])
        a = c.fetchall()
        if not a: c.close(); return ['Неверный логин или пароль', 401, False]
        c.close()
        return ['Вход успешно выполнен', 200, True]

    def update(self, updusername, updpassword) -> list[str, int]:
        c = conn.cursor()
        if self.username == updusername :
            c.execute('SELECT id FROM "user" WHERE username = %s', [updusername])
            a = c.fetchall()    
            c.execute("""UPDATE "user" SET username = %s, password = %s WHERE id = %s""", [updusername, updpassword, a[0]])
            conn.commit()
            c.close()
            return ['Обновить данные получилось', 200]
        c.execute('SELECT id FROM "user" WHERE username = %s', [updusername])
        a = c.fetchall()
        if a: c.close(); return ['Пользователь с таким именем уже существует', 401]
        c.execute('SELECT id FROM "user" WHERE username = %s', [self.username])
        a = c.fetchall()
        if not a: c.close(); return ['Пользователь не найден', 401]
        c.execute("""UPDATE "user" SET username = %s, password = %s WHERE id = %s""", [updusername, updpassword, a[0]])
        conn.commit()
        c.close()
        return ['Обновить данные получилось', 200]

    def signout(self):
        c = conn.cursor()
        c.execute('SELECT id FROM "user" WHERE username = %s', [self.username])
        a = c.fetchall()
        if not a: c.close(); return [False, 'Пользователь не найден', 401]
        return [True]



class AdminUser():
    def __init__(self, username: str):
        self.username = username

    def listuser(self, start, count) -> list:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.username])
        a = c.fetchall()
        if not a: c.close(); return 401
        if a[0] == RealDictRow([('isAdmin', True)]):
            c.execute('SELECT * FROM "user" ORDER BY id LIMIT %s OFFSET %s', [count, start])
            a = c.fetchall()
            c.close()
            return a
        else:
            c.close()
            return 401
    
    def userbyid(self, id) -> list:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.username])
        a = c.fetchall()
        if not a: c.close(); return 401
        if a == RealDictRow([('isAdmin', True)]):
            c.close()
            return 401
        c.execute('SELECT * FROM "user" WHERE id = %s', [id])
        a = c.fetchall()
        c.close()
        return a

    def adduseradmin(self, username, password, isAdmin, balance) -> list:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.username])
        a = c.fetchall()
        if not a or a != [RealDictRow([('isAdmin', True)])]: c.close(); return 401
        c.execute('SELECT id FROM "user" WHERE username = %s', [username])
        a = c.fetchall()
        if a: c.close(); return 409 
        a = c.execute('''INSERT INTO "user" (username, password, "isAdmin", balance) VALUES (%s, %s, %s, %s) RETURNING *''', [username, password, isAdmin, balance])
        conn.commit()
        a = c.fetchone()
        c.close()
        return a
    
    def edituseradmin(self, username, password, isAdmin, balance, id) -> list:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.username])
        a = c.fetchall()
        if not a or a != [RealDictRow([('isAdmin', True)])]: c.close(); return 401
        c.execute('SELECT id FROM "user" WHERE username = %s', [username])
        a = c.fetchall()
        if a: c.close(); return 409
        c.execute("""UPDATE "user" SET username = %s, password = %s, "isAdmin" = %s, balance = %s WHERE id = %s RETURNING *""", [username, password, isAdmin, balance, id])
        conn.commit()
        a = c.fetchone()
        c.close()
        return a
    
    def deleteuseradmin(self, id) -> list[str, int]:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.username])
        a = c.fetchall()
        if not a or a != [RealDictRow([('isAdmin', True)])]: c.close(); return 401

        c.execute('DELETE FROM "user" WHERE id = %s', [id])
        conn.commit()
        c.close()

        return 204
    

    def addbalance(self, accountId):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.username])
        a = c.fetchall()
        if not a or a[0]['isAdmin'] == False: c.close(); return 401
        if not a[0]['isAdmin']:
            c.execute('SELECT "isAdmin" FROM "user" WHERE id = %s', [accountId])
            a = c.fetchall()
            if not a: c.close(); return 404
            c.execute('SELECT "id" FROM "user" WHERE username = %s', [self.username])
            a = c.fetchall()
            if a[0]['id'] == accountId:
                c.execute('SELECT "balance"::float FROM "user" WHERE id = %s', [accountId])
                b = c.fetchall()
                if not b: c.close(); return ['Пользователь не найден', 401]
                c.execute("""UPDATE "user" SET balance = %s WHERE id = %s""", [b[0]['balance'] + float(250000), accountId])
                conn.commit()
                c.close()
                return 200
            else: c.close(); return 404
        c.execute('SELECT "balance"::float FROM "user" WHERE id = %s', [accountId])
        b = c.fetchall()
        if not b: c.close(); return 404
        c.execute("""UPDATE "user" SET balance = %s WHERE id = %s""", [b[0]['balance'] + float(250000), accountId])
        conn.commit()
        c.close()
        return 200



class Transport():
    def __init__(self, user):
        self.user = user

    def addtransport(self, canBeRented: bool,
            transportType: str, model: str,
            color: str, identifier: str,
            description: str , latitude: float,
            longitude: float, minutePrice: float,
            dayPrice: float):

        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT id FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a: c.close(); return 401
        ownerid = a[0]['id']
        c.execute('''INSERT INTO "transport" ("ownerid", "canBeRented", "transportType", "model", "color", "identifier", "description", "latitude", "longitude", "minutePrice", "dayPrice") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *''', [ownerid, canBeRented, transportType, model, color, identifier, description, latitude, longitude, minutePrice, dayPrice])
        conn.commit()
        a = c.fetchone()
        c.close()
        return a
    
    def gettransportbyid(self):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT * FROM "transport" WHERE id = %s', [self.user])
        a = c.fetchall()
        c.close()
        return a
    
    def edittransport(self, canBeRented: bool,
            transportType: str, model: str,
            color: str, identifier: str,
            description: str , latitude: float,
            longitude: float, minutePrice: float,
            dayPrice: float, id):
        
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT id FROM "user" WHERE username = %s', [self.user])
        uid = c.fetchall()
        if not uid: c.close(); return 401
        c.execute('SELECT ownerid FROM "transport" WHERE id = %s', [id])
        tid = c.fetchall()
        tid = tid[0]['ownerid']
        if not tid: c.close(); return 404
        if uid[0]['id'] != tid: c.close(); return 400
        c.execute('''UPDATE "transport" SET "canBeRented" = %s, "transportType" = %s, "model" = %s, "color" = %s, "identifier" = %s, "description" = %s, "latitude" = %s, "longitude" = %s, "minutePrice" = %s, "dayPrice" = %s WHERE "ownerid" = %s RETURNING *''', [canBeRented, transportType, model, color, identifier, description, latitude, longitude, minutePrice, dayPrice, tid])
        conn.commit()
        a = c.fetchone()
        c.close()
        return a
    

    def deletetransportbyid(self, id):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT id FROM "user" WHERE username = %s', [self.user])
        uid = c.fetchall()
        if not uid: c.close(); return 401
        c.execute('SELECT ownerid FROM "transport" WHERE id = %s', [id])
        tid = c.fetchall()
        tid = tid[0]['ownerid']
        if not tid: c.close(); return 404
        if uid[0]['id'] != tid: c.close(); return 400
        c.execute('DELETE FROM "transport" WHERE id = %s', [id])
        conn.commit()
        c.close()
        return 200
    

class AdminTransport():
    def __init__(self, user):
        self.user = user

    def admintrlist(self, start, count, transportType):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or a != [RealDictRow([('isAdmin', True)])]: c.close(); return 401
        if transportType == 'ALL':
            c.execute('SELECT * FROM "transport" ORDER BY id LIMIT %s OFFSET %s', [count, start])
            a = c.fetchall()
            c.close()
            return a
        else:
            c.execute('SELECT * FROM "transport" WHERE "transportType" = %s ORDER BY id LIMIT %s OFFSET %s', [transportType, count, start])
            a = c.fetchall()
            c.close()
            return a

        
    def admintrbyid(self, id):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or a != [RealDictRow([('isAdmin', True)])]: c.close(); return 401
        c.execute('SELECT * FROM "transport" WHERE id = %s', [id])
        a = c.fetchall()
        c.close()
        return a
    
    def addtransport(self, ownerid: int, canBeRented,
            transportType: str, model: str,
            color: str, identifier: str,
            description: str, latitude: float,
            longitude: float, minutePrice: float,
            dayPrice: float):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or a != [RealDictRow([('isAdmin', True)])]: c.close(); return 401
        c.execute('SELECT * FROM "user" WHERE id = %s', [ownerid])
        a = c.fetchall()
        if not a: return 404

        c.execute('''INSERT INTO "transport" ("ownerid", "canBeRented", "transportType", "model", "color", "identifier", "description", "latitude", "longitude", "minutePrice", "dayPrice") VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''', [ownerid, canBeRented, transportType, model, color, identifier, description, latitude, longitude, minutePrice, dayPrice])
        conn.commit()
        c.close()
        return 200
    
    def edittransport(self, ownerid: int, canBeRented,
            transportType: str, model: str,
            color: str, identifier: str,
            description: str, latitude: float,
            longitude: float, minutePrice: float,
            dayPrice: float, id:int):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or a != [RealDictRow([('isAdmin', True)])]: c.close(); return 401
        c.execute('SELECT * FROM "user" WHERE id = %s', [ownerid])
        a = c.fetchall()
        if not a: return 404
        c.execute('SELECT * FROM "transport" WHERE id = %s', [id])
        a = c.fetchall()
        if not a: return 404
        c.execute('''UPDATE "transport" SET "ownerid" = %s, "canBeRented" = %s, "transportType" = %s, "model" = %s, "color" = %s, "identifier" = %s, "description" = %s, "latitude" = %s, "longitude" = %s, "minutePrice" = %s, "dayPrice" = %s WHERE "id" = %s''', [ownerid, canBeRented, transportType, model, color, identifier, description, latitude, longitude, minutePrice, dayPrice, id])
        conn.commit()
        c.close()
        return 200
    
    def deletetransportbyid(self, id):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or a != [RealDictRow([('isAdmin', True)])]: c.close(); return 401
        c.execute('SELECT * FROM "transport" WHERE id = %s', [id])
        a = c.fetchall()
        if not a: return 404
        c.execute('DELETE FROM "transport" WHERE id = %s', [id])
        conn.commit()
        c.close()
        return 200
    





class Rent():
    def __init__(self, user=None):
        self.user = user

    def rentrad(self, lat, long, radius, type):
        c = conn.cursor(cursor_factory=RealDictCursor)
        if type == 'ALL':
            c.execute('SELECT * FROM "transport" WHERE calculate_distance("latitude", "longitude", %s, %s) <= %s AND "canBeRented" = true', [lat, long, radius])
            a = c.fetchall()
            c.close()
            return a
        c.execute('SELECT * FROM "transport" WHERE calculate_distance("latitude", "longitude", %s, %s) <= %s AND "canBeRented" = true AND "transportType" = %s', [lat, long, radius, type])
        a = c.fetchall()
        c.close()
        return a
    
    def rentnew(self, transportId, rentType):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "canBeRented" FROM "transport" WHERE id = %s', [transportId])
        b = c.fetchall()
        if not b: c.close();return 401
        if b[0]['canBeRented'] == False: c.close(); return 405

        c.execute('SELECT "id" FROM "user" WHERE username = %s', [self.user])
        id = c.fetchall()
        if not id: c.close(); 401

        c.execute('SELECT "id" FROM "transport" WHERE "ownerid" = %s', [id[0]['id']])
        a = c.fetchall()
        if not a: c.close(); return 401
        for i in a:
            if i['id'] == transportId: c.close(); return 405

        c.execute('SELECT "minutePrice" FROM "transport" WHERE "id" = %s', [transportId])
        a = c.fetchall()
        if not a: c.close(); return 401
        if a[0]['minutePrice'] == None: c.close(); return 400

        c.execute('SELECT "dayPrice" FROM "transport" WHERE "id" = %s', [transportId])
        g = c.fetchall()
        if not g: c.close(); return 401
        if g[0]['dayPrice'] == None: c.close(); return 400

        c.execute('''INSERT INTO "rent" ("transportId", "userId", "timeStart", "priceOfUnit", "priceType") VALUES (%s, %s, %s, %s, %s)''', [transportId, id[0]['id'], datetime.datetime.now().isoformat(), a[0]['minutePrice'], rentType])
        conn.commit()
        c.close()
        return 200

    def inforentid(self, rentId):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "id" FROM "user" WHERE username = %s', [self.user])
        uid = c.fetchall()
        if not uid: c.close(); return 401
        c.execute('SELECT "userId" FROM "rent" WHERE id = %s', [rentId])
        rid = c.fetchall()
        if not rid: c.close(); return 401
        c.execute('SELECT "transportId" FROM "rent" WHERE id = %s', [rentId])
        tid = c.fetchall()
        if not tid: c.close();return 401
        c.execute('SELECT "ownerid" FROM "transport" WHERE id = %s', [tid[0]['transportId']])
        tid = c.fetchall()
        if not tid: c.close();return 405
        if uid[0]['id'] != rid[0]['userId'] and uid[0]['id'] != tid[0]['ownerid']: c.close(); return 405
        c.execute('SELECT * FROM "rent" WHERE id = %s', [rentId])
        a = c.fetchall()
        c.close()
        return a

    def myhistory(self):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "id" FROM "user" WHERE username = %s', [self.user])
        uid = c.fetchall()
        if not uid: c.close(); return 401

        c.execute('''SELECT * FROM "rent" WHERE "rent"."userId" = %s''', [uid[0]['id']])
        a = c.fetchall()
        c.close()
        return a
    
    def trhistory(self, transportId):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "id" FROM "user" WHERE username = %s', [self.user])
        uid = c.fetchall()
        if not uid: c.close(); return 401

        c.execute('''SELECT ownerid FROM "transport" WHERE id = %s''', [transportId])
        a = c.fetchall()
        if not a: c.close(); return 404
        if a[0]['ownerid'] != uid[0]['id']: c.close(); return 405
        c.execute('''SELECT * FROM "rent" WHERE "rent"."transportId" = %s''', [transportId])
        a = c.fetchall()
        c.close()
        return a
    
    def rentend(self, rentid, lat, long):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "id" FROM "user" WHERE username = %s', [self.user])
        uid = c.fetchall()
        if not uid: c.close(); 401
        c.execute('SELECT "userId" FROM "rent" WHERE id = %s', [rentid])
        a = c.fetchall()
        if not a: c.close(); return 404
        if a[0]["userId"] != uid[0]["id"]: c.close(); return 405
        c.execute('SELECT "transportId" FROM "rent" WHERE id = %s', [rentid])
        tid = c.fetchall()
        c.execute('SELECT "ownerid" FROM "transport" WHERE id = %s', [tid[0]['transportId']])
        ttest = c.fetchall()
        if ttest[0]['ownerid'] != uid[0]['id']: c.close(); return 405

        c.execute("""UPDATE "transport" SET latitude = %s, longitude = %s WHERE id = %s""", [lat, long, tid[0]['transportId']])
        conn.commit()
        c.execute("""UPDATE "rent" SET "timeEnd" = %s WHERE id = %s""", [datetime.datetime.now().isoformat(), rentid])
        conn.commit()
        c.close()
        return 200
    


class AdminRent():
    def __init__(self, user=None):
        self.user = user

    def inforentid(self, rentid):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or not a[0]['isAdmin']: c.close(); return 401

        c.execute('SELECT * FROM rent WHERE id = %s', [rentid])
        a = c.fetchall()
        c.close()
        return a
    
    def inforentuser(self, userId):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or not a[0]['isAdmin']: c.close(); return 401
        c.execute('SELECT * FROM "rent" WHERE "userId" = %s', [userId])
        a = c.fetchall()
        c.close()
        return a

    def inforenttr(self, transportId):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or not a[0]['isAdmin']: c.close(); return 401
        c.execute('SELECT * FROM "rent" WHERE "transportId" = %s', [transportId])
        a = c.fetchall()
        c.close()
        return a

    def addrent(self, transportId, 
            userId, timeStart,
            timeEnd, priceOfUnit,
            priceType, finalPrice):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or not a[0]['isAdmin']: c.close(); return 401

        c.execute('SELECT "id" FROM "transport" WHERE id = %s', [transportId])
        a = c.fetchall()
        if not a: c.close(); return 404

        c.execute('SELECT "id" FROM "user" WHERE id = %s', [userId])
        a = c.fetchall()
        if not a: c.close(); return 404

        c.execute('''INSERT INTO "rent" ("transportId", "userId", "timeStart", "timeEnd", "priceOfUnit", "priceType", "finalPrice") VALUES (%s, %s, %s, %s, %s, %s, %s)''', [transportId, userId, timeStart, timeEnd, priceOfUnit, priceType, finalPrice])
        conn.commit()
        c.close()
        return 200
    
    def rentend(self, rentid, lat, long):
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or not a[0]['isAdmin']: c.close(); return 401

        c.execute('SELECT "transportId" FROM "rent" WHERE id = %s', [rentid])
        tid = c.fetchall()
        if not tid: c.close(); return 404

        c.execute('SELECT "id" FROM "transport" WHERE id = %s', [tid[0]['transportId']])
        a = c.fetchall()
        if not a: c.close(); return 404

        c.execute('SELECT "userId" FROM "rent" WHERE id = %s', [rentid])
        a = c.fetchall()
        if not a: c.close(); return 404

        c.execute('SELECT "id" FROM "user" WHERE id = %s', [a[0]['userId']])
        a = c.fetchall()
        if not a: c.close(); return 404

        c.execute("""UPDATE "transport" SET latitude = %s, longitude = %s WHERE id = %s""", [lat, long, tid[0]['transportId']])
        conn.commit()
        c.execute("""UPDATE "rent" SET "timeEnd" = %s WHERE id = %s""", [datetime.datetime.now().isoformat(), rentid])
        conn.commit()
        c.close()
        return 200
    
    def putadminrentid(self, id, transportId, 
            userId, timeStart,
            timeEnd, priceOfUnit,
            priceType, finalPrice):   
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or not a[0]['isAdmin']: c.close(); return 401

        c.execute('SELECT "id" FROM "transport" WHERE id = %s', [transportId])
        a = c.fetchall()
        if not a: c.close(); return 404

        c.execute('SELECT "id" FROM "user" WHERE id = %s', [userId])
        a = c.fetchall()
        if not a: c.close(); return 404

        c.execute('SELECT "id" FROM "rent" WHERE id = %s', [id])
        a = c.fetchall()
        if not a: c.close(); return 404

        c.execute("""UPDATE "rent" SET "transportId" = %s, "userId" = %s, "timeStart" = %s, "timeEnd" = %s, "priceOfUnit" = %s, "priceType" = %s, "finalPrice" = %s WHERE id = %s""", [transportId, userId, timeStart, timeEnd, priceOfUnit, priceType, finalPrice, id])
        conn.commit()
        c.close()
        return 200

    def deladminrent(self, id): 
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute('SELECT "isAdmin" FROM "user" WHERE username = %s', [self.user])
        a = c.fetchall()
        if not a or not a[0]['isAdmin']: c.close(); return 401

        c.execute('SELECT "id" FROM "rent" WHERE id = %s', [id])
        a = c.fetchall()
        if not a: c.close(); return 404

        c.execute('DELETE FROM "rent" WHERE id = %s', [id])
        conn.commit()
        c.close()
        return 200
    







