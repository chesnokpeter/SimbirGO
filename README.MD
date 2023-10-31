# SimbirGo API решение Чеснокова Петра Ильича
## Установка
`pip install -r requirements.txt`
## Настройка
### Настройка соединения с базой данных происходит в models.py:13
JWT Авторизация просиходит с одним токеном, который хранит username \
Токен передаётся в заголовок Authorization: Bearer \<JWT>
## Запуск
`uvicorn main:app --reload`
## Swagger URL
`http://127.0.0.1:8000/docs#/` 

Запрос `/api/Account/SignIn` вернет JWT токен \
После того, как вы получите JWT токен, его необходимо добавить в загловок Authorization, для этого в Swagger нужно нажать на кнопку сверху Authorize, написать Bearer и вставить JWT токен