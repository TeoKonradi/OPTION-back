# Authentication

## Permissions
Address: `{{connection}}/auth/permissions` [GET]
Answer `200`, `json`
```json
["permission"]
```


## Login
Address: `{{connection}}/auth/login` [POST]

Standard owner login is password is "admin", "admin"

Require: `json`
```json
{
  "username": "USERNAME",
  "password": "PASSWORD"
}
```

Answer: `200`, `COOKIE` & `json`
```json
{
    "refresh_token": "REFRESH_TOKEN",
    "access_token": "ACCESS_TOKEN"
}
```

## Logout
Address: `{{connection}}/auth/logout` [GET]
Answer: `200`, `COOKIE` & `json`
```json
{
    "refresh_token": "log out",
    "access_token": "log out"
}
```

## Refresh
Address: `{{connection}}/auth/me/refresh` [GET]
Require: `LOGIN`
Answer: `200`, `COOKIE` & `json`
```json
{
    "refresh_token": "REFRESH_TOKEN"
}
```

## Me
Address: `{{connection}}/auth/me` [GET]
Require: `LOGIN`
Answer: `200`, `COOKIE` & `json`
```json
{
  "username": "admin",
  "is_active": true,
  "is_staff": true,
  "is_super_user": true,
  "last_login": 1694253508,
  "register": 1694235994,
  "permissions": ["permission"],
  "groups": []
}
```
Permissions field already include all groups permissions

## Change password
Address: `{{connection}}/auth/change/password` [GET]

Require: `LOGIN` & `json`
```json
{
  "old_password": "OLD_PASSWORD",
  "password": "PASSWORD"
}
```

Answer: `200`, `json`
```json
{
  "status": "success"
}
```