# vulngo

## 脆弱なGoアプリ

## use local

```
$ docker build -t vulngo:1 .
$ docker run -it -d --name vulngo1 -p 8081:8081 vulngo:1
```

open http://localhost:8081/
