FROM golang:latest

#$GOPATHに/go/srcを追加．この後srcの下にアプリケーションフォルダを作成する為
ENV GOPATH $GOPATH:/go/src

#とりあえず更新
RUN apt-get update && \
    apt-get upgrade -y && \
		apt-get install -y default-mysql-client

# go1.16から変わったらしいので対応
RUN go env -w GO111MODULE=off 

#インストール
RUN go get github.com/mattn/go-sqlite3 && \
    go get github.com/gorilla/mux && \
    go get github.com/gorilla/handlers && \
    go get github.com/dgrijalva/jwt-go && \
    go get github.com/dgrijalva/jwt-go/request

#アプリケーション(myapp)をマウントするためのディレクトリを作成
RUN mkdir /go/src/myapp
RUN : "flagを作成する" && { \
  echo "flag_directory_traversal"; \
} | tee /flag

# 直下のディレクトリをコンテナ上に載せる
ADD . /go/src/myapp

WORKDIR /go/src/myapp

# RUN: docker buildするときに実行される
#RUN go build -o test1 .
#CMD ["test1"]

# ここでビルド
RUN go build /go/src/myapp/main.go
ENTRYPOINT ["/go/src/myapp/main"]

EXPOSE 8081
