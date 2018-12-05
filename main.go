package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
_ "github.com/mattn/go-sqlite3"
	"log"
	"html"
	"os/exec"
	"os"
	"time"
	"strconv"
	"io"
	"io/ioutil"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"strings"
)

//データ
type Addressbook struct{
	ID   int    `json:"id"`
	Name string `json:"name"`
	Address string `json:"address"`
	Memo string `json:"memo"`
	Created string `json:"created"`
}

type App struct {
	Router *mux.Router
}

//初期化
func (a *App) Initialize() {
	//URLルーティング
	a.Router = mux.NewRouter()
	//SQLインジェクション
	a.Router.HandleFunc("/sqli/id/{id}", sqliIDhandler).Methods("GET")
	a.Router.HandleFunc("/nosqli/id/{id}", nosqliIDhandler).Methods("GET")
	a.Router.HandleFunc("/sqli/{name}", sqlihandler)
	a.Router.HandleFunc("/nosqli/{name}", nosqlihandler)

	a.Router.HandleFunc("/sqli_name", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/sqli_name.html")
	})
	a.Router.HandleFunc("/nosqli_name", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/nosqli_name.html")
	})
	a.Router.HandleFunc("/sqli_id", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/sqli_id.html")
	})
	a.Router.HandleFunc("/nosqli_id", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/nosqli_id.html")
	})

	//XSS
	a.Router.HandleFunc("/xss", XSShandler)//ある方
	a.Router.HandleFunc("/noxss", noXSShandler)//ない方
	//オープンリダイレクト
	a.Router.HandleFunc("/hredirect", headerRedirectHandler)//リダイレクトその1
	a.Router.HandleFunc("/redirect", RedirectHandler)//リダイレクトその2
	//RCE
	a.Router.HandleFunc("/rce", rcehandler)
	a.Router.HandleFunc("/ping1", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/rce.html")
	})
	a.Router.HandleFunc("/norce", norcehandler)
	a.Router.HandleFunc("/ping2", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/norce.html")
	})
	//ディレクトリトラバーサル
	a.Router.HandleFunc("/traversal", traversalhandler)
	a.Router.HandleFunc("/readfile", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/readfile.html")
	})
	//ディレクトリトラバーサルなし
	a.Router.PathPrefix("/data/").Handler(http.StripPrefix("/data/", http.FileServer(http.Dir("./data"))))
	a.Router.HandleFunc("/notraversal", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/notraversal.html")
	})

	//SSRF
	a.Router.HandleFunc("/ssrfget", getSSRFhandler)//
	a.Router.HandleFunc("/ssrf1", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/ssrf1.html")
	})

	a.Router.HandleFunc("/ssrfrequest", requestSSRFhandler)
	a.Router.HandleFunc("/ssrf2", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/ssrf2.html")
	})

	a.Router.HandleFunc("/jwt/token", jwttokenhandler)
	a.Router.HandleFunc("/jwt/private", jwtprivatehandler)
	a.Router.HandleFunc("/jwt", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/jwt.html")
	})

	//静的ファイル
	a.Router.PathPrefix("/images/").Handler(http.StripPrefix("/images/", http.FileServer(http.Dir("./images/"))))
	a.Router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

}

//アプリ開始
func (a *App) Run(addr string) {
	log.Fatal(http.ListenAndServe(addr, handlers.CORS() (a.Router)))
}

//JSONの書き出し
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(code)
	w.Write(response)
}

func main(){
	a := App{}
    //DBの接続設定
	a.Initialize()
	//指定したポートで起動
	a.Run(":8081")
}

//ハンドラ
func sqliIDhandler(w http.ResponseWriter,r *http.Request) {
	vars := mux.Vars(r)
	search_id:= vars["id"]
	fmt.Println(search_id)
	u := Addressbook{}
	// データベースのコネクションを開く
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		panic(err)
	}
	statement := fmt.Sprintf("SELECT `id`,`name`,`address`,`memo`,`created` FROM `ADDRESSBOOK` WHERE id=%s limit 0,1", search_id)
	fmt.Println(statement)
	//QueryRowは一件取得
	if err := db.QueryRow(statement).Scan(&u.ID,&u.Name,&u.Address,&u.Memo,&u.Created); err != nil {
		//panic(err)
		errmsg:=[]byte(fmt.Sprintf(`{"error": "%s"}`,err))
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(errmsg)
		return
	}
	respondWithJSON(w, http.StatusOK, u)
}
//ハンドラ
func nosqliIDhandler(w http.ResponseWriter,r *http.Request) {
	vars := mux.Vars(r)
	search_id:= vars["id"]
	u := Addressbook{}
	// データベースのコネクションを開く
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		panic(err)
	}
	if err := db.QueryRow("SELECT `id`,`name`,`address`,`memo`,`created` FROM `ADDRESSBOOK` WHERE `id`=?",search_id).Scan(&u.ID,&u.Name,&u.Address,&u.Memo,&u.Created); err != nil {
		//panic(err)
		errmsg:=[]byte(fmt.Sprintf(`{"error": "%s"}`,err))
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(errmsg)
		return
	}
	fmt.Printf("id: %d, name: %s address: %s memo: %s \n", u.ID, u.Name,u.Address,u.Memo)
	respondWithJSON(w, http.StatusOK, u)
}

func sqlihandler(w http.ResponseWriter,r *http.Request) {
	//URLから引数を取得
	vars := mux.Vars(r)
	search_name := vars["name"]
	fmt.Println(search_name)

	u := Addressbook{}
	// データベースのコネクションを開く
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		panic(err)
	}
	//statement := fmt.Sprintf("SELECT id, name, age FROM users LIMIT %d OFFSET %d", count, start)
	statement := fmt.Sprintf("SELECT `id`,`name`,`address`,`memo`,`created` FROM `ADDRESSBOOK` WHERE `name`='%s' limit 0,1", search_name)

	//QueryRowは一件取得
	if err := db.QueryRow(statement).Scan(&u.ID,&u.Name,&u.Address,&u.Memo,&u.Created); err != nil {
		//panic(err)
		errmsg:=[]byte(fmt.Sprintf(`{"error": "%s"}`,err))
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(errmsg)
		return
	}

	fmt.Printf("id: %d, name: %s address: %s memo: %s \n", u.ID, u.Name,u.Address,u.Memo)
	respondWithJSON(w, http.StatusOK, u)
}
func nosqlihandler(w http.ResponseWriter,r *http.Request) {
	//URLから引数を取得
	vars := mux.Vars(r)
	search_name := vars["name"]
	fmt.Println(search_name)

	u := Addressbook{}
	// データベースのコネクションを開く
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		panic(err)
	}
	if err := db.QueryRow("SELECT `id`,`name`,`address`,`memo`,`created` FROM `ADDRESSBOOK` WHERE `name`=? limit 0,1",search_name).Scan(&u.ID,&u.Name,&u.Address,&u.Memo,&u.Created); err != nil {
		//panic(err)
		errmsg:=[]byte(fmt.Sprintf(`{"error": "%s"}`,err))
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(errmsg)
		return
	}
	fmt.Printf("id: %d, name: %s address: %s memo: %s \n", u.ID, u.Name,u.Address,u.Memo)
	respondWithJSON(w, http.StatusOK, u)
}

//XSS
//ハンドラ
func XSShandler(
	//レスポンスを書き込む
	w http.ResponseWriter,
	//リクエスト
	r *http.Request) {
		//入力された文字列
		value_xss := r.FormValue("name")
		if value_xss==""{
			http.Redirect(w, r, "/xss?name=test", 302)
		}
		form:=`<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<title>XSSテスト</title>
<link rel ="stylesheet" type="text/css" href="./vuln.css" title="style">
</head>
<body>
<div class="title">XSSなWebサイト</div>
<div class="box">
ようこそ`+value_xss+`さん！<br>
<img src="harada.jpg">
</div>
<input id="menu-cb" type="checkbox" value="off">
<label id="menu-icon" for="menu-cb">≡</label>
<label id="menu-background" for="menu-cb"></label>
<div id="ham-menu">
    <ul>
			<li><a href="/sqli_name">SQLインジェクション1</a><br></li>
			<li><a href="/nosqli_name">SQLインジェクション1できない版</a><br></li>
			<li><a href="/sqli_id">SQLインジェクション2</a><br></li>
			<li><a href="/nosqli_id">SQLインジェクション2できない版</a><br></li>
			<li><a href="/xss">XSS(GET)</a><br></li>
			<li><a href="/noxss">XSSできない版</a><br></li>
			<li><a href="/hredirect?redirect=/">オープンリダイレクト1</a><br></li>
			<li><a href="/redirect?redirect=/">オープンリダイレクト2</a><br></li>
			<li><a href="/ping1">安全でないコマンド実行</a><br></li>
			<li><a href="/ping2">たぶん安全なコマンド実行</a><br></li>
			<li><a href="/readfile">ディレクトリトラバーサル</a><br></li>
			<li><a href="/notraversal">ディレクトリトラバーサルできないファイル読み込み</a><br></li>
			<li><a href="/ssrf1">SSRF</a><br></li>
			<li><a href="/jwt">JSON Web Token</a><br></li>
    </ul>
</div>
</body>
</html>
`
 		fmt.Fprint(w, form)
}

func noXSShandler(
	//レスポンスを書き込む
	w http.ResponseWriter,
	//リクエスト
	r *http.Request) {
		//入力された文字列
		value_xss := r.FormValue("name")
		if value_xss==""{
			http.Redirect(w, r, "/noxss?name=test", 302)
		}
		form:=`<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8" />
<title>XSSテスト</title>
<link rel ="stylesheet" type="text/css" href="./vuln.css" title="style">
</head>
<body>
<div class="title">XSSが起きないWebサイト</div>
<div class="box">
ようこそ`+html.EscapeString(value_xss)+`さん！<br>
<img src="harada.jpg">
</div>
<input id="menu-cb" type="checkbox" value="off">
<label id="menu-icon" for="menu-cb">≡</label>
<label id="menu-background" for="menu-cb"></label>
<div id="ham-menu">
    <ul>
		<li><a href="/sqli_name">SQLインジェクション1</a><br></li>
		<li><a href="/nosqli_name">SQLインジェクション1できない版</a><br></li>
		<li><a href="/sqli_id">SQLインジェクション2</a><br></li>
		<li><a href="/nosqli_id">SQLインジェクション2できない版</a><br></li>
		<li><a href="/xss">XSS(GET)</a><br></li>
		<li><a href="/noxss">XSSできない版</a><br></li>
		<li><a href="/hredirect?redirect=/">オープンリダイレクト1</a><br></li>
		<li><a href="/redirect?redirect=/">オープンリダイレクト2</a><br></li>
		<li><a href="/ping1">安全でないコマンド実行</a><br></li>
		<li><a href="/ping2">たぶん安全なコマンド実行</a><br></li>
		<li><a href="/readfile">ディレクトリトラバーサル</a><br></li>
		<li><a href="/notraversal">ディレクトリトラバーサルできないファイル読み込み</a><br></li>
		<li><a href="/ssrf1">SSRF</a><br></li>
		<li><a href="/jwt">JSON Web Token</a><br></li>
    </ul>
</div>
</body>
</html>
`
 		fmt.Fprint(w, form)
}

func headerRedirectHandler(w http.ResponseWriter, r *http.Request) {
	value_redirect := r.FormValue("redirect")
	if value_redirect!=""{
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("location", value_redirect)
		w.WriteHeader(http.StatusFound) // 301 Moved Permanently
	}
}
func RedirectHandler(w http.ResponseWriter, r *http.Request) {
	value_redirect := r.FormValue("redirect")
	if value_redirect!=""{
		http.Redirect(w, r, value_redirect, 302)
	}
}

func rcehandler(w http.ResponseWriter,r *http.Request) {
	value_rce := r.FormValue("host")

	if value_rce!=""{
		host :=html.EscapeString(value_rce)
		out, _ := exec.Command("bash", "-c", "ping -c 5 "+host).CombinedOutput()
		//fmt.Println(strings.Replace(string(out), "\n", "\\n", -1))
		//結果をjsonにして送信
		//outは[]byteなのでキャストしてからエスケープしてまたキャスト
		msg:=[]byte(fmt.Sprintf(`{"msg": "%s"}`,strings.Replace(string(out), "\n", "\\n", -1)))

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(msg)

	}
}

func norcehandler(w http.ResponseWriter,r *http.Request) {
	value_rce := r.FormValue("host")

	if value_rce!=""{
		host :=html.EscapeString(value_rce)
		out, _ := exec.Command("ping", "-c 5", host).CombinedOutput()
		//fmt.Println(strings.Replace(string(out), "\n", "\\n", -1))
		//結果をjsonにして送信
		//outは[]byteなのでキャストしてからエスケープしてまたキャスト
		msg:=[]byte(fmt.Sprintf(`{"msg": "%s"}`,strings.Replace(string(out), "\n", "\\n", -1)))

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(msg)

	}
}

func traversalhandler(w http.ResponseWriter,r *http.Request) {
	value_file := r.FormValue("file")
	if value_file!=""{
		data, err := ioutil.ReadFile("./data/"+value_file)
		if err != nil {
			// エラー処理
			fmt.Println(err)
			msg:=[]byte(fmt.Sprintf(`%s`,err))

			w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(msg)
			return
    }
		//結果はそのまま送信
		w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}
//SSRF GET版
func getSSRFhandler(w http.ResponseWriter,r *http.Request) {
		//入力された文字列
	url := r.FormValue("url")
	//var url string = "http://bogus.jp/img1.jpg"
	if url !=""{
		response, err := http.Get(url)
		//基本URLエンコードされる
		//Get file:///etc/passwd: unsupported protocol scheme "file"
		//Get ftp:///etc/passwd: unsupported protocol scheme "ftp"
		if err != nil {
			msg:=[]byte(fmt.Sprintf(`{"file": "%s"}`,"no file"))
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(msg)
			return
		}
		defer response.Body.Close()
		now := time.Now().Unix()
    n := strconv.FormatInt(now, 10)
		//排他制御すべき
		filename:=fmt.Sprintf(`./images/%s.jpg`,n)
		file, err := os.Create(filename)

		if err != nil {
			panic(err)
		}
		defer file.Close()
		io.Copy(file, response.Body)
		msg:=[]byte(fmt.Sprintf(`{"file": "%s"}`,filename))
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(msg)
	}
}

//SSRF GET版
func requestSSRFhandler(w http.ResponseWriter,r *http.Request) {
		//入力された文字列
	url := r.FormValue("url")
	//var url string = "http://bogus.jp/img1.jpg"
	if url !=""{
		client := &http.Client{
		}
		req, err := http.NewRequest("GET", url, nil)
		response, err := client.Do(req)
		//基本URLエンコードされる
		//Get file:///etc/passwd: unsupported protocol scheme "file"
		//Get ftp:///etc/passwd: unsupported protocol scheme "ftp"
		if err != nil {
			msg:=[]byte(fmt.Sprintf(`{"file": "%s"}`,"no file"))
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			w.WriteHeader(http.StatusBadRequest)
			w.Write(msg)
			return
		}
		defer response.Body.Close()
		now := time.Now().Unix()
    n := strconv.FormatInt(now, 10)
		//排他制御すべき
		filename:=fmt.Sprintf(`./images/%s.jpg`,n)
		file, err := os.Create(filename)

		if err != nil {
			panic(err)
		}
		defer file.Close()
		io.Copy(file, response.Body)
		msg:=[]byte(fmt.Sprintf(`{"file": "%s"}`,filename))
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(msg)
	}
}

//脆弱なJSON Web Token
func jwttokenhandler(w http.ResponseWriter,r *http.Request) {
	token := jwt.New(jwt.GetSigningMethod("none")) // https://github.com/dgrijalva/jwt-go/pull/79/files
	token.Claims = jwt.MapClaims{
	  "user": "guest",
	  "exp":  time.Now().Add(time.Hour * 1).Unix(),
	}
//トークンに対して署名の付与
//tokenString, err := token.SignedString([]byte(secretKey))
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err == nil {
		token:=[]byte(fmt.Sprintf(`{"token": "%s"}`,tokenString))
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(token)
	} else {
		token:=[]byte(fmt.Sprintf(`{"error": "%s"}`,err))
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(token)
	}
}

func jwtprivatehandler(w http.ResponseWriter,r *http.Request) {
	//署名の検証
	token, err := request.ParseFromRequest(r, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
	b := jwt.UnsafeAllowNoneSignatureType
		return b, nil
	})

	if err == nil {
		//ユーザー情報
		claims := token.Claims.(jwt.MapClaims)
		msg := fmt.Sprintf("こんにちは、「 %s 」さん", claims["user"])
		token:=[]byte(fmt.Sprintf(`{"message": "%s"}`,msg))
		if claims["user"]=="flag"{
			token=[]byte(`{"flag": "flag_JSON_WEB_TOKEN_none"}`)
		}
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(token)

	} else {
		token:=[]byte(fmt.Sprintf(`{"error": "%s"}`,err))
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(token)
	}
}
