package main

import (
	"strings"
	"net/http"
	"net/http/httptest"
	"testing"
//	"io/ioutil"
	"fmt"
	"os"
	"encoding/json"
)

var a App
func TestMain(m *testing.M) {
    a = App{}
		a.Initialize()
    //ensureTableExists()
    code := m.Run()
    //clearTable()
    os.Exit(code)
}

func executeRequest(req *http.Request) *httptest.ResponseRecorder {
    rr := httptest.NewRecorder()
    a.Router.ServeHTTP(rr, req)

    return rr
}
func checkResponseCode(t *testing.T, expected, actual int) {
    if expected != actual {
        t.Errorf("Expected response code %d. Got %d\n", expected, actual)
    }
}
//SQLインジェクション脆弱性
//存在しない値
func TestSQLi_noID(t *testing.T) {
    req, _ := http.NewRequest("GET", "/sqli/id/6", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusBadRequest, response.Code)
		var m map[string]string
		//返ってきたエラーメッセージをチェック
		json.Unmarshal(response.Body.Bytes(), &m)
		if m["error"] != "sql: no rows in result set" {
				t.Errorf("Expected the 'error' key of the response to be set to 'sql: no rows in result set'. Got '%s'", m["error"])
		}
}

//存在する値
func TestSQLi_ID(t *testing.T) {
    req, _ := http.NewRequest("GET", "/sqli/id/5", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusOK, response.Code)
		//string型のmap
		var m map[string]string
		json.Unmarshal(response.Body.Bytes(), &m)
		//なのでstring型しかmapされない
		fmt.Println(m)
		//string
		if m["name"] != "admin" {
				t.Errorf("Expected the 'id' key of the response to be set to '5'. Got '%s'", m["id"])
		}
}
//存在する値
func TestSQLi_ID_sqli(t *testing.T) {
    req, _ := http.NewRequest("GET", "/sqli/id/6-1", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusOK, response.Code)
		//string型のmap
		var m map[string]string
		json.Unmarshal(response.Body.Bytes(), &m)
		//なのでstring型しかmapされない
		fmt.Println(m)
		//string
		if m["name"] != "admin" {
				t.Errorf("Expected the 'id' key of the response to be set to '5'. Got '%s'", m["id"])
		}
}

//存在しない値
func TestNOSQLi_noID(t *testing.T) {
    req, _ := http.NewRequest("GET", "/nosqli/id/6", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusBadRequest, response.Code)
		var m map[string]string
		//返ってきたエラーメッセージをチェック
		json.Unmarshal(response.Body.Bytes(), &m)
		if m["error"] != "sql: no rows in result set" {
				t.Errorf("Expected the 'error' key of the response to be set to 'sql: no rows in result set'. Got '%s'", m["error"])
		}
}
//存在する値
func TestNOSQLi_ID(t *testing.T) {
	req, _ := http.NewRequest("GET", "/nosqli/id/5", nil)
	response := executeRequest(req)
	//レスポンスコードがOKだと
	checkResponseCode(t, http.StatusOK, response.Code)
	//string型のmap
	var m map[string]string
	json.Unmarshal(response.Body.Bytes(), &m)
	//なのでstring型しかmapされない
	fmt.Println(m)
	//string
	if m["name"] != "admin" {
		t.Errorf("Expected the 'id' key of the response to be set to '5'. Got '%s'", m["id"])
	}
}
//存在する値
func TestNOSQLi_ID_sqli(t *testing.T) {
	req, _ := http.NewRequest("GET", "/nosqli/id/6-1", nil)
	response := executeRequest(req)
	//レスポンスコードがOKだと
	checkResponseCode(t, http.StatusBadRequest, response.Code)
	var m map[string]string
	//返ってきたエラーメッセージをチェック
	json.Unmarshal(response.Body.Bytes(), &m)
	if m["error"] != "sql: no rows in result set" {
		t.Errorf("Expected the 'error' key of the response to be set to 'sql: no rows in result set'. Got '%s'", m["error"])
	}
}
//文字列ベース
//存在しない値
func TestSQLi_noName(t *testing.T) {
    req, _ := http.NewRequest("GET", "/sqli/user", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusBadRequest, response.Code)
		var m map[string]string
		//返ってきたエラーメッセージをチェック
		json.Unmarshal(response.Body.Bytes(), &m)
		if m["error"] != "sql: no rows in result set" {
				t.Errorf("Expected the 'error' key of the response to be set to 'sql: no rows in result set'. Got '%s'", m["error"])
		}
}
//存在する値
func TestSQLi_withName(t *testing.T) {
    req, _ := http.NewRequest("GET", "/sqli/admin", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusOK, response.Code)
		//string型のmap
		var m map[string]string
		json.Unmarshal(response.Body.Bytes(), &m)
		//なのでstring型しかmapされない
		fmt.Println(m)
		//string
		if m["name"] != "admin" {
				t.Errorf("Expected the 'id' key of the response to be set to '5'. Got '%s'", m["id"])
		}
}
//SQLインジェクション脆弱性
func TestSQLi_Name_sqli(t *testing.T) {
    req, _ := http.NewRequest("GET", "/sqli/ad'||'min", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusOK, response.Code)
		//string型のmap
		var m map[string]string
		json.Unmarshal(response.Body.Bytes(), &m)
		//なのでstring型しかmapされない
		fmt.Println(m)
		//string
		if m["name"] != "admin" {
				t.Errorf("Expected the 'id' key of the response to be set to '5'. Got '%s'", m["id"])
		}
}

//存在しない値
func TestNOSQLi_noName(t *testing.T) {
    req, _ := http.NewRequest("GET", "/nosqli/user", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusBadRequest, response.Code)
		var m map[string]string
		//返ってきたエラーメッセージをチェック
		json.Unmarshal(response.Body.Bytes(), &m)
		if m["error"] != "sql: no rows in result set" {
				t.Errorf("Expected the 'error' key of the response to be set to 'sql: no rows in result set'. Got '%s'", m["error"])
		}
}
//存在する値
func TestNOSQLi_withName(t *testing.T) {
    req, _ := http.NewRequest("GET", "/nosqli/admin", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusOK, response.Code)
		//string型のmap
		var m map[string]string
		json.Unmarshal(response.Body.Bytes(), &m)
		//なのでstring型しかmapされない
		fmt.Println(m)
		//string
		if m["name"] != "admin" {
				t.Errorf("Expected the 'id' key of the response to be set to '5'. Got '%s'", m["id"])
		}
}
//SQLインジェクション脆弱性
func TestSNOQLi_Name_sqli(t *testing.T) {
    req, _ := http.NewRequest("GET", "/nosqli/ad'||'min", nil)
		response := executeRequest(req)
		//レスポンスコードがOKだと
		checkResponseCode(t, http.StatusBadRequest, response.Code)
		var m map[string]string
		//返ってきたエラーメッセージをチェック
		json.Unmarshal(response.Body.Bytes(), &m)
		if m["error"] != "sql: no rows in result set" {
			t.Errorf("Expected the 'error' key of the response to be set to 'sql: no rows in result set'. Got '%s'", m["error"])
		}
}


func TestXSS(t *testing.T) {
	// テスト用のリクエスト作成
	w := httptest.NewRecorder()
	// テスト用のレスポンス作成
	body := "name=<script>alert(1)</script>"
	r := httptest.NewRequest("POST", "/xss", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	XSShandler(w, r)

	rw := w.Result()
	defer rw.Body.Close()

	if rw.StatusCode != http.StatusOK {
		t.Fatal("unexpected status code")
	}
}

func TestNoXSS(t *testing.T) {
	// テスト用のリクエスト作成
	w := httptest.NewRecorder()
	// テスト用のレスポンス作成
	body := "name=<script>alert(2)</script>"
	r := httptest.NewRequest("POST", "/noxss", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	noXSShandler(w, r)

	rw := w.Result()
	defer rw.Body.Close()

	if rw.StatusCode != http.StatusOK {
		t.Fatal("unexpected status code")
	}
}
//オープンリダイレクト脆弱性
func TestHeaderRedirect(t *testing.T) {
    req, _ := http.NewRequest("GET", "/hredirect?redirect=http://bogus.jp", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusFound, response.Code)


}
func TestRedirect(t *testing.T) {
    req, _ := http.NewRequest("GET", "/redirect?redirect=http://bogus.jp", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusFound, response.Code)
}

//RCE
//通常動作
func TestRCE_normal(t *testing.T) {
    req, _ := http.NewRequest("GET", "/rce?rce=bogus.jp", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusOK, response.Code)
}
func TestRCE_ls(t *testing.T) {
    req, _ := http.NewRequest("GET", "/rce?rce=bogus.jp|ls", nil)
    response := executeRequest(req)
		//レスポンスコードがOKだと
    checkResponseCode(t, http.StatusOK, response.Code)
}
//ない版通常動作
func TestNORCE_normal(t *testing.T) {
	req, _ := http.NewRequest("GET", "/norce?rce=bogus.jp", nil)
	response := executeRequest(req)
	//レスポンスコードがOKだと
	checkResponseCode(t, http.StatusOK, response.Code)
}
//ない版で実行しようとするとエラーになるはず
func TestNORCE_ls(t *testing.T) {
	req, _ := http.NewRequest("GET", "/norce?rce=bogus.jp|ls", nil)
	response := executeRequest(req)
	//レスポンスコードがOKだと
	checkResponseCode(t, http.StatusOK, response.Code)
}

//ディレクトリトラバーサル
//とりあえず通常動作
func TestTraversal_normal(t *testing.T) {
	req, _ := http.NewRequest("GET", "/traversal?file=1", nil)
	response := executeRequest(req)
	//レスポンスコードがOKだと
	checkResponseCode(t, http.StatusOK, response.Code)
}
//とりあえず通常動作
func TestTraversal_hosts(t *testing.T) {
	req, _ := http.NewRequest("GET", "/traversal?file=../../../../../../../etc/hosts", nil)
	response := executeRequest(req)
	//レスポンスコードがOKだと
	fmt.Println(response)
	checkResponseCode(t, http.StatusOK, response.Code)
}

//SSRF
//とりあえず通常動作
func TestGETSSRF_normal(t *testing.T) {
	req, _ := http.NewRequest("GET", "/ssrfget?url=http%3A%2F%2Fbogus.jp%2Fimg1.jpg", nil)
	response := executeRequest(req)
	//レスポンスコードがOKだと
	checkResponseCode(t, http.StatusOK, response.Code)
}

//とりあえず通常動作
func TestRequestSSRF_normal(t *testing.T) {
	req, _ := http.NewRequest("GET", "/ssrfrequest?url=http%3A%2F%2Fbogus.jp%2Fimg1.jpg", nil)
	response := executeRequest(req)
	//レスポンスコードがOKだと
	checkResponseCode(t, http.StatusOK, response.Code)
}

//JSON Web Token
//とりあえず通常動作
func TestJWTtoken_normal(t *testing.T) {
	req, _ := http.NewRequest("GET", "/jwt/token", nil)
	response := executeRequest(req)
	//レスポンスコードがOKだと
	checkResponseCode(t, http.StatusOK, response.Code)
}
//ヘッダがないと401
func TestJWTprivate_normal(t *testing.T) {
	req, _ := http.NewRequest("GET", "/jwt/private", nil)
	response := executeRequest(req)
	//レスポンスコードがOKだと
	checkResponseCode(t, http.StatusUnauthorized, response.Code)
}
