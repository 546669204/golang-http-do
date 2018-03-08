package httpdo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/axgle/mahonia"
	//pcookie "github.com/juju/persistent-cookiejar"
)

var Autocookie = &Jar{
	entries: make(map[string]map[string]entry),
}

var Autocookieflag = false

var Debug = false

type option struct {
	Method      string
	Url         string
	Data        interface{}
	Cookies     string
	Proxystr    string
	Overtime    int
	Header      string
	Printreq    bool
	Printresp   bool
	PrintStatus bool
}

func Default() option {
	return option{
		Method:      "GET",
		Url:         "",
		Data:        "",
		Cookies:     "",
		Proxystr:    "",
		Overtime:    30,
		Header:      "",
		Printreq:    false,
		Printresp:   false,
		PrintStatus: false,
	}
}
func HttpDo(o option) ([]byte, error) {
	if o.Overtime == 0 {
		o.Overtime = 30
	}
	o.Method = strings.ToUpper(o.Method)
	client := &http.Client{}
	transport := &http.Transport{
		Dial: func(netw, addr string) (net.Conn, error) {
			deadline := time.Now().Add(time.Duration(o.Overtime) * time.Second)
			c, err := net.DialTimeout(netw, addr, time.Second*time.Duration(o.Overtime))
			if err != nil {
				return nil, err
			}
			c.SetDeadline(deadline)
			return c, nil
		},
		//TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},//跳过效验证书
	}
	if o.Proxystr != "" {
		urli := url.URL{}
		proxy, _ := urli.Parse(strings.ToLower(o.Proxystr))
		transport.Proxy = http.ProxyURL(proxy)
	}
	if Autocookieflag == true {
		client.Jar = Autocookie
	}
	client.Transport = transport

	var ReqData []byte
	switch reflect.TypeOf(o.Data).String() {
	case "string":
		ReqData = []byte(o.Data.(string))
		break
	default:
		ReqData = o.Data.([]uint8)
		break
	}
	req, err := http.NewRequest(o.Method, o.Url, bytes.NewReader(ReqData))
	if err != nil {
		return []byte("http.NewRequest ERROR"), err
	}
	req.Header.Add("User-Agent", `User-Agent,Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36`)

	if o.Method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if o.Cookies != "" {
		req.Header.Set("Cookie", o.Cookies)
	}

	if o.Header != "" {
		array := strings.Split(o.Header, "\n")
		for index := 0; index < len(array); index++ {
			elm := array[index]
			si := strings.Index(elm, ":")
			if si >= 0 {
				req.Header.Set(string([]byte(elm)[:si]), string([]byte(elm)[si+1:]))
			}
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return []byte("client.Do ERROR"), err
	}
	defer resp.Body.Close()

	if o.Printreq {
		log.Printf("%s\n", req.Header)
	}
	if o.Printresp {
		log.Printf("%s\n", resp.Header)
	}
	if o.PrintStatus {
		log.Printf("%s\n", resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if Debug {
		file, _ := os.OpenFile("httpdo.log", os.O_APPEND|os.O_CREATE, 0664)
		defer file.Close()
		file.WriteString(fmt.Sprintf("======[START]===%s===\n\n%s  %s  %s\n%s\n%s\n\n%s  %s\n%s\n%s\n\n======[END]======\n\n\n", time.Now().Format("2006-01-02 15:04:05"), req.Method, req.URL, req.Proto, formatheader(req.Header), ReqData, resp.Status, resp.Proto, formatheader(resp.Header), body))
	}

	if strings.Index(resp.Status, "200") != -1 {

		if _, ok := resp.Header["Content-Type"]; ok {
			ContentType := resp.Header["Content-Type"][0]
			if err != nil {
				return []byte("ioutil.ReadAll ERROR"), err
			}
			if strings.Contains(ContentType, "text/html") {
				charset := (GetBetweenStr(ContentType, "charset=", ""))
				if charset == "" || charset == ContentType {
					charset = (GetBetweenStr(string(body), "charset=", "\""))
					if charset == "" {
						charset = "UTF-8"
					}
				}
				if strings.ToLower(charset) == "gb2312" {
					charset = "GBK"
				}
				if strings.Contains("GBKUTF-8", charset) {
					dec := mahonia.NewDecoder(charset)
					return []byte(dec.ConvertString(string(body))), nil
				}
				return body, nil
			} else if strings.Contains(ContentType, "text/css") {
				charset := (GetBetweenStr(string(body), "charset \"", "\""))
				if charset == "" {
					charset = "utf-8"
				}
				dec := mahonia.NewDecoder(charset)
				return []byte(dec.ConvertString(string(body))), nil
			} else {
				return body, nil
			}
		} else {
			return body, nil
		}

	} else {
		var err error = errors.New(resp.Status)
		return []byte("非200ERROR"), err
	}

}

func GetBetweenStr(str, start, end string) string {
	n, m := 0, 0

	if start != "" {
		n = strings.Index(str, start)
		if n == -1 {
			return ""
		} else {
			str = string([]byte(str)[n+len(start):])
		}
	}

	if end == "" {
		m = len(str)
	} else {
		m = strings.Index(str, end)
		if m == -1 {
			return ""
		}
	}
	str = string([]byte(str)[:m])
	return str
}

func SaveCookies() {
	file, err := os.OpenFile("cookie.data", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0)
	if err != nil {
		log.Println(err)
	}
	defer file.Close()

	jsonbyte, _ := json.Marshal(Autocookie.entries)
	file.Write(jsonbyte)
	return
}

func LoadCookies() {
	var entries = make(map[string]map[string]entry)
	_, err := os.OpenFile("cookie.data", os.O_RDWR, 0)
	if os.IsNotExist(err) {
		return
	}
	filebyte, _ := ioutil.ReadFile("cookie.data")
	if err := json.Unmarshal(filebyte, &entries); err != nil {
		log.Println(err)
		return
	}
	Autocookie.entries = entries
}

func GetAllCookies() string {
	jsonbyte, _ := json.Marshal(Autocookie.entries)
	return string(jsonbyte)
}

func formatheader(h http.Header) string {
	var str = ""
	for i, k := range h {
		str = str + fmt.Sprintf("%s : %s\n", i, k)
	}
	return str
}
