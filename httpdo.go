package httpdo

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"

	"github.com/axgle/mahonia"

	"net/url"
	"reflect"
	"strings"
	"time"
	//pcookie "github.com/juju/persistent-cookiejar"
)

var Autocookie = &Jar{
	entries: make(map[string]map[string]entry),
}

var Autocookieflag = false

var Debug = false
var SaveFileName string = "cookies.data"

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
	PrintRaw    bool
	Raw         *HttpdoRawModel
}
type HttpdoRawModel struct {
	Resp  http.Response
	Req   http.Request
	Relty []byte
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
		PrintRaw:    false,
		Raw:         new(HttpdoRawModel),
	}
}
func HttpDo(o option) (retbody []byte, reterr error) {
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

	var body []byte
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err := gzip.NewReader(resp.Body)
		defer reader.Close()
		if err != nil {
			retbody = []byte(err.Error())
			reterr = err
			goto ENDANDPRINT
		}
		body, err = ioutil.ReadAll(reader)
		if err != nil {
			retbody = []byte("ioutil.ReadAll ERROR")
			reterr = err
			goto ENDANDPRINT
		}
		break
	default:
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			retbody = []byte("ioutil.ReadAll ERROR")
			reterr = err
			goto ENDANDPRINT
		}
	}
	retbody = body
	reterr = nil

	if ContentType, ok := resp.Header["Content-Type"]; ok && len(ContentType) > 0 {
		charset := regexp.MustCompile("charset=\\w+$").FindStringSubmatch(ContentType[0])
		if len(charset) == 2 {
			dec := mahonia.NewDecoder(strings.ToLower(charset[1]))
			if dec != nil {
				retbody = []byte(dec.ConvertString(string(body)))
				reterr = nil
				goto ENDANDPRINT
			}
		}
	}

ENDANDPRINT:

	if o.PrintRaw {
		o.Raw.Req = *req
		o.Raw.Resp = *resp
		o.Raw.Relty = retbody
	}
	if Debug {
		file, _ := os.OpenFile("httpdo.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		defer file.Close()
		file.WriteString(fmt.Sprintf("======[START]===%s===\n\n%s  %s  %s\n%s\n%s\n\n%s  %s\n%s\n%s\n\n======[END]======\n\n\n", time.Now().Format("2006-01-02 15:04:05"), req.Method, req.URL, req.Proto, formatheader(req.Header), ReqData, resp.Status, resp.Proto, formatheader(resp.Header), retbody))
	}
	return
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
	file, err := os.OpenFile(SaveFileName, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0)
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
	_, err := os.OpenFile(SaveFileName, os.O_RDWR, 0)
	if os.IsNotExist(err) {
		return
	}
	filebyte, _ := ioutil.ReadFile(SaveFileName)
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
