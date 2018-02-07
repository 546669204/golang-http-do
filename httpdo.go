package httpdo

import (
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/axgle/mahonia"
)

var autocookie, _ = cookiejar.New(nil)
var Autocookieflag = false

type option struct {
	Method      string
	Url         string
	Data        string
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
	}
	if o.Proxystr != "" {
		urli := url.URL{}
		proxy, _ := urli.Parse(strings.ToLower(o.Proxystr))
		transport.Proxy = http.ProxyURL(proxy)
	}
	if Autocookieflag == true {
		client.Jar = autocookie
	}
	client.Transport = transport

	req, err := http.NewRequest(o.Method, o.Url, strings.NewReader(o.Data))
	if err != nil {
		return []byte("http.NewRequest ERROR"), err
	}
	req.Header.Add("accept", `text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8`)
	//req.Header.Add("accept-encoding", `gzip`)
	req.Header.Add("accept-language", `zh-CN,zh;q=0.8,en;q=0.6`)
	req.Header.Add("cache-control", `max-age=0`)
	req.Header.Add("upgrade-insecure-requests", `1`)
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

	if strings.Index(resp.Status, "200") != -1 {
		body, err := ioutil.ReadAll(resp.Body)
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
