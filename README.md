# golang-http-do
模拟表单 GET POST 提交基于golang


把常用的模拟http提交函数 拎出来 方便维护 调用


#demo 

```
op := httpdo.Default()
op.Url = fmt.Sprintf(`http://www.baidu.com`, d)
op.Header = `referer: https://www.baidu.com\ncookie: ssid=1465qw7e9wq87ewqew`
httpbyte, err := httpdo.HttpDo(op)
if err != nil {
    log.Println(err)
}
log.Println(string(httpbyte))
```