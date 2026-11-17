package main

import (
	"strings"
)

func singleJoin(basePath, reqPath string) string {
	if basePath == "" || basePath == "/" {
		return reqPath
	}
	if strings.HasSuffix(basePath, "/") && strings.HasPrefix(reqPath, "/") {
		return basePath + strings.TrimPrefix(reqPath, "/")
	}
	if !strings.HasSuffix(basePath, "/") && !strings.HasPrefix(reqPath, "/") {
		return basePath + "/" + reqPath
	}
	return basePath + reqPath
}
