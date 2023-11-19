package option

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"strings"
)

type Log struct {
	gorm.Model
	Method        string
	IP            string
	RemoteIp      string
	URL           string
	Proto         string
	Header        string
	ContentLength int64
	RequestURI    string
}

func (core *Core) LogMiddleware(c *gin.Context) {
	var headersList []string
	for name, values := range c.Request.Header {
		for _, value := range values {
			headersList = append(headersList, fmt.Sprintf(`{"%s": "%s"}`, name, value))
		}
	}
	header := fmt.Sprintf("[%s]", strings.Join(headersList, ", "))
	logObj := Log{
		Method:        c.Request.Method,
		IP:            c.ClientIP(),
		RemoteIp:      c.RemoteIP(),
		URL:           c.Request.URL.RequestURI(),
		Proto:         c.Request.Proto,
		Header:        header,
		ContentLength: c.Request.ContentLength,
		RequestURI:    c.Request.RequestURI,
	}
	fmt.Sprintf("", logObj)
	//err := l.Postgre.CreateRLog(&log)
	//if err != nil {
	//	logger.Println(fmt.Sprintf("Log middleware error: %s", err))
	//}
	//log.Println(logObj)
	c.Next()
}
