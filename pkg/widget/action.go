package widget

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"log"
	"reflect"
)

type Action struct {
	Tag    string
	Name   map[string]string //[LNG KEY] name on language
	Func   func(c *gin.Context)
	Model  any
	Method string //`GET`/`POST`/`PUT` if anything else standard rout `GET`
	Query  bool
	Access string
}

const (
	actionLink    = "link"
	actionForm    = "form"
	actionRequest = "request"
)

type mmmm interface {
	gorm.Model
}

type ActionLink struct {
	ActionRes
	Val string `json:"val"`
}

type ActionForm struct {
	ActionRes
	RequestPath string `json:"request_path"`
	RequestType string `json:"request_type"` // `GET`/`POST`/`PUT`
	RequestForm []any  `json:"request_form"`
}

func ActionWidget(actions []Action) (res []any) {
	for _, action := range actions {
		if action.Model != nil {
			form := ActionFormNames(action.Model)
			if form == nil {
				form = &[]any{}
			}
			res = append(res, ActionForm{
				ActionRes: ActionRes{
					Type:  actionForm,
					Name:  Name{ENG: action.Tag, LNG: action.Tag},
					Query: action.Query,
				},
				RequestPath: action.Tag,
				RequestType: action.Method,
				RequestForm: *form,
			})
		} else {
			res = append(res, ActionLink{
				ActionRes: ActionRes{
					Type:  actionLink,
					Name:  Name{ENG: action.Tag, LNG: action.Tag},
					Query: action.Query,
				},
				Val: action.Tag,
			})
		}
	}
	return res
}

func ActionFormNames(model interface{}) *[]any {
	form := []any{}
	m := reflect.TypeOf(model)
	if m.Kind() == reflect.Ptr {
		m = m.Elem()
	}
	if m.Kind() != reflect.Struct {
		log.Println(fmt.Sprintf("%v type can't have attributes inspected", m.Kind()))
		return nil
	}
	for i := 0; i < m.NumField(); i++ {
		field := m.Field(i)
		tag, ok := field.Tag.Lookup("json")
		if !ok {
			tag = field.Name
		}
		form = append(form, tag)
	}
	return &form
}
