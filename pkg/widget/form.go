package widget

import (
	"fmt"
	"gorm.io/gorm"
	"log"
	"reflect"
	"time"
)

// FormWidget built-in function of option package,
// return map with the basic json struct for option form widget
//
//	model - option.Model inheritor
//	stg - settings map, for each field different settings
func FormWidget(model interface{}) *[]any {
	form := []any{}
	m := reflect.TypeOf(model).Elem()
	v := reflect.ValueOf(model).Elem()
	if m.Kind() != reflect.Struct {
		log.Println(fmt.Sprintf("%v type can't have attributes inspected", m.Kind()))
		return nil
	}
	for i := 0; i < m.NumField(); i++ {
		field := m.Field(i)
		val := v.Field(i)
		formField(field, val, &form)
	}
	return &form
}

func formField(field reflect.StructField, val reflect.Value, res *[]any) {
	name := Name{
		ENG: field.Name,
		LNG: field.Name,
	}
	stg := field.Tag.Get("option")
	tag, ok := field.Tag.Lookup("json")
	if !ok {
		tag = field.Name
	}
	switch {
	// TODO add more field types
	case field.Name == "ID":
		(*res) = append(*res, buildFieldAuto(tag, name, 0, val.Uint(), stg))
	case field.Type.Kind() == reflect.String:
		(*res) = append(*res, buildFieldChar(tag, name, "", val.String(), stg))
	case field.Type.Kind() == reflect.Int:
		(*res) = append(*res, buildFieldInt(tag, name, 0, int(val.Int()), stg))
	case field.Type.Kind() == reflect.Uint:
		(*res) = append(*res, buildFieldInt(tag, name, 0, int(val.Uint()), stg))
	case field.Type.String() == "time.Time":
		timeDefault := time.Unix(0, 0)
		(*res) = append(*res, buildFieldDateTime(tag, name, &timeDefault, val.Interface(), stg))
	case field.Type.String() == "gorm.DeletedAt":
		timeDefault := time.Unix(0, 0)
		(*res) = append(*res, buildFieldDateTime(tag, name, &timeDefault, val.Interface().(gorm.DeletedAt).Time, stg))
	case field.Type.Kind() == reflect.Struct:
		if field.Type.String() == "option.Model" {
			mm := reflect.TypeOf(val.Interface())
			vv := reflect.ValueOf(val.Interface())
			for j := 0; j < mm.NumField(); j++ {
				mmField := mm.Field(j)
				vvVal := vv.Field(j)
				formField(mmField, vvVal, res)
			}
		} else {
			log.Println(fmt.Sprintf("Unsupported struct %s - %s", field.Name, field.Type))
		}
	default:
		log.Println(fmt.Sprintf("Unsupported type %s - %s", field.Name, field.Type))
	}
	return
}

func FormContentType(model interface{}) (*map[string]string) {
	type interf interface {
		GetTagAndField() (string, string)
	}
	res := &map[string]string{}

	form := FormWidget(model)
	for _, v := range *form {
		key, val := v.(interf).GetTagAndField()
		(*res)[key] = val
	}

	return res
}
