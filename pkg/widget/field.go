package widget

import (
	"strings"
	"time"
)

type Field struct {
	Field    string `json:"field"` // field type name
	Tag      string `json:"tag"`
	Blank    bool   `json:"blank"`     // can be nil
	ReadOnly bool   `json:"read_only"` // allow to change
	Editable bool   `json:"editable"`  // allow to edite
	HelpText string `json:"help_text"`
	Unique   bool   `json:"unique"`
}

func (f Field) GetTagAndField() (string, string) {
	return f.Tag, f.Field
}

const (
	blankStg    = "blank"
	readOnlyStg = "read_only"
	editableStg = "editable"
	uniqueStg   = "unique"
)

// Auto field

const fieldAuto = "auto_field"

type FieldAuto struct {
	Field
	Default int  `json:"default"`
	Name    Name `json:"name"`
	Val     int  `json:"val"`
}

func buildFieldAuto(Tag string, Name Name, Default int, Val uint64, stg string) (res FieldAuto) {
	// TODO
	blank := true
	readOnly := true
	editable := false
	unique := true
	if strings.Contains(stg, blankStg) {
		blank = true
	}
	if strings.Contains(stg, readOnlyStg) {
		readOnly = true
	}
	if strings.Contains(stg, editableStg) {
		editable = true
	}
	if strings.Contains(stg, uniqueStg) {
		unique = true
	}

	res.Field = Field{
		Field:    fieldAuto,
		Tag:      Tag,
		Blank:    blank,
		ReadOnly: readOnly,
		Editable: editable,
		HelpText: "", // TODO
		Unique:   unique,
	}
	res.Name = Name
	res.Default = Default
	res.Val = int(Val)
	return res
}

// Date time

const fieldDateTime = "date_time_field"

type FieldDateTime struct {
	Field
	Default string `json:"default"`
	Name    Name   `json:"name"`
	Val     string `json:"val"`
}

func buildFieldDateTime(Tag string, Name Name, Default *time.Time, Val any, stg string) (res FieldDateTime) {
	// TODO
	blank := true
	readOnly := true
	editable := false
	unique := true
	if strings.Contains(stg, blankStg) {
		blank = true
	}
	if strings.Contains(stg, readOnlyStg) {
		readOnly = true
	}
	if strings.Contains(stg, editableStg) {
		editable = true
	}
	if strings.Contains(stg, uniqueStg) {
		unique = true
	}

	res.Field = Field{
		Field:    fieldDateTime,
		Tag:      Tag,
		Blank:    blank,
		ReadOnly: readOnly,
		Editable: editable,
		HelpText: "", // TODO
		Unique:   unique,
	}
	res.Name = Name
	res.Default = Default.Format("2006-01-02 15:04:05.00000-07")
	res.Val = Val.(time.Time).Format("2006-01-02 15:04:05.00000-07")
	return res
}

// Integer field

const intChar = "int_field"

type IntChar struct {
	Field
	Default int  `json:"default"`
	Name    Name `json:"name"`
	Val     int  `json:"val"`
}

func buildFieldInt(Tag string, Name Name, Default int, Val int, stg string) (res IntChar) {
	// TODO

	blank := true
	readOnly := true
	editable := true
	unique := true
	if strings.Contains(stg, blankStg) {
		blank = true
	}
	if strings.Contains(stg, readOnlyStg) {
		readOnly = true
	}
	if strings.Contains(stg, editableStg) {
		editable = true
	}
	if strings.Contains(stg, uniqueStg) {
		unique = true
	}

	res.Field = Field{
		Field:    intChar,
		Tag:      Tag,
		Blank:    blank,
		ReadOnly: readOnly,
		Editable: editable,
		HelpText: "", // TODO
		Unique:   unique,
	}
	res.Name = Name
	res.Default = Default
	res.Val = Val
	return res
}

// Char field

const fieldChar = "char_field"

type FieldChar struct {
	Field
	Default string `json:"default"`
	Name    Name   `json:"name"`
	Val     string `json:"val"`
}

func buildFieldChar(Tag string, Name Name, Default string, Val string, stg string) (res FieldChar) {
	// TODO

	blank := true
	readOnly := true
	editable := true
	unique := true
	if strings.Contains(stg, blankStg) {
		blank = true
	}
	if strings.Contains(stg, readOnlyStg) {
		readOnly = true
	}
	if strings.Contains(stg, editableStg) {
		editable = true
	}
	if strings.Contains(stg, uniqueStg) {
		unique = true
	}

	res.Field = Field{
		Field:    fieldChar,
		Tag:      Tag,
		Blank:    blank,
		ReadOnly: readOnly,
		Editable: editable,
		HelpText: "", // TODO
		Unique:   unique,
	}
	res.Name = Name
	res.Default = Default
	res.Val = string(Val)
	return res
}

// bool field

const fieldBool = "bool_field"

type FieldBool struct {
	Field
	Default bool `json:"default"`
	Name    Name `json:"name"`
	Val     bool `json:"val"`
}

func buildFieldBool(Tag string, Name Name, Default bool, Val bool, stg string) (res FieldBool) {
	// TODO

	blank := true
	readOnly := true
	editable := true
	unique := true
	if strings.Contains(stg, blankStg) {
		blank = true
	}
	if strings.Contains(stg, readOnlyStg) {
		readOnly = true
	}
	if strings.Contains(stg, editableStg) {
		editable = true
	}
	if strings.Contains(stg, uniqueStg) {
		unique = true
	}

	res.Field = Field{
		Field:    fieldBool,
		Tag:      Tag,
		Blank:    blank,
		ReadOnly: readOnly,
		Editable: editable,
		HelpText: "", // TODO
		Unique:   unique,
	}
	res.Name = Name
	res.Default = Default
	res.Val = Val
	return res
}

// slice

const fieldSlice = "list_field"

type FieldSlice struct {
	Field
	SliceField string `json:"list_field"`
	Blank      bool   `json:"blank"`
	ReadOnly   bool   `json:"read_only"`
	Editable   bool   `json:"editable"`
	HelpText   string `json:"help_text"`
	Unique     bool   `json:"unique"`
	Name       Name   `json:"name"`
	Val        any    `json:"val"`
}

func buildFieldSlice(Tag string, Name Name, Type string, Val any, stg string) (res FieldSlice) {
	// TODO
	blank := true
	readOnly := true
	editable := true
	unique := true
	if strings.Contains(stg, blankStg) {
		blank = true
	}
	if strings.Contains(stg, readOnlyStg) {
		readOnly = true
	}
	if strings.Contains(stg, editableStg) {
		editable = true
	}
	if strings.Contains(stg, uniqueStg) {
		unique = true
	}

	res.Field = Field{
		Field:    fieldSlice,
		Tag:      Tag,
		Blank:    blank,
		ReadOnly: readOnly,
		Editable: editable,
		HelpText: "", // TODO
		Unique:   unique,
	}
	res.SliceField = Type
	res.Name = Name
	res.Val = Val
	return res
}

// sub form

const fieldSubForm = "sub_form_field"

type FieldSubForm struct {
	Field
	//	TODO
}

// TODO
