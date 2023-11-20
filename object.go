package option

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/wawilow108/option/pkg/widget"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"time"
)

const (
	methodGet  = "GET"
	methodPost = "POST"
	methodPut  = "PUT"
)

type Model struct {
	ID        uint           `json:"id" gorm:"primarykey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

type AppGroup struct {
	Tag string

	SideBar       bool
	SideBarWeight int
}

type App struct {
	Tag      string
	Name     map[string]string //[LNG KEY] name on language
	Model    model
	Function []widget.Action

	Migration bool

	SideBar       bool
	SideBarWeight int

	//	Basic functions
	GetFunction    bool
	ListFunction   bool
	DeleteFunction bool
	UpdateFunction bool
}

type Form struct {
	Widget  string `json:"widget"`
	Object  string `json:"object"`
	Actions []any  `json:"actions"`
	Form    []any  `json:"form"`
}

func (app *App) CreateForm(form *[]any, actions *[]any) (res Form) {
	res.Widget = "form"
	res.Object = app.Tag
	res.Actions = *actions
	res.Form = *form
	return res
}

type List struct {
	Widget      string            `json:"widget"`
	Object      string            `json:"object"`
	Actions     []any             `json:"actions"`
	ContentType map[string]string `json:"content_type"`
	Content     any               `json:"content"`
	Pagination  ListPagination    `json:"pagination"`
}

type ListPagination struct {
	Pagination bool `json:"pagination"`
	Page       int  `json:"page"`
	Pages      int  `json:"pages"`
}

func (app *App) CreateList(actions []any, contentType map[string]string, content any, pagination ListPagination) (res List) {
	res.Widget = "form"
	res.Object = app.Tag
	res.Actions = actions
	res.ContentType = contentType
	res.Content = content
	res.Pagination = pagination
	return res
}

type model interface {
	ModelSave(core *Core, model *model, app App) func(c *gin.Context)
	ModelGet(core *Core, model *model, app App) func(c *gin.Context)
	ModelList(core *Core, model *model, app App) func(c *gin.Context)
	ModelDel(core *Core, model *model, app App) func(c *gin.Context)
}

// ModelSave
// {{connection}}/{{model_tag}}/{id}/save [POST]
// Success 200 Model
func (_ Model) ModelSave(core *Core, model *model, app App) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Get the params
		idString := c.Param("id")
		id, err := strconv.Atoi(idString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "bad id", Message: "Bad id"})
			return
		}

		err = c.Bind(*model)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "Bad json", Message: "Bad json"})
			return
		}
		if id != 0 {
			err = core.Session.Config.Database.PS.Db.Save(*model).Error
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "save error"})
				return
			}
		} else {
			err = core.Session.Config.Database.PS.Db.Create(*model).Error
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "save error"})
				return
			}
		}

		// Get back the function with result
		c.JSON(http.StatusOK, map[string]any{"model": model})
		return
	}
}

// ModelList
// {{connection}}/{{model_tag}}/ [GET]
// Success 200
func (_ Model) ModelList(core *Core, model *model, app App) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Get actions
		act := widget.ActionWidget(app.Function)
		if act == nil {
			act = []any{}
		}
		contentType := widget.FormContentType(*model)
		if contentType == nil {
			contentType = &map[string]string{}
		}

		// Create list of app type
		list := reflect.MakeSlice(reflect.SliceOf(reflect.TypeOf(app.Model)), 0, 0).Interface()
		err := core.Session.Config.Database.PS.Db.Find(&list).Error
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "not found", Message: fmt.Sprintf("Not found, perhaps %d doen't exist?")})
			return
		}

		res := app.CreateList(act, *contentType, list, ListPagination{})

		c.JSON(http.StatusOK, res)
		return
	}
}

// ModelDel
// {{connection}}/{{model_tag}}/del [POST]
// Params []id
// Success 200
func (_ Model) ModelDel(core *Core, model *model, app App) func(c *gin.Context) {
	return func(c *gin.Context) {
		ids := []uint{}
		err := c.Bind(&ids)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "man, are u dull?"})
			return
		}
		for _, id := range ids {
			err = core.Session.Config.Database.PS.Db.Delete(model, id).Error
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{"Delete error", "Delete error"})
				return
			}
		}
		c.JSON(http.StatusOK, ids)
		return
	}
}

// ModelGet
// {{connection}}/{{model_tag}}/{id}/get [GET]
// Success 200 Model
func (_ Model) ModelGet(core *Core, model *model, app App) func(c *gin.Context) {
	return func(c *gin.Context) {
		// Get the params
		idString := c.Param("id")
		id, err := strconv.Atoi(idString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "bad id", Message: "Bad id"})
			return
		}

		if id != 0 {
			// Get the value
			core.Session.Config.Database.PS.Db.Statement.RaiseErrorOnNotFound = true
			err = core.Session.Config.Database.PS.Db.Preload(clause.Associations).Find(model, id).Error
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "not found", Message: fmt.Sprintf("Not found, perhaps %d doen't exist?", id)})
				return
			}
		}

		form := widget.FormWidget(*model)
		if form == nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "form error", Message: fmt.Sprintf("Form error, perhaps %d doen't exist?", id)})
			return
		}
		act := widget.ActionWidget(app.Function)
		if act == nil {
			act = []any{}
		}
		res := app.CreateForm(form, &act)
		// Get back the function with result
		c.JSON(http.StatusOK, res)
		return
	}
}

func (core *Core) Migrate(app App) (err error) {
	err = core.Session.Config.Database.PS.Db.AutoMigrate(
		&app.Model,
	)
	if err != nil {
		log.Print("Migration", app.Tag, "error: ", err)
		return err
	}

	log.Print("Migration", app.Tag, "success")
	return err
}

func (core *Core) Serve(app App) (err error) {
	for _, bl := range core.ActiveTag {
		if app.Tag == bl {
			return errors.New("bad tag")
		}
	}

	if app.DeleteFunction {
		const delTag = "del"

		//// Add permission
		//permission := fmt.Sprintf("%s_%s", app.Tag, delTag)
		//_, ok := AuthSuperUserPermissions(core)[permission]
		//if !ok {
		//	core.Permissions = append(core.Permissions, permission)
		//}

		type delModel struct {
			ID uint `json:"id"`
		}
		app.Function = append(app.Function, widget.Action{
			Tag:    delTag,
			Name:   map[string]string{"ENG": "Delete"},
			Model:  delModel{},
			Method: methodPost,
			Query:  true,
			Access: fmt.Sprintf("%s-%s", app.Tag, delTag),
			Func:   app.Model.ModelDel(core, &app.Model, app),
		})
		//core.Router.GET(fmt.Sprintf("api/v1/%s/del", app.Tag), ModelDel(core, &app.Model, app))
	}

	if app.GetFunction {
		const getTag = "get"

		// Add permission
		permission := fmt.Sprintf("%s_%s", app.Tag, getTag)
		_, ok := AuthSuperUserPermissions(core)[permission]
		if !ok {
			core.Permissions = append(core.Permissions, permission)
		}

		core.Router.GET(fmt.Sprintf("api/v1/%s/:id/get", app.Tag), app.Model.ModelGet(core, &app.Model, app))
	}
	if app.ListFunction {
		const getTag = "get"

		// Add permission
		permission := fmt.Sprintf("%s_%s", app.Tag, getTag)
		_, ok := AuthSuperUserPermissions(core)[permission]
		if !ok {
			core.Permissions = append(core.Permissions, permission)
		}

		core.Router.GET(fmt.Sprintf("api/v1/%s/list", app.Tag), app.Model.ModelList(core, &app.Model, app))
	}
	if app.UpdateFunction {
		const updateTag = "update"

		// Add permission
		permission := fmt.Sprintf("%s_%s", app.Tag, updateTag)
		_, ok := AuthSuperUserPermissions(core)[permission]
		if !ok {
			core.Permissions = append(core.Permissions, permission)
		}

		core.Router.POST(fmt.Sprintf("api/v1/%s/:id/save", app.Tag), app.Model.ModelSave(core, &app.Model, app))
	}

	functionTag := map[string]bool{}
	for _, action := range app.Function {
		const actionTag = "action"

		// Add permission
		permission := fmt.Sprintf("%s_%s_%s", app.Tag, actionTag, action.Tag)
		_, ok := AuthSuperUserPermissions(core)[permission]
		if !ok {
			core.Permissions = append(core.Permissions, permission)
		}

		// Function tag must be unique
		if functionTag[action.Tag] {
			return errors.New(fmt.Sprintf("not unique function tag: %s", action.Tag))
		}

		mthd := ""
		switch action.Method {
		case methodGet:
			mthd = "get"
		case methodPost:
			mthd = "post"
		case methodPut:
			mthd = "put"
		default:
			mthd = "get"
		}

		path := fmt.Sprintf("api/v1/%s/", app.Tag)
		if !action.Query {
			path = fmt.Sprintf("%s:id/%s", path, action.Tag)
		} else {
			path = fmt.Sprintf("%s%s", path, action.Tag)
		}
		switch mthd {
		case "get":
			core.Router.GET(path, action.Func)
		case "post":
			core.Router.POST(path, action.Func)
		case "put":
			core.Router.PUT(path, action.Func)
		}
	}

	core.ActiveTag = append(core.ActiveTag, app.Tag)
	return nil
}
