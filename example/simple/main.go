package main

import (
	"github.com/wawilow108/option"
	"github.com/wawilow108/option/pkg/config"
	"github.com/wawilow108/option/pkg/widget"
	"log"
	"time"
)

func main() {
	core := option.Default(&config.Session{
		DryRun:      true,
		Initialized: false,
		Config: &config.Config{
			Debug:        true,
			SSL:          false,
			Active:       true,
			Version:      "0.0.1",
			BasePath:     "api/v1/",
			AllowedHosts: []string{"*"},
			Data: config.Data{
				SiteTitle:  "testSite",
				SiteHeader: "testSite",
				SiteBrand:  "testSite",
				SiteLogo:   "testSite",
				Copyright:  "testSite",
			},
			Database:         nil,
			Logger:           nil,
			LoggerMiddleware: "/Users/user/Projects/PetProjects/CRM/data/",
			NowFunc:          func() time.Time { return time.Now() },
		}})

	//core.SetUpAuth()

	type Product struct {
		option.Model
		//ID          uint   `json:"id" gorm:"primarykey"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Price       int    `json:"price"`
	}
	productApp := option.App{
		Tag:      "product",
		Name:     map[string]string{option.LNG_ENG: "Product", option.LNG_RU: "Продукт"},
		Model:    new(Product),
		Function: []widget.Action{},

		Migration: true,

		SideBar:       true,
		SideBarWeight: 0,

		//	Basic functions
		GetFunction:    true,
		ListFunction:   true,
		DeleteFunction: true,
		UpdateFunction: true,
	}
	err := core.Session.Config.Database.PS.Migration(&productApp.Model)
	if err != nil {
		log.Printf("Server - there was an error calling Serve on router: %v", err)
	}
	err = core.Serve(productApp)
	if err != nil {
		log.Printf("Server - there was an error calling Serve on router: %v", err)
	}
	err = core.Router.Run(":8000")
	//err := s.router.RunTLS(":443", "sert/cert.pem", "sert/key.pem")
	if err != nil {
		log.Printf("Server - there was an error calling Run on router: %v", err)
	}
}
