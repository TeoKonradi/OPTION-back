package option

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type ErrorResponseStruct struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type LoginSuccessResponseStruct struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

type LoginRequiredStruct struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AdminUserStruct struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`

	IsActive    bool `json:"is_active"`
	IsStaff     bool `json:"is_staff"`
	IsSuperUser bool `json:"is_super_user"`

	LastLogin int `json:"last_login"`
	Register  int `json:"register"`

	Permissions []string           `json:"permissions"`
	Groups      []AdminGroupStruct `json:"groups"`
}

type AdminGroupStruct struct {
	ID          uint     `json:"ID"`
	Tag         string   `json:"tag"`
	Permissions []string `json:"permissions"`
}

type AdminChangePassword struct {
	OldPassword string `json:"old_password"`
	Password    string `json:"password"`
}

// ---- DB structs ----

type AdminUser struct {
	Model

	Username string `json:"username" gorm:"unique;default:null"`
	Password string `json:"password"`

	Permissions            Permissions             `json:"permissions" gorm:"type:jsonb;default:'[]';not null"`
	AdminPermissionsGroups []AdminPermissionsGroup `json:"admin_permissions_groups" gorm:"many2many:admin_users_groups;"`

	RefreshTokens []RefreshTokens `json:"refresh_tokens" gorm:"polymorphic:Owner;"`
	AccessTokens  []AccessTokens  `json:"access_tokens" gorm:"polymorphic:Owner;"`

	IsActive    bool `json:"is_active"`
	IsStaff     bool `json:"is_staff"`
	IsSuperUser bool `json:"is_super_user"`

	LastLogin time.Time
}

type AccessTokens struct {
	Model

	OwnerID   uint
	OwnerType string

	Token         string `gorm:"unique;default:null"`
	Expired       bool
	ExpiredReason string
	Show          bool `gorm:"default:TRUE"`
}

type RefreshTokens struct {
	Model

	OwnerID   uint
	OwnerType string

	Token         string `json:"token" gorm:"unique;default:null"`
	Expired       bool   `json:"expired"`
	ExpiredReason string `json:"expired_reason"`
	Show          bool   `json:"show" gorm:"default:TRUE"`
}

type AdminPermissionsGroup struct {
	Model

	Tag         string      `gorm:"unique;default:null"`
	Permissions Permissions `gorm:"type:jsonb;default:'[]';not null"`

	AdminUsers []AdminUser `gorm:"many2many:admin_users_groups;" json:"admin_users"`
}

type Permissions []string

func (dj Permissions) Value() (driver.Value, error) {
	return json.Marshal(dj)
}

func (dj *Permissions) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("[]byte assertion failed")
	}
	return json.Unmarshal(b, dj)
}

// ---- User management ----

func (core *Core) CreateStandardAdminUser() {
	list := []AdminUser{}
	err := core.Session.Config.Database.PS.Db.Find(&list).Error
	if err != nil || len(list) == 0 {
		// hash the password
		hash, err := bcrypt.GenerateFromPassword([]byte("admin"), 10)
		if err != nil {
			log.Fatal("error: Password is to long or idk")
			return
		}

		standardUsr := AdminUser{
			Username: "admin",
			Password: string(hash),

			Permissions: []string{},

			RefreshTokens: []RefreshTokens{},
			AccessTokens:  []AccessTokens{},

			IsActive:    true,
			IsStaff:     true,
			IsSuperUser: true,
		}

		err = core.Session.Config.Database.PS.Db.Create(&standardUsr).Error
		if err != nil {
			log.Fatal("error: Save error")
		}
	}
}

//// AdminCreateUser
//// /admin/user/reg [post]
//func (core *Core) AdminCreateUser(c *gin.Context) {
//	const PermissionsName = "create_adm_user"
//	usr, access := core.AuthRequireUser(c, PermissionsName)
//	if !access || usr.ID == 0 {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "auth required", Message: "auth required"})
//		return
//	}
//
//	// Get the params
//	var regBody AdminRegUserStruct
//	err := c.Bind(&regBody)
//	if err != nil {
//		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "man, are u dull?", Message: "man, are u dull?"})
//		return
//	}
//
//	// hash the password
//	hash, err := bcrypt.GenerateFromPassword([]byte(regBody.Password), 10)
//	if err != nil {
//		log.Fatal("error: Password is to long or idk")
//		return
//	}
//
//	permissionsGroupList := []p.AdminPermissionsGroup{}
//	for _, grId := range regBody.Groups {
//		group := p.AdminPermissionsGroup{}
//		err = a.postgre.Db.Find(&group, grId).Error
//		if err != nil || group.ID == 0 {
//			c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "find error", Message: "group find error"})
//			return
//		}
//		permissionsGroupList = append(permissionsGroupList, group)
//	}
//
//	newUser := p.AdminUser{
//		Username: regBody.Username,
//		Password: string(hash),
//
//		Permissions: regBody.Permissions,
//
//		AdminPermissionsGroups: permissionsGroupList,
//		RefreshTokens:          []p.RefreshTokens{},
//		AccessTokens:           []p.AccessTokens{},
//
//		IsActive:    regBody.IsActive,
//		IsStaff:     regBody.IsStaff,
//		IsSuperUser: regBody.IsSuperUser,
//	}
//
//	err = a.postgre.Db.Create(&newUser).Error
//	if err != nil {
//		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "save error", Message: "save error"})
//		return
//	}
//
//	c.JSON(http.StatusOK, gin.H{"status": "success"})
//	return
//}
//
//// AdminUserList
//// /admin/user [get]
//// 200 array api.AdminUserStruct
//func (core *Core) AdminUserList(c *gin.Context) {
//	const PermissionsName = "list_adm_user"
//	usr, access := core.AuthRequireUser(c, PermissionsName)
//	if !access || usr.ID == 0 {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "auth required", Message: "auth required"})
//		return
//	}
//
//	list := []p.AdminUser{}
//	err := a.postgre.Db.Find(&list).Error
//	if err != nil {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "find error", Message: "find error"})
//		return
//	}
//
//	res := []AdminUserStruct{}
//	for _, user := range list {
//		allPermissions := GetSuperUserPermissions()
//
//		permissionsList := []UserPermission{}
//		for _, pr := range user.Permissions {
//			pprr, ok := allPermissions[pr]
//			if ok {
//				permissionsList = append(permissionsList, pprr)
//			}
//		}
//
//		gropList := []AdminGroupStruct{}
//		for _, gr := range user.AdminPermissionsGroups {
//			grPermissionsList := []UserPermission{}
//			for _, pr := range gr.Permissions {
//				pprr, ok := allPermissions[pr]
//				if ok {
//					grPermissionsList = append(grPermissionsList, pprr)
//				}
//			}
//
//			gropList = append(gropList, AdminGroupStruct{
//				Tag:         gr.Tag,
//				Permissions: grPermissionsList,
//			})
//		}
//
//		res = append(res, AdminUserStruct{
//			ID:          user.ID,
//			Username:    user.Username,
//			IsActive:    user.IsActive,
//			IsStaff:     user.IsStaff,
//			IsSuperUser: user.IsSuperUser,
//
//			LastLogin: int(user.LastLogin.Unix() + a.Location),
//			Register:  int(user.CreatedAt.Unix() + a.Location),
//
//			Permissions: permissionsList,
//			Groups:      gropList,
//		})
//	}
//
//	c.JSON(http.StatusOK, gin.H{"total": len(res), "items": res})
//	return
//}
//
//// AdminUserGet
//// /admin/user/:id/ [get]
//// 200 object api.AdminUserStruct
//func (core *Core) AdminUserGet(c *gin.Context) {
//	const PermissionsName = "get_adm_user"
//	usr, access := core.AuthRequireUser(c, PermissionsName)
//	if !access || usr.ID == 0 {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "auth required", Message: "auth required"})
//		return
//	}
//
//	// Get the params
//	id_string := c.Param("id")
//	id, err := strconv.Atoi(id_string)
//	if err != nil {
//		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "bad id", Message: "bad id"})
//		return
//	}
//
//	user := p.AdminUser{}
//	err = a.postgre.Db.Find(&user, id).Error
//	if err != nil || user.ID == 0 {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "find error", Message: "find error"})
//		return
//	}
//
//	allPermissions := GetSuperUserPermissions()
//
//	permissionsList := []UserPermission{}
//	for _, pr := range user.Permissions {
//		pprr, ok := allPermissions[pr]
//		if ok {
//			permissionsList = append(permissionsList, pprr)
//		}
//	}
//
//	gropList := []AdminGroupStruct{}
//	for _, gr := range user.AdminPermissionsGroups {
//		grPermissionsList := []UserPermission{}
//		for _, pr := range gr.Permissions {
//			pprr, ok := allPermissions[pr]
//			if ok {
//				grPermissionsList = append(grPermissionsList, pprr)
//			}
//		}
//
//		gropList = append(gropList, AdminGroupStruct{
//			Tag:         gr.Tag,
//			Permissions: grPermissionsList,
//		})
//	}
//
//	res := AdminUserStruct{
//		ID:          user.ID,
//		Username:    user.Username,
//		IsActive:    user.IsActive,
//		IsStaff:     user.IsStaff,
//		IsSuperUser: user.IsSuperUser,
//
//		LastLogin: int(user.LastLogin.Unix() + a.Location),
//		Register:  int(user.CreatedAt.Unix() + a.Location),
//
//		Permissions: permissionsList,
//		Groups:      gropList,
//	}
//
//	c.JSON(http.StatusOK, res)
//	return
//}
//
//// AdminUserUpdate
//// /admin/user/:id/update [put]
//// 200 object api.AdminUserStruct
//func (core *Core) AdminUserUpdate(c *gin.Context) {
//	const PermissionsName = "update_adm_user"
//	usr, access := core.AuthRequireUser(c, PermissionsName)
//	if !access || usr.ID == 0 {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "auth required", Message: "auth required"})
//		return
//	}
//
//	// Get the params
//	var regBody AdminUser
//	err := c.Bind(&regBody)
//	if err != nil {
//		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "man, are u dull?", Message: "man, are u dull?"})
//		return
//	}
//	id_string := c.Param("id")
//	id, err := strconv.Atoi(id_string)
//	if err != nil {
//		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "bad id", Message: "bad id"})
//		return
//	}
//
//	user := p.AdminUser{}
//	err = a.postgre.Db.Find(&user, id).Error
//	if err != nil || user.ID == 0 {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "find error", Message: "find error"})
//		return
//	}
//
//	//Groups      []uint   `json:"groups"`
//	user.Username = regBody.Username
//	user.IsActive = regBody.IsActive
//	user.IsStaff = regBody.IsStaff
//	user.IsSuperUser = regBody.IsSuperUser
//	user.Permissions = regBody.Permissions
//	err = a.postgre.Db.Save(&user).Error
//	if err != nil || user.ID == 0 {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "save error", Message: "save error"})
//		return
//	}
//
//	c.JSON(http.StatusOK, gin.H{"status": "success"})
//	return
//}
//
//// AdminUserDel
//// /admin/user/:id/reg [post]
//func (core *Core) AdminUserDel(c *gin.Context) {
//	const PermissionsName = "delete_adm_user"
//	usr, access := core.AuthRequireUser(c, PermissionsName)
//	if !access || usr.ID == 0 {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "auth required", Message: "auth required"})
//		return
//	}
//
//	// Get the params
//	var regBody AdminUser
//	err := c.Bind(&regBody)
//	if err != nil {
//		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "man, are u dull?", Message: "man, are u dull?"})
//		return
//	}
//	id_string := c.Param("id")
//	id, err := strconv.Atoi(id_string)
//	if err != nil {
//		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "bad id", Message: "bad id"})
//		return
//	}
//
//	user := p.AdminUser{}
//	err = a.postgre.Db.Find(&user, id).Error
//	if err != nil || user.ID == 0 {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "find error", Message: "find error"})
//		return
//	}
//
//	err = a.postgre.Db.Delete(&user).Error
//	if err != nil || user.ID == 0 {
//		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "save error", Message: "save error"})
//		return
//	}
//
//	c.JSON(http.StatusOK, gin.H{"status": "success"})
//	return
//}

// create_adm_group
// /admin/group/reg [post]

// list_adm_group
// /admin/group/ [get]

// get_adm_group
// /admin/group/:id/ [get]

// update_adm_group
// /admin/group/:id/update [put]

// delete_adm_group
// /admin/group/:id/del [post]

// ---- Functions ----

func (core *Core) AuthLoginLogic(user *AdminUser, c *gin.Context) (error, *LoginSuccessResponseStruct) {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"typ": "rfr",
		"foo": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 31 * 24).Unix(),
		//"exp": time.Now().Add(time.Minute * 2).Unix(),
	})

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"typ": "acs",
		"foo": user.ID,
		"exp": time.Now().Add(time.Hour * 12).Unix(),
		//"exp": time.Now().Add(time.Minute * 2).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return errors.New("invalid secret 228"), nil

	}

	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return errors.New("invalid secret 228"), nil
	}

	refreshTokens := append(user.RefreshTokens, RefreshTokens{Token: refreshTokenString, Expired: false})
	accessTokens := append(user.AccessTokens, AccessTokens{Token: accessTokenString, Expired: false})
	user.RefreshTokens = refreshTokens
	user.AccessTokens = accessTokens
	user.LastLogin = time.Now()
	err = core.Session.Config.Database.PS.Db.Save(&user).Error
	if err != nil {
		return errors.New("unable to save refresh token"), nil
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"auth_adm_token",
		refreshTokenString,
		(1 * 60 * 60 * 24 * 31 * 12),
		"/",
		"",
		false,
		true,
	)
	c.SetCookie(
		"auth_adm_session",
		accessTokenString,
		(1 * 60 * 60 * 24 * 31 * 12),
		"/",
		"",
		false,
		true,
	)

	return nil, &LoginSuccessResponseStruct{RefreshToken: refreshTokenString, AccessToken: accessTokenString}
}

// AuthLogin
// Require api.LoginRequiredStruct
// [post] {{connection}}/auth/login
func (core *Core) AuthLogin(c *gin.Context) {
	// Get the params
	var loginBody LoginRequiredStruct
	err := c.Bind(&loginBody)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "man, are u dull?", Message: "man, are u dull?"})
		return
	}

	var userDisposable AdminUser
	var user AdminUser

	switch {
	case core.Session.Config.Database.PS.Db.First(&userDisposable, "username = ?", strings.ToLower(loginBody.Username)).Error == nil:
		if userDisposable.ID != 0 {
			user = userDisposable
		}
	default:
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "no username", Message: "no username"})
		return
	}

	if user.ID == 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "wrong username or password", Message: "wrong username or password"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginBody.Password))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "wrong username or password", Message: "wrong username or password"})
		return
	}

	err, res := core.AuthLoginLogic(&user, c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "wrong username or password", Message: "wrong username or password"})
		return
	}
	c.JSON(http.StatusOK, res)
	return
}

// AuthRefreshToken
// [get] {{connection}}/auth/refresh
func (core *Core) AuthRefreshToken(c *gin.Context) {
	// get the cookie or query
	tokenString, err := c.Cookie("auth_adm_token")
	if err != nil {
		tokenString = c.Query("auth_adm_token")
		if tokenString == "" {
			c.Next()
			return
		}
	}

	// check expiration
	if tokenString == "log out" {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "log out", Message: "log out"})
		return
	}

	tokenCheck := RefreshTokens{}
	err = core.Session.Config.Database.PS.Db.First(&tokenCheck, "Token = ?", tokenString).Error
	if err != nil || tokenCheck.Expired {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "expired", Message: "expired"})
		return
	}

	// validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "not valid", Message: "not valid"})
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// check is refresh token
		if claims["typ"] != "rfr" {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "wrong token", Message: "wrong token"})
			return
		}

		// check the expired
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "not valid", Message: "not valid"})
			return
		}

		// find the token owner
		var usr AdminUser
		core.Session.Config.Database.PS.Db.First(&usr, claims["foo"])
		if usr.ID == 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "not valid", Message: "not valid"})
			return
		}

		// return new token
		accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"typ": "acs",
			"foo": usr.ID,
			"exp": time.Now().Add(time.Hour * 12).Unix(),
			//"exp": time.Now().Add(time.Minute * 2).Unix(),
		})
		accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("SECRET")))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "invalid secret", Message: "invalid secret"})
			return
		}

		accessTokens := append(usr.AccessTokens, AccessTokens{Token: accessTokenString, Expired: false})
		usr.AccessTokens = accessTokens
		res := core.Session.Config.Database.PS.Db.Save(&usr)
		if res.Error != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "unable to save refresh token", Message: "unable to save refresh token"})
			return
		}

		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(
			"auth_adm_session",
			accessTokenString,
			(1 * 60 * 60 * 24 * 31 * 12),
			"/",
			"",
			false,
			true,
		)
		c.JSON(http.StatusOK, LoginSuccessResponseStruct{AccessToken: accessTokenString})
		return
	} else {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "not valid", Message: "not valid"})
		return
	}
}

// AuthMe
// [get] {{connection}}/admin/me
func (core *Core) AuthMe(c *gin.Context) {
	const PermissionsName = "me"
	usr, access := core.AuthRequireUser(c, PermissionsName)
	if !access || usr.ID == 0 {
		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "auth required", Message: "auth required"})
		return
	}

	allPermissions := AuthSuperUserPermissions(core)

	permissionsList := []string{}
	for _, pr := range usr.Permissions {
		pprr, ok := allPermissions[pr]
		if ok {
			permissionsList = append(permissionsList, pprr)
		}
	}

	gropList := []AdminGroupStruct{}
	for _, gr := range usr.AdminPermissionsGroups {
		grPermissionsList := []string{}
		for _, pr := range gr.Permissions {
			pprr, ok := allPermissions[pr]
			if ok {
				grPermissionsList = append(grPermissionsList, pprr)
			}
		}

		gropList = append(gropList, AdminGroupStruct{
			ID:          gr.ID,
			Tag:         gr.Tag,
			Permissions: grPermissionsList,
		})
	}

	res := AdminUserStruct{
		ID:          usr.ID,
		Username:    usr.Username,
		IsActive:    usr.IsActive,
		IsStaff:     usr.IsStaff,
		IsSuperUser: usr.IsSuperUser,

		LastLogin: int(usr.LastLogin.Unix()),
		Register:  int(usr.CreatedAt.Unix()),

		Permissions: permissionsList,
		Groups:      gropList,
	}

	c.JSON(http.StatusOK, res)
	return
}

// AuthChangePassword
// Require AdminChangePassword
// [get] {{connection}}/admin/me/change/password
func (core *Core) AuthChangePassword(c *gin.Context) {
	const PermissionsName = "me"
	usr, access := core.AuthRequireUser(c, PermissionsName)
	if !access || usr.ID == 0 {
		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "auth required", Message: "auth required"})
		return
	}

	// Get the params
	var loginBody AdminChangePassword
	err := c.Bind(&loginBody)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "man, are u dull?", Message: "man, are u dull?"})
		return
	}

	// Check the passwords matches everything
	pass_err := bcrypt.CompareHashAndPassword([]byte(usr.Password), []byte(loginBody.OldPassword))
	if pass_err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "wrong old password", Message: "wrong old password"})
		return
	}

	// hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(loginBody.Password), 10)
	if err != nil {
		log.Fatal("error: Password is to long or idk")
		return
	}

	usr.Password = string(hash)
	res := core.Session.Config.Database.PS.Db.Save(&usr)
	if res.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponseStruct{Error: "save err", Message: "save err"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
	return
}

// AuthLogout
// [get] /admin/logout
func (core *Core) AuthLogout(c *gin.Context) {
	const PermissionsName = "me"
	usr, access := core.AuthRequireUser(c, PermissionsName)
	if !access || usr.ID == 0 {
		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "auth required", Message: "auth required"})
		return
	}

	// get the cookie or query
	sessionString, err := c.Cookie("auth_adm_session")
	if err != nil {
		sessionString = c.Query("auth_adm_session")
		if sessionString == "" {
			c.Next()
			return
		}
	}
	tokenString, err := c.Cookie("auth_adm_token")
	if err != nil {
		tokenString = c.Query("auth_adm_token")
		if tokenString == "" {
			c.Next()
			return
		}
	}

	err1 := core.Session.Config.Database.PS.Db.Model(&RefreshTokens{}).Where("Token = ?", tokenString).Updates(RefreshTokens{Expired: true, ExpiredReason: "log out"}).Error
	err2 := core.Session.Config.Database.PS.Db.Model(&AccessTokens{}).Where("Token = ?", sessionString).Updates(AccessTokens{Expired: true, ExpiredReason: "log out"}).Error
	if err1 != nil || err2 != nil {
		c.AbortWithStatusJSON(http.StatusNetworkAuthenticationRequired, ErrorResponseStruct{Error: "auth required", Message: "auth required"})
		return
	}
	c.SetCookie(
		"auth_adm_session",
		"log out",
		-1,
		"/",
		"",
		false,
		true,
	)
	c.SetCookie(
		"auth_adm_token",
		"log out",
		-1,
		"/",
		"",
		false,
		true,
	)
	c.JSON(http.StatusOK, LoginSuccessResponseStruct{"log out", "log out"})
	return
}

func (core *Core) AuthMiddleware(c *gin.Context) {
	// get the cookie or query
	tokenString, err := c.Cookie("auth_adm_session")
	if err != nil {
		tokenString = c.Query("auth_adm_session")
		if tokenString == "" {
			c.Next()
			return
		}
	}

	// check expiration
	if tokenString == "log out" {
		c.Next()
		return
	}

	tokenCheck := AccessTokens{}
	err = core.Session.Config.Database.PS.Db.First(&tokenCheck, "Token = ?", tokenString).Error
	if err != nil {
		c.Next()
		return
	}
	if tokenCheck.Expired {
		c.Next()
		return
	}

	// validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		c.Next()
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// check the expired
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.Next()
			return
		}

		// find the token owner
		var usr AdminUser
		err = core.Session.Config.Database.PS.Db.First(&usr, claims["foo"]).Error
		//usr, err := a.postgre.GetUserById(claims["foo"])
		if err != nil || usr.ID == 0 {
			c.Next()
			return
		}
		if usr.ID == 0 {
			c.Next()
			return
		}

		// attach to req
		c.Set("adm_usr_id", usr.ID)

		// continue
		c.Next()
		return
	} else {
		c.Next()
		return
	}
}

func (core *Core) AuthRequireUser(c *gin.Context, permissionName string) (*AdminUser, bool) {
	userId, exist := c.Get("adm_usr_id")
	if !exist {
		return nil, false
	}

	user := AdminUser{}
	err := core.Session.Config.Database.PS.Db.Preload("RefreshTokens").Preload("AccessTokens").Preload("AdminPermissionsGroups").Find(&user, userId).Error
	if err != nil || user.ID == 0 {
		return nil, false
	}

	if user.IsSuperUser {
		user.Permissions = []string{}
		for _, pr := range AuthSuperUserPermissions(core) {
			user.Permissions = append(user.Permissions, pr)
		}

		return &user, true
	}

	if permissionName == "me" {
		return &user, true
	}

	for _, pr := range user.Permissions {
		if pr == permissionName {
			return &user, true
		}
	}
	for _, gr := range user.AdminPermissionsGroups {
		for _, pr := range gr.Permissions {
			if pr == permissionName {
				return &user, true
			}
		}
	}

	return &user, false
}

// AuthAllPermissions
// /admin/permissions
// 200 array api.UserPermission
func (core *Core) AuthAllPermissions(c *gin.Context) {
	c.JSON(http.StatusOK, AuthSuperUserPermissions)
}

func AuthSuperUserPermissions(core *Core) map[string]string {
	res := make(map[string]string)
	for _, pr := range core.Permissions {
		res[pr] = pr
	}
	return res
}

func (core *Core) SetUpAuth() {
	authGroup := core.Router.Group("/auth")
	authGroup.Use(core.AuthMiddleware)
	{
		authGroup.GET("/permissions", core.AuthAllPermissions)

		authGroup.POST("/login", core.AuthLogin)
		authGroup.GET("/logout", core.AuthLogout)

		//adminUserGroup := authGroup.Group("/user")
		//{
		//	adminUserGroup.POST("/reg", core.AdminCreateUser)
		//	adminUserGroup.GET("", core.AdminUserList)
		//adminUserGroup.GET("/:id", core.AdminUserGet)
		//adminUserGroup.PUT("/:id/update", core.AdminUserUpdate)
		//adminUserGroup.POST("/:id/del", core.AdminUserDel)
		//}

		adminMeGroup := authGroup.Group("/me")
		{
			adminMeGroup.GET("", core.AuthMe)
			adminMeGroup.GET("/refresh", core.AuthRefreshToken)
			adminMeGroup.POST("/change/password", core.AuthChangePassword)
		}
	}
}
