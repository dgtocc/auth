package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/dgtocc/random"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	Dburl      string
	Dbdriver   string
	CookieName string
}

type User struct {
	Id       uint
	Username string
	Enabled  *bool
	Name     string
	Email    string
	Hash     string
	Groups   []*Group `gorm:"many2many:user_groups;"`
}

type Group struct {
	Id    uint
	Name  string
	Perms []*Perm `gorm:"many2many:group_perms;"`
}

type Perm struct {
	Id   uint
	Name string
}

type Session struct {
	Id       string
	Perms    string
	Username string
}

func (s *Session) HasPerm(p string) bool {
	return strings.Contains(s.Perms, "|"+p+"|")
}

var db *gorm.DB

func newErr(s string, p ...interface{}) error {
	return errors.New(fmt.Sprintf(s, p...))
}

var cfg *Config

func Init(c *Config) (err error) {
	cfg = c
	if c.Dbdriver == "sqlite" {
		db, err = gorm.Open(sqlite.Open(c.Dburl), &gorm.Config{})
		if err != nil {
			return err
		}
	} else if c.Dbdriver == "sqlserver" {
		db, err = gorm.Open(sqlserver.Open(c.Dburl), &gorm.Config{})
		if err != nil {
			return err
		}
	} else {
		return errors.New(fmt.Sprintf("Unknown dbdriver: %s", c.Dbdriver))
	}

	for _, v := range []interface{}{
		&User{}, &Group{}, &Perm{}, &Session{},
	} {
		err = db.AutoMigrate(v)
		if err != nil {
			return
		}
	}

	return

}

func Prepare() (err error) {
	ptrtrue := true
	hash, err := bcrypt.GenerateFromPassword([]byte("toor"), 10)
	if err != nil {
		return
	}
	p := &Perm{
		Id:   0,
		Name: "*",
	}
	err = db.Create(p).Error
	if err != nil {
		return
	}
	g := &Group{
		Name:  "Root",
		Perms: []*Perm{p},
	}
	err = db.Create(g).Error
	if err != nil {
		return
	}
	u := User{
		Username: "root",
		Enabled:  &ptrtrue,
		Name:     "Root",
		Email:    "",
		Hash:     string(hash),
		Groups:   []*Group{g},
	}
	err = db.Create(&u).Error
	return
}

func AddGroup(gname string) (err error) {
	g := &Group{}
	g.Name = gname
	err = db.Create(g).Error
	return
}

func RemGroup(gname string) (err error) {
	g := &Group{}
	err = db.Where("name = ?", gname).First(g).Error
	if err != nil {
		return
	}
	err = db.Where("id = ?", g.Id).Delete(g).Error
	return
}

func AddPerm(name string) (err error) {
	g := &Perm{}
	g.Name = name
	err = db.Create(g).Error
	return
}

func RemPerm(name string) (err error) {
	g := &Perm{}
	err = db.Where("name = ?", name).First(g).Error
	if err != nil {
		return
	}
	err = db.Where("id = ?", g.Id).Delete(g).Error
	return
}

func AddUser(u *User) (err error) {
	err = db.Create(u).Error
	return
}

func SetUserPass(u string, p string) (err error) {
	uo := &User{}
	err = db.Where("username = ?", u).Find(uo).Error
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(p), 10)
	if err != nil {
		return err
	}
	uo.Hash = string(hash)
	err = db.Save(uo).Error
	return
}

func EnableUser(u string) (err error) {
	ptrtrue := true
	err = db.Where("username = ?", u).Save(&User{
		Enabled: &ptrtrue,
	}).Error

	return
}

func DisableUser(u string) (err error) {
	ptrtrue := false
	err = db.Where("username = ?", u).Save(&User{
		Enabled: &ptrtrue,
	}).Error

	return
}

func AddUserToGroup(u string, g string) (err error) {
	uobj := &User{}
	gobj := &Group{}
	err = db.Preload("Groups").Where("username = ?", u).First(uobj).Error
	if err != nil {
		return
	}
	for _, v := range uobj.Groups {
		if v.Name == g {
			err = errors.New(fmt.Sprintf("User %s already assigned to group %s", u, g))
			return
		}
	}
	err = db.Where("name = ?", g).First(gobj).Error
	if err != nil {
		return
	}
	uobj.Groups = append(uobj.Groups, gobj)
	err = db.Save(uobj).Error
	return

}

func RemoveUserFromGroup(u string, g string) (err error) {
	uobj := &User{}

	err = db.Preload("Groups").Where("username = ?", u).First(uobj).Error
	if err != nil {
		return
	}

	for _, v := range uobj.Groups {
		if v.Name == g {
			err = db.Model(uobj).Association("Groups").Delete(v)
			return
		}
	}

	return

}

func AddPermToGroup(g string, p string) (err error) {
	pobj := &Perm{}
	gobj := &Group{}
	err = db.Preload("Perms").Where("name = ?", g).First(gobj).Error
	if err != nil {
		return
	}
	for _, v := range gobj.Perms {
		if v.Name == p {
			err = errors.New(fmt.Sprintf("Group %s already assigned to perm %s", g, p))
			return
		}
	}
	err = db.Where("name = ?", p).First(pobj).Error
	if err != nil {
		return
	}

	gobj.Perms = append(gobj.Perms, pobj)
	err = db.Save(gobj).Error
	return

}

func RemovePermFromGroup(g string, p string) (err error) {
	gobj := &Group{}

	err = db.Preload("Perms").Where("name = ?", g).First(gobj).Error

	if err != nil {
		return
	}

	for _, v := range gobj.Perms {
		if v.Name == g {
			db.Model(gobj).Association("Perms").Delete(v)
			break
		}
	}

	return

}

func Auth(username, password string) (sessid string, err error) {
	u := &User{}
	db.Preload("Groups.Perms").Where("username = ? and enabled = true", username).First(u)
	err = bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(password))
	if err != nil {
		return
	}
	s := &Session{}
	sb := strings.Builder{}
	for _, g := range u.Groups {
		for _, p := range g.Perms {
			sb.WriteString(fmt.Sprintf("|%s|", p.Name))
		}
	}
	s.Id = random.StringUpperAndNumber(32)
	s.Username = u.Username
	s.Perms = sb.String()
	err = db.Create(&s).Error
	if err != nil {
		return
	}
	sessid = s.Id
	return
}

func Sess(id string) (ret *Session, err error) {
	ret = &Session{}
	err = db.Where("id = ?", id).First(ret).Error
	return
}

func MDSession(ctx *gin.Context) {
	cookie, err := ctx.Request.Cookie(cfg.CookieName)
	perm := GetPerm(ctx)
	if perm != "" {
		if err != nil {
			ctx.AbortWithError(http.StatusForbidden, err)
			return
		} else {
			sess, err := Sess(cookie.Value)
			if err != nil {
				ctx.AbortWithError(http.StatusForbidden, err)
				return
			}
			if sess.HasPerm(perm) {
				ctx.Set("SESSION", sess)
				ctx.Next()
			} else {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}
		}
	}

}

/*@API*/
type AuthRequest struct {
	Username string
	Password string
}

/*
@API
@PATH: /auth
*/
func APIAuth(ctx context.Context, req *AuthRequest) (sessid string, err error) {
	sessid, err = Auth(req.Username, req.Password)
	gctx := ctx.Value("CTX").(*gin.Context)
	cookie := http.Cookie{
		Name:       cfg.CookieName,
		Value:      sessid,
		Path:       "/",
		Domain:     ".",
		Expires:    time.Now().AddDate(10, 0, 0),
		RawExpires: "",
		MaxAge:     0,
		Secure:     true,
		HttpOnly:   true,
		SameSite:   http.SameSiteLaxMode,
	}
	http.SetCookie(gctx.Writer, &cookie)
	return
}
