package model

import (
	"github.com/alist-org/alist/v3/internal/errs"
	"github.com/alist-org/alist/v3/pkg/utils"
	"github.com/pkg/errors"
	"gorm.io/gorm"
	"strings"
)

const (
	GENERAL = iota
	GUEST   // only one exists
	ADMIN
)

type Privilege int

const (
	Normal    Privilege = 0
	SiteAdmin Privilege = 100
)

type User struct {
	ID uint `json:"id" gorm:"primaryKey"`

	Username string `json:"username" gorm:"column:email" binding:"required"`

	Password  string `xml:"-" json:"password"`
	Privilege Privilege

	BasePath string `json:"base_path" gorm:"-"` // base path
	Role     int    `json:"role" gorm:"-"`      // user's role
	Disabled bool   `json:"disabled" gorm:"-"`
	// Determine permissions by bit
	//   0: can see hidden files
	//   1: can access without password
	//   2: can add aria2 tasks
	//   3: can mkdir and upload
	//   4: can rename
	//   5: can move
	//   6: can copy
	//   7: can remove
	//   8: webdav read
	//   9: webdav write
	//  10: can add qbittorrent tasks
	Permission int32  `json:"permission" gorm:"-"`
	OtpSecret  string `json:"-" gorm:"-"`
	SsoID      string `json:"sso_id" gorm:"-"`
}

func (User) TableName() string {
	return "uploaders"
}

func (u *User) AfterFind(db *gorm.DB) (err error) {
	if u.Privilege == SiteAdmin {
		u.Role = ADMIN
	} else if u.Privilege < 0 {
		u.Role = GUEST
		u.Disabled = true
	}
	u.Permission = 8 + 16 + 32 + 64 + 128
	u.BasePath = "bcs-src/blob/" + strings.ReplaceAll(u.Username, "@", ".")
	return
}

func (u User) IsGuest() bool {
	return u.Privilege < Normal
}

func (u User) IsAdmin() bool {
	return u.Privilege == SiteAdmin
}

func (u User) ValidatePassword(password string) error {
	if password == "" {
		return errors.WithStack(errs.EmptyPassword)
	}
	if !BCryptValidateHash(password, u.Password) {
		return errors.WithStack(errs.WrongPassword)
	}
	return nil
}

func (u User) CanSeeHides() bool {
	return u.IsAdmin() || u.Permission&1 == 1
}

func (u User) CanAccessWithoutPassword() bool {
	return u.IsAdmin() || (u.Permission>>1)&1 == 1
}

func (u User) CanAddAria2Tasks() bool {
	return u.IsAdmin() || (u.Permission>>2)&1 == 1
}

func (u User) CanWrite() bool {
	return u.IsAdmin() || (u.Permission>>3)&1 == 1
}

func (u User) CanRename() bool {
	return u.IsAdmin() || (u.Permission>>4)&1 == 1
}

func (u User) CanMove() bool {
	return u.IsAdmin() || (u.Permission>>5)&1 == 1
}

func (u User) CanCopy() bool {
	return u.IsAdmin() || (u.Permission>>6)&1 == 1
}

func (u User) CanRemove() bool {
	return u.IsAdmin() || (u.Permission>>7)&1 == 1
}

func (u User) CanWebdavRead() bool {
	return u.IsAdmin() || (u.Permission>>8)&1 == 1
}

func (u User) CanWebdavManage() bool {
	return u.IsAdmin() || (u.Permission>>9)&1 == 1
}

func (u User) CanAddQbittorrentTasks() bool {
	return u.IsAdmin() || (u.Permission>>10)&1 == 1
}

func (u User) JoinPath(reqPath string) (string, error) {
	return utils.JoinBasePath(u.BasePath, reqPath)
}
