package auth

import (
	contextlib "context"
	"github.com/gin-gonic/gin"
	"net/http"
)

var perms map[string]string

func init() {
	perms = make(map[string]string)
}
func GetPerm(c *gin.Context) string {
	perm, ok := perms[c.Request.Method+"_"+c.Request.URL.Path]
	if !ok {
		return ""
	}
	return perm
}

func Build(r *gin.Engine) {
	r.POST("/auth", func(c *gin.Context) {
		var req *AuthRequest
		req = &AuthRequest{}
		c.BindJSON(req)
		c.Request.WithContext(contextlib.WithValue(c.Request.Context(), "CTX", c))
		res, err := APIAuth(c.Request.Context(), req)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		c.JSON(200, res)
	})
}
