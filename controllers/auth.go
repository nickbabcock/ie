package controllers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/intervention-engine/fhir/server"
	"github.com/intervention-engine/ie/models"
	"gopkg.in/mgo.v2/bson"
)

var Store = sessions.NewCookieStore([]byte("somethingsecret"))

func init() {
	gob.Register(bson.ObjectId(""))
}

type requestForm struct {
	Session sessionRequestForm
}

type sessionRequestForm struct {
	Identification string
	Password       string
}

type responseForm struct {
	Session sessionResponseForm `json:"session"`
}

type sessionResponseForm struct {
	Token string `json:"token"`
}

type errorForm struct {
	Error string `json:"error"`
}

type registrationRequestForm struct {
	Identification string
	Password       string
	Confirmation   string
}

func LoginHandler(c *gin.Context) {
	var reqform requestForm
	if err := c.Bind(&reqform); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	//grab the username and password from the form
	username, password := reqform.Session.Identification, reqform.Session.Password

	user, err := models.Login(username, password)

	if err != nil {
		//var errform error_form
		//errform.Error = "invalid credentials"
		c.Header("Content-Type", "application/json; charset=utf-8")
		ef := errorForm{Error: "Invalid Credentials"}
		c.JSON(http.StatusUnauthorized, ef)
		return
	}

	if user != nil {
		var respform responseForm
		token := generateToken()

		var usersession models.UserSession
		usersession.User = *user
		usersession.Token = token
		usersession.Expiration = time.Now().Add(90 * time.Minute)
		server.Database.C("sessions").Insert(usersession)

		respform.Session.Token = token
		c.JSON(http.StatusOK, respform)
		return
	}
	c.AbortWithError(http.StatusInternalServerError, errors.New("Somehow reached here"))
}

func generateToken() string {
	rb := make([]byte, 32)
	_, err := rand.Read(rb)

	if err != nil {
		panic(err)
	}

	token := base64.URLEncoding.EncodeToString(rb)
	return token
}

func LogoutHandler(c *gin.Context) {
	clientToken := c.Request.Header.Get("Authorization")
	sessionCollection := server.Database.C("sessions")

	if err := sessionCollection.Remove(bson.M{"token": clientToken}); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
	}
}
