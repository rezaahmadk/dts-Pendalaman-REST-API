package helper

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/rezaahmadk/dts-Pendalaman-REST-API/auth/constant"
	"github.com/rezaahmadk/dts-Pendalaman-REST-API/auth/database"
)

//Generate Token
func CreateToken(role int, idUser string) (error, *database.TokenDetails) {
	var roleStr string
	if role == constant.ADMIN {
		roleStr = "admin"
	} else if role == constant.CONSUMER {
		roleStr = "consumer"
	}

	//Token Details Initialization
	td := &database.TokenDetails{}
	//Set Waktu Access Token
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	//Set Waktu Refresh Token
	td.RtExpires = time.Now().Add(time.Hour).Unix()

	//Set Header + Payload Access Token
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id_user": idUser,
		"role":    role,
		"exp":     td.RtExpires,
	})

	//Set Salt Access Token
	//Admin Salt -> secret_admin_digitalent
	//Consumer Salt -> secret_consumer_digitalent
	var err error
	td.AccessToken, err = at.SignedString([]byte(fmt.Sprintf("secret_%s_digitalent", roleStr)))
	if err != nil {
		return err, &database.TokenDetails{}
	}

	//Set Header + Payload Refresh Token
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id_user": idUser,
		"role":    role,
		"exp":     td.RtExpires,
	})

	//Set Salt Refresh Token
	//Admin Salt -> refresh_secret_admin_digitalent
	//Consumer Salt -> refresh_secret_consumer_digitalent
	td.RefreshToken, err = rt.SignedString([]byte(fmt.Sprintf("secret_%s_digitalent", roleStr)))
	if err != nil {
		return err, &database.TokenDetails{}
	}

	return nil, td
}

//Extract / Parsing Ambil Data
func ExtractToken(roles int, r *http.Request) string {
	var bearToken string

	//Ambil dari Key Header
	if roles == constant.ADMIN {
		bearToken = r.Header.Get("digitalent-admin")
	} else if roles == constant.CONSUMER {
		bearToken = r.Header.Get("digitalent-consumer")
	}

	//Split Bearer xxx_xxx_xxx -> array of string
	//Array[0] = Bearer
	//Array[1] = xxx_xxx_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}

	return ""
}

//Verifikasi Token
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	var roleStr string
	var roles int

	if r.Header.Get("digitalent-admin") != "" {
		roleStr = "admin"
		roles = constant.ADMIN
	} else if r.Header.Get("digitalent-consumer") != "" {
		roleStr = "consumer"
		roles = constant.CONSUMER
	} else {
		return nil, errors.Errorf("Session Invalid")
	}

	tokenString := ExtractToken(roles, r)
	log.Println(tokenString)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Cek Signing Header apakah HS256
		if jwt.GetSigningMethod("HS256") != token.Method {
			return nil, errors.Errorf("Unexpected Signing Method: %v", token.Header["alg"])
		}
		return []byte(fmt.Sprintf("secret_%s_digitalent", roleStr)), nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

//Token Validation / IsTokenValid
func TokenValid(r *http.Request) (string, int, error) {
	//Memanggil Fungsi Verifikasi
	token, err := VerifyToken(r)
	if err != nil {
		return "", 0, err
	}

	//Proses Claim Payload Data dari Token
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		idUser, ok := claims["id_user"].(string)
		role, ok := claims["role"]
		if !ok {
			return "", 0, nil
		}
		return idUser, int(role.(float64)), nil
	}

	return "", 0, nil
}
