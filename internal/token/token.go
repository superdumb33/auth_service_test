package token

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type RefreshToken struct {
	RandomBytes string
	UserID      string
	UserIP      string
	TokenID     string
}

func GenerateAccessToken(jti string, ttl time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"exp": time.Now().Add(ttl).Unix(),
		"jti": jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}
//returns base64 encoded refresh token
func GenerateRefreshToken() (string, error) {
	var randBytes = make([]byte, 32)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(randBytes), nil
}

// accepts raw token, returns bcrypt hash
func GenerateBCryptHash(token string) ([]byte, error) {
	if token == "" {
		return nil, errors.New("empty token")
	}

	return bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
}
//if allowExpired = true, omits ErrTokenExpired error and returns token
func ParseJWTToken(tokenString string, allowExpired bool) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || token.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, errors.New("unprocessable signing method")
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) && allowExpired {
			return token, nil
		}

		return nil, err
	}

	return token, nil
}

// accepts refreshToken, comparing it's bcrypt hash with storedHash; returns nil if hash matches
func VerifyRefreshToken(refreshToken, storedHash string) error {
	return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(refreshToken))
}
