package helios

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Configuration :
type Configuration struct {
	RequestHeaders          []string
	Secret                  func(string) string
	ExpirationTime          time.Duration
	ExpirationTimeTolerance time.Duration
}

// NewConfiguration :
func NewConfiguration(_requestHeaders []string, _secret func(string) string, _expirationTime time.Duration, _expirationTimeTolerance time.Duration) *Configuration {
	return &Configuration{
		RequestHeaders:          _requestHeaders,
		Secret:                  _secret,
		ExpirationTime:          _expirationTime,
		ExpirationTimeTolerance: _expirationTimeTolerance,
	}
}

//
type authorizationHeader struct {
	AccessKey       string
	Signature       string
	TimestampString string
	Timestamp       time.Time
}

// AuthorisationHandler :
func AuthorisationHandler(configuration *Configuration) func(http.ResponseWriter, *http.Request) {
	// Validate Configuration
	return func(w http.ResponseWriter, r *http.Request) {
		if configuration.Secret == nil {
			log.Fatalf("%s", "Secret key configuration is missing")
		}
		input, err := parseHeader(r.Header.Get("Authorization"))
		if err != nil {
			log.Panic(err)
		}
		err = configuration.isValidTimestamp(input.Timestamp)
		if err != nil {
			log.Panic(err)
		}
		stringToSign := (r.Method + "\n" + r.Host + "\n" + r.URL.RequestURI() + "\n" + input.TimestampString + "\n")
		sort.Strings(configuration.RequestHeaders)
		for _, header := range configuration.RequestHeaders {
			currentHeader := r.Header.Get(header)
			if currentHeader == "" {
				log.Panicf("%s", header)
			}
			stringToSign = stringToSign + currentHeader + "\n"
		}
		secretKey := configuration.Secret(input.AccessKey)
		if len(secretKey) == 0 {
			log.Panicf("Request API key is invalid")
		}
		hash := hmac.New(sha256.New, []byte(secretKey))
		hash.Write([]byte(stringToSign))
		encodedSignature := base64.StdEncoding.EncodeToString(hash.Sum(nil))
		if input.Signature != encodedSignature {
			log.Panicf("Request signature is invalid")
		}
	}
}
func parseHeader(header string) (*authorizationHeader, error) {
	if header == "" {
		return nil, fmt.Errorf("%s", "request missing authorization header")
	}

	input := new(authorizationHeader)
	parts := strings.Split(header, ",")
	for _, part := range parts {
		currentPart := strings.SplitN(strings.Trim(part, " "), "=", 2)
		switch currentPart[0] {
		case "AccessKey":
			{
				if len(input.AccessKey) > 0 {
					return nil, fmt.Errorf("Parameter [%s] is repeated in request header", currentPart[0])
				}
				input.AccessKey = currentPart[1]
			}
		case "Signature":
			{
				if len(input.Signature) > 0 {
					return nil, fmt.Errorf("Parameter [%s] is repeated in request header", currentPart[0])
				}
				input.Signature = currentPart[1]
			}
		case "Timestamp":
			{
				if !input.Timestamp.IsZero() {
					return nil, fmt.Errorf("Parameter [%s] is repeated in request header", currentPart[0])
				}
				var err error
				input.Timestamp, err = time.Parse(time.RFC3339, currentPart[1])
				if err != nil {
					return nil, fmt.Errorf("%s", "request header has invalid timestamp format .format RFC3339 required.")
				}
				input.TimestampString = currentPart[1]
			}
		default:
			return nil, fmt.Errorf("request header contains invalid parameter [%s]", currentPart[0])
		}

	}
	if len(input.AccessKey) == 0 && len(input.Signature) == 0 && input.Timestamp.IsZero() {
		return nil, fmt.Errorf("%s", "request header missing parameter.")
	}
	return input, nil
}

func (configuration *Configuration) isValidTimestamp(ts time.Time) error {
	reqAge := time.Since(ts)
	if reqAge < 0-configuration.ExpirationTimeTolerance {
		return fmt.Errorf("request header timestamp out of tolerated range of %d", configuration.ExpirationTimeTolerance)

	}

	if configuration.ExpirationTime != 0 {
		if reqAge > configuration.ExpirationTime {
			return fmt.Errorf("%s", "expired request signature")

		}
	}
	return nil
}
