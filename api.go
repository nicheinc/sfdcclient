package sfdcclient

import (
	"fmt"
	"strings"
)

/*****************************************/
/*  Salesforce auth token response type  */
/*****************************************/

// AccessTokenResponse represents a successful response of a requests to salesforce for an OAuth token
// https://${yourInstance}.salesforce.com/services/oauth2/token
type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	Instance    string `json:"instance_url"`
	ID          string `json:"id"`
	TokenType   string `json:"token_type"`
}

// OAuthErr represents an error that occurs during the OAuth authorization flow
// https://help.salesforce.com/articleView?id=remoteaccess_oauth_flow_errors.htm&type=5
type OAuthErr struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *OAuthErr) Error() string {
	return fmt.Sprintf("OAuth authorization error code: %s, description: %s", e.Code, e.Description)
}

/**********************************************/
/*  Salesforce REST API error response types  */
/**********************************************/

// APIErrs represents an error response from salesforce REST API endpoints
// Example:
// [
//     {
// 			"statusCode": "MALFORMED_ID",
// 			"message": "SomeSaleforceObject ID: id value of incorrect type: 1234",
// 			"fields": [
// 				"Id"
// 			]
//     }
// ]
type APIErrs []APIErr

func (e *APIErrs) Error() string {
	var str []string
	if e != nil {
		for _, e := range *e {
			str = append(str, e.Error())
		}
	}
	return strings.Join(str, "|")
}

type APIErr struct {
	Message string   `json:"message"`
	ErrCode string   `json:"errorCode"`
	Fields  []string `json:"fields"`
}

func (e *APIErr) Error() string {
	if len(e.Fields) > 0 {
		return fmt.Sprintf("error code: %s, message: %s, fields: %s", e.ErrCode, e.Message, strings.Join(e.Fields, ","))
	}
	return fmt.Sprintf("error code: %s, message: %s", e.ErrCode, e.Message)
}
