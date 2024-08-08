package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"github.com/ArtisanCloud/PowerLibs/v3/object"
	"github.com/ArtisanCloud/PowerWeChat/v3/src/kernel"
	response2 "github.com/ArtisanCloud/PowerWeChat/v3/src/kernel/response"
	"github.com/ArtisanCloud/PowerWeChat/v3/src/openPlatform/auth"
	"github.com/ArtisanCloud/PowerWeChat/v3/src/openPlatform/authorizer/miniProgram/auth/response"
)

type Client struct {
	*kernel.BaseClient

	// PowerWechat\OpenPlatform\Application
	component kernel.ApplicationInterface
}

func NewClient(app kernel.ApplicationInterface, component kernel.ApplicationInterface) (*Client, error) {
	baseClient, err := kernel.NewBaseClient(&app, nil)
	if err != nil {
		return nil, err
	}
	return &Client{
		baseClient,
		component,
	}, nil
}

// 小程序登录
// https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/2.0/api/others/WeChat_login.html
func (comp *Client) Session(ctx context.Context, code string) (*response.ResponseSession, error) {

	result := &response.ResponseSession{}

	config := (*comp.App).GetConfig()
	componentConfig := comp.component.GetConfig()
	token := comp.component.GetComponent("AccessToken").(*auth.AccessToken)
	componentToken, err := token.GetToken(false)

	query := &object.StringMap{
		"appid":                  config.GetString("app_id", ""),
		"js_code":                code,
		"grant_type":             "authorization_code",
		"component_appid":        componentConfig.GetString("app_id", ""),
		"component_access_token": componentToken.ComponentAccessToken,
	}
	_, err = comp.BaseClient.HttpGet(ctx, "sns/component/jscode2session", query, nil, result)

	return result, err
}

// 检测sessionKey是否有效
// https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/user-login/checkSessionKey.html
func (comp *Client) CheckSessionValid(ctx context.Context, openid, sessionKey string) (*response2.ResponseOpenPlatform, error) {
	result := &response2.ResponseOpenPlatform{}

	config := (*comp.App).GetConfig()
	componentConfig := comp.component.GetConfig()
	token := comp.component.GetComponent("AccessToken").(*auth.AccessToken)
	componentToken, err := token.GetToken(false)

	h := hmac.New(sha256.New, []byte{})
	h.Write([]byte(sessionKey))

	query := &object.StringMap{
		"openid":     openid,
		"signature":  string(h.Sum(nil)),
		"sig_method": "hmac_sha256",
	}

	_, err = comp.BaseClient.HttpGet(ctx, "wxa/checksession", query, nil, result)

	return result, err
}
