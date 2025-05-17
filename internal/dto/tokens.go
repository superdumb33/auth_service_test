package dto

type IssueTokensResponse struct {
	AccessToken  string`json:"access_token"`
	RefreshToken string`json:"refresh_token"`
}

type RefreshTokensRequest struct {
	AccessToken string`json:"access_token"`
	RefreshToken string`json:"refresh_token"`
}

type RefreshTokensResponse struct {
	AccessToken string`json:"access_token"`
	RefreshToken string`json:"refresh_token"`
}
