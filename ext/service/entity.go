package service

type AuthValidateRequest struct {
	Header        map[string]string
	Path          string
	TargetService string
}

type AuthValidateResponse struct {
	IsValid       bool
	InjectHeaders map[string]string
}
