package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/plugins/rest"
	"github.com/open-policy-agent/opa/util"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	PluginName          = "auth_plugin"
	ContentTypeHeader   = "Content-Type"
	JsonContentType     = "application/json"
	AuthorizationHeader = "Authorization"
)

type PluginFactory struct{}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type JWTToken struct {
	Exp int64 `json:"exp"`
}

type Config struct {
	AuthURL       string `json:"auth_url"`
	RefreshURL    string `json:"refresh_url"`
	AssignmentURL string `json:"assignment_url"`
	Login         string `json:"login"`
	Password      string `json:"password"`
	CaCertPath    string `json:"ca_path"`
	CertPath      string `json:"cert_path"`
	KeyPath       string `json:"key_path"`
}

type Plugin struct {
	manager      *plugins.Manager
	config       Config
	client       *http.Client
	stop         chan chan struct{}
	reconfig     chan interface{}
	accessToken  string
	refreshToken string
	expiry       time.Time
}

func (p *PluginFactory) New(manager *plugins.Manager, config interface{}) plugins.Plugin {
	return &Plugin{
		config:   *config.(*Config),
		manager:  manager,
		client:   &http.Client{},
		stop:     make(chan chan struct{}),
		reconfig: make(chan interface{}),
	}
}

func (p *PluginFactory) Validate(_ *plugins.Manager, config []byte) (interface{}, error) {
	var parsedConfig Config
	if err := util.Unmarshal(config, &parsedConfig); err != nil {
		return nil, err
	}
	return &parsedConfig, nil
}

func (p *Plugin) Start(_ context.Context) error {
	http.HandleFunc("/api/v2/public/assignments/search", p.handleHttp)
	http.HandleFunc("/api/v2/assignments/search", p.handleHttp)
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})

	go func() {
		if err := http.ListenAndServe(":8182", nil); err != nil {
			fmt.Println("Failed to start HTTP server:", err)
			os.Exit(1)
		}
	}()

	return nil
}

func (p *Plugin) Stop(_ context.Context) {
	done := make(chan struct{})
	p.stop <- done
	<-done
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

func (p *Plugin) Reconfigure(_ context.Context, config interface{}) {
	p.reconfig <- config
}

func (p *Plugin) NewClient(_ rest.Config) (*http.Client, error) {
	certPath := p.config.CertPath
	caCertPath := p.config.CaCertPath
	keyPath := p.config.KeyPath

	certFile, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore file: %v", err)
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file: %v", err)
	}

	keyFile, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read truststore file: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certFile)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	keyPool := x509.NewCertPool()
	keyPool.AppendCertsFromPEM(keyFile)

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore certificate and key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      caCertPool,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	p.client = client

	return p.client, nil
}

func (p *Plugin) Prepare(req *http.Request) error {
	if time.Now().Before(p.expiry) {
		req.Header.Add(AuthorizationHeader, fmt.Sprintf("Bearer %s", p.accessToken))
		log.Printf("Request for bundle. Use current token")
		return nil
	}

	log.Printf("Try to get token for bundle loading")

	token, err := p.getJWTToken()
	if err != nil {
		return err
	}

	p.accessToken = token.AccessToken
	p.refreshToken = token.RefreshToken
	p.expiry, err = p.getExpTime(p.accessToken)
	if err != nil {
		return err
	}

	log.Printf("Current time: %v, Token expiration time: %v", time.Now(), p.expiry)

	req.Header.Add(AuthorizationHeader, fmt.Sprintf("Bearer %s", p.accessToken))

	return nil
}

func (p *Plugin) handleHttp(w http.ResponseWriter, req *http.Request) {
	if time.Now().After(p.expiry) {

		log.Printf("Try to get token for /v2/assignments/search. Current time: %v, Token expiration time: %v", time.Now(), p.expiry)

		token, err := p.getJWTToken()
		if err == nil {
			p.accessToken = token.AccessToken
			p.refreshToken = token.RefreshToken
			p.expiry, err = p.getExpTime(p.accessToken)
		} else {
			http.Error(w, "Handle request from policy: failed to get auth token", http.StatusInternalServerError)
			return
		}
	}

	log.Printf("Request /v2/assignments/search. Use current token")

	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Handle request from policy: failed to read request body", http.StatusInternalServerError)
		return
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(req.Body)

	var requestData map[string]interface{}

	if err := json.Unmarshal(body, &requestData); err != nil {
		http.Error(w, "Handle request from policy: failed to parse JSON", http.StatusBadRequest)
		return
	}

	externalSystemCodes, ok := requestData["externalSystemCodes"].([]interface{})
	if !ok {
		http.Error(w, "Handle request from policy: externalSystemCodes not found or invalid type", http.StatusBadRequest)
		return
	}

	var systemCodes []string
	for _, code := range externalSystemCodes {
		if str, ok := code.(string); ok {
			systemCodes = append(systemCodes, str)
		} else {
			http.Error(w, "Handle request from policy: externalSystemCodes contains invalid type", http.StatusBadRequest)
			return
		}
	}

	assignmentsMap, err := p.getAssignments(p.accessToken, requestData)
	if err != nil {
		http.Error(w, "Handle request from policy: failed to get assignments", http.StatusInternalServerError)
		return
	}

	w.Header().Set(ContentTypeHeader, JsonContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(assignmentsMap)
}

func (p *Plugin) getJWTToken() (*TokenResponse, error) {
	var body map[string]string
	var url string

	if p.refreshToken == "" {
		body = map[string]string{
			"username": p.config.Login,
			"password": p.config.Password,
		}
		url = p.config.AuthURL

		log.Printf("Get token via /login url")
	} else {
		body = map[string]string{
			"refresh_token": p.refreshToken,
		}
		url = p.config.RefreshURL
		log.Printf("Get token via /refresh url")
	}

	token, err := p.requestJwtToken(body, url)

	return token, err
}

func (p *Plugin) requestJwtToken(body map[string]string, url string) (*TokenResponse, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}

	req.Header.Set(ContentTypeHeader, JsonContentType)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
}

func (p *Plugin) getExpTime(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("failed to parse token")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to decode token payload: %v", err)
	}

	var parsedToken JWTToken
	if err := json.Unmarshal(payload, &parsedToken); err != nil {
		return time.Time{}, fmt.Errorf("failed to unmarshal token payload: %v", err)
	}

	tokenExpSeconds := time.Unix(parsedToken.Exp, 0)
	expTime := time.Now().Add(tokenExpSeconds.Sub(time.Now()))

	return expTime, nil
}

func (p *Plugin) getAssignments(authToken string, body map[string]interface{}) ([]byte, error) {
	b, err := json.Marshal(body)
	req, err := http.NewRequest("PUT", p.config.AssignmentURL, bytes.NewBuffer(b))
	if err != nil {
		return []byte{}, err
	}

	req.Header.Set(ContentTypeHeader, JsonContentType)
	req.Header.Set(AuthorizationHeader, "Bearer "+authToken)

	resp, err := p.client.Do(req)
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Get assignments: error occurred: ", err)
		return []byte{}, err
	}

	return bodyBytes, nil
}
