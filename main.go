package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	_ "go.uber.org/automaxprocs"
	"go.uber.org/zap"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	metav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	kubemetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	ArvanCloudAPIBaseURL *url.URL    = nil
	logger               *zap.Logger = nil
)

type (
	arvanCloudDNSProviderGlobalConfig struct {
		GroupName            string `env:"GROUP_NAME" env-default:"acme.parmin.cloud"`
		ArvanCloudAPIBaseURL string `env:"ARVANCLOUD_API_BASE_URL" env-default:"https://napi.arvancloud.ir"`
		LogLevel             string `env:"LOG_LEVEL" env-default:"INFO"`
	}
	DNSRecord struct {
		ID    string            `json:"id,omitempty"`
		Type  string            `json:"type"`
		Name  string            `json:"name"`
		Value map[string]string `json:"value"`
		Cloud bool              `json:"cloud"`
		TTL   int               `json:"ttl,omitempty"`
	}

	DNSRecords struct {
		Data []DNSRecord `json:"data"`
	}
)

func main() {
	var cfg arvanCloudDNSProviderGlobalConfig

	err := cleanenv.ReadEnv(&cfg)
	if err != nil {
		panic(err)
	}
	cfg.ArvanCloudAPIBaseURL = strings.TrimSuffix(cfg.ArvanCloudAPIBaseURL, "/")

	logLevel, err := zap.ParseAtomicLevel(cfg.LogLevel)
	if err != nil {
		panic(fmt.Sprintf("Invalid Log Level: %v", err.Error()))
	}
	zapCfg := zap.NewProductionConfig()
	zapCfg.Level = logLevel
	var loggerErr error
	logger, loggerErr = zapCfg.Build()
	if loggerErr != nil {
		panic(loggerErr)
	}

	defer logger.Sync()

	ArvanCloudAPIBaseURL, err = url.ParseRequestURI(cfg.ArvanCloudAPIBaseURL)
	if err != nil {
		panic(err)
	}
	cmd.RunWebhookServer(cfg.GroupName,
		&arvanCloudDNSProviderSolver{},
	)
}

type arvanCloudDNSProviderSolver struct {
	kubeClient *kubernetes.Clientset
	httpClient *http.Client
}

type arvanCloudDNSProviderConfig struct {
	APIKey          string                   `json:"apiKey"`
	APIKeySecretRef metav1.SecretKeySelector `json:"apiKeySecretRef"`
}

func (cfg *arvanCloudDNSProviderConfig) GetAPIKey(namespace string, client *kubernetes.Clientset) (string, error) {
	if cfg.APIKey != "" {
		return cfg.APIKey, nil
	}
	if cfg.APIKeySecretRef.LocalObjectReference.Name == "" {
		return "", fmt.Errorf("You should provide one of apiKey or apiKeySecretRef")
	}
	secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), cfg.APIKeySecretRef.LocalObjectReference.Name, kubemetav1.GetOptions{})
	if err != nil {
		return "", err
	}
	data, ok := secret.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		return "", fmt.Errorf("key %v not found is %v/%v", cfg.APIKeySecretRef.Key, namespace, cfg.APIKeySecretRef.LocalObjectReference.Name)
	}
	return string(data), nil
}

func (c *arvanCloudDNSProviderSolver) Name() string {
	return "arvancloud"
}

func (c *arvanCloudDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	sugar := logger.Sugar()
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), ".")

	apiKey, err := cfg.GetAPIKey(ch.ResourceNamespace, c.kubeClient)
	if err != nil {
		return err
	}
	sugar.Infow(
		"Persisting record in ArvanCloud",
		"Name", name,
		"Type", "TXT",
		"Value", ch.Key,
	)

	var records DNSRecords

	_, err = c.SendAPIRequest("GET", "/cdn/4.0/domains/"+strings.TrimSuffix(ch.ResolvedZone, ".")+"/dns-records?type=txt&per_page=25&page=1&search="+name, apiKey, nil, &records)
	if err != nil {
		sugar.Errorw(
			"Error while getting records from ArvanCloud",
			"Name", name,
			"Type", "TXT",
			"Value", ch.Key,
			"Error", err.Error(),
		)
		return err
	}
	for _, record := range records.Data {
		if record.Name == name && record.Value["text"] == ch.Key {
			sugar.Infow(
				"Record Already Exist",
				"Name", record.Name,
				"Type", record.Type,
				"ID", record.ID,
			)
			return nil
		}
	}

	record := DNSRecord{
		Type:  "TXT",
		Cloud: false,
		Value: map[string]string{
			"text": ch.Key,
		},
		Name: name,
	}
	var createResponseBody any
	createResponse, err := c.SendAPIRequest("POST", "/cdn/4.0/domains/"+strings.TrimSuffix(ch.ResolvedZone, ".")+"/dns-records", apiKey, record, &createResponseBody)
	if err != nil {
		sugar.Errorw(
			"Error while creating record in ArvanCloud",
			"Name", name,
			"Type", "TXT",
			"Value", ch.Key,
			"Error", err.Error(),
		)
		return err
	}
	if createResponse.StatusCode != http.StatusCreated {
		sugar.Errorw(
			"API error while getting records from ArvanCloud",
			"Name", name,
			"Type", "TXT",
			"Value", ch.Key,
			"Status", createResponse.Status,
			"Body", createResponseBody,
		)
		return fmt.Errorf("Error while creating records in ArvanCloud, Status: %v, Body: %+v", createResponse.Status, createResponseBody)
	}
	sugar.Infow(
		"Successfully persisted record",
		"Name", name,
		"Type", "TXT",
		"Value", ch.Key,
	)
	return nil
}

func (c *arvanCloudDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	sugar := logger.Sugar()
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), ".")

	apiKey, err := cfg.GetAPIKey(ch.ResourceNamespace, c.kubeClient)
	if err != nil {
		return err
	}
	sugar.Infow(
		"Cleaning up record in ArvanCloud",
		"Name", name,
		"Type", "TXT",
		"Value", ch.Key,
	)
	var records DNSRecords

	_, err = c.SendAPIRequest("GET", "/cdn/4.0/domains/"+strings.TrimSuffix(ch.ResolvedZone, ".")+"/dns-records?type=txt&per_page=25&page=1&search="+name, apiKey, nil, &records)
	if err != nil {
		sugar.Errorw(
			"Error while getting records from ArvanCloud",
			"Name", name,
			"Type", "TXT",
			"Value", ch.Key,
			"Error", err.Error(),
		)
		return err
	}

	for _, record := range records.Data {
		if record.Name == name && record.Value["text"] == ch.Key {
			var cleanUpResponseBody any
			response, err := c.SendAPIRequest("DELETE", "/cdn/4.0/domains/"+strings.TrimSuffix(ch.ResolvedZone, ".")+"/dns-records/"+record.ID, apiKey, nil, &cleanUpResponseBody)
			if err != nil {
				sugar.Errorw(
					"Error while cleaning up records from ArvanCloud",
					"Name", name,
					"Type", "TXT",
					"Value", ch.Key,
					"Error", err.Error(),
				)
				return err
			}
			if response.StatusCode != http.StatusOK {
				sugar.Errorw(
					"API error while cleaning up records from ArvanCloud",
					"Name", name,
					"Type", "TXT",
					"Value", ch.Key,
					"Status", response.Status,
					"Body", cleanUpResponseBody,
				)
				return fmt.Errorf("API error while cleaning up records from ArvanCloud, Status: %v, Body: %+v", response.Status, cleanUpResponseBody)
			}
			sugar.Infow(
				"Record cleaned up in ArvanCloud",
				"Name", name,
				"Type", "TXT",
				"Value", ch.Key,
			)
			return nil
		}
	}
	sugar.Warnw(
		"Record not found to clean up in ArvanCloud",
		"Name", name,
		"Type", "TXT",
		"Value", ch.Key,
	)
	return nil
}

func (c *arvanCloudDNSProviderSolver) SendAPIRequest(method, uri, token string, requestBody any, responseBody any) (*http.Response, error) {
	sugar := logger.Sugar()
	tokenParts := strings.Split(token, " ")
	if len(tokenParts) != 2 {
		return nil, fmt.Errorf("Token is not valid, it should be in two parts")
	}
	rel, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	u := ArvanCloudAPIBaseURL.ResolveReference(rel)
	var buf io.ReadWriter
	if requestBody != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(requestBody)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", token)
	req.Header.Set("User-Agent", "ArvanCloud Issuer Webhook for CertManager")
	filteredHeaders := make(map[string]string)
	curlHeaders := ""
	for k, v := range req.Header {
		if k == "Authorization" {
			filteredHeaders[k] = tokenParts[0] + " " + strings.Repeat("#", len(tokenParts[1]))
			continue
		}
		curlHeaders += fmt.Sprintf(` -H %q`, fmt.Sprintf("%s: %s", k, v[0]))
		filteredHeaders[k] = v[0]
	}
	curlOpts := curlHeaders
	if requestBody != nil {
		body, _ := json.Marshal(requestBody)
		curlOpts += fmt.Sprintf(" -d %s", string(body))
	}
	sugar.Debugw(
		"Sending request to ArvanCloud API",
		"Headers", filteredHeaders,
		"Body", fmt.Sprintf("%+v", requestBody),
		"URL", u.String(),
		"cURL", fmt.Sprintf("curl -v -X %s %s '%s'", req.Method, curlOpts, u.String()),
	)
	startTime := time.Now()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	latency := startTime.Sub(time.Now())
	sugar.Debugw(
		"Request sent to ArvanCloud API",
		"URL", u.String(),
		"Status", resp.Status,
		"Took", latency.String(),
	)
	defer resp.Body.Close()
	if reflect.ValueOf(&responseBody).Kind() == reflect.Ptr {
		err = json.NewDecoder(resp.Body).Decode(responseBody)
	}
	return resp, err
}

func (c *arvanCloudDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.kubeClient = cl

	c.httpClient = &http.Client{
		Timeout: time.Duration(1) * time.Second,
	}
	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (arvanCloudDNSProviderConfig, error) {
	cfg := arvanCloudDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
