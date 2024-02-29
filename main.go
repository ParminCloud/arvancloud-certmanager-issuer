package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
	_ "go.uber.org/automaxprocs"
	"go.uber.org/zap"
	"io"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	metav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	kubemetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TODO: Change how we are managing configurations
var (
	ArvanCloudAPIBaseURL *url.URL = nil
	logger, loggerErr             = zap.NewProduction()
)

type (
	arvanCloudDNSProviderGlobalConfig struct {
		GroupName            string `env:"GROUP_NAME" env-default:"https://napi.arvancloud.ir"`
		ArvanCloudAPIBaseURL string `env:"ARVANCLOUD_API_BASE_URL" env-default:"acme.parmin.cloud"`
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
	if loggerErr != nil {
		panic(loggerErr)
	}
	defer logger.Sync()

	var cfg arvanCloudDNSProviderGlobalConfig

	err := cleanenv.ReadEnv(&cfg)
	if err != nil {
		panic(err)
	}
	cfg.ArvanCloudAPIBaseURL = strings.TrimSuffix(cfg.ArvanCloudAPIBaseURL, "/")

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
	apiKey, err := cfg.GetAPIKey(ch.ResourceNamespace, c.kubeClient)
	if err != nil {
		return err
	}
	var records DNSRecords

	_, err = c.SendAPIRequest("GET", "/cdn/4.0/domains/"+strings.TrimSuffix(ch.ResolvedZone, ".")+"/dns-records", apiKey, nil, &records)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), ".")
	for _, record := range records.Data {
		if record.Name == name && record.Type == "TXT" && record.Value["text"] == ch.Key {
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
	createResponse, err := c.SendAPIRequest("GET", "/cdn/4.0/domains/"+strings.TrimSuffix(ch.ResolvedZone, ".")+"/dns-records", apiKey, record, &createResponseBody)
	if err != nil {
		return err
	}
	if createResponse.StatusCode != http.StatusCreated {
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
	apiKey, err := cfg.GetAPIKey(ch.ResourceNamespace, c.kubeClient)
	if err != nil {
		return err
	}

	var records DNSRecords

	_, err = c.SendAPIRequest("GET", "/cdn/4.0/domains/"+strings.TrimSuffix(ch.ResolvedZone, ".")+"/dns-records", apiKey, nil, &records)
	if err != nil {
		return err
	}

	name := strings.TrimSuffix(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), ".")
	for _, record := range records.Data {
		if record.Name == name && record.Type == "TXT" && record.Value["text"] == ch.Key {
			var cleanUpResponseBody any
			response, err := c.SendAPIRequest("DELETE", "/cdn/4.0/domains/"+strings.TrimSuffix(ch.ResolvedZone, ".")+"/dns-records/"+record.ID, apiKey, nil, cleanUpResponseBody)
			if err != nil {
				return err
			}
			if response.StatusCode != http.StatusOK {
				return fmt.Errorf("Error while cleaning up records from ArvanCloud, Status: %v, Body: %+v", response.Status, cleanUpResponseBody)
			}
			return nil
		}
	}
	sugar.Warnw(
		"Record not found to crean up in ArvanCloud",
		"Name", name,
		"Type", "TXT",
		"Value", ch.Key,
	)
	return nil
}

func (c *arvanCloudDNSProviderSolver) SendAPIRequest(method, uri, token string, requestBody any, responseBody any) (*http.Response, error) {
	if len(strings.Split(token, " ")) != 2 {
		return nil, fmt.Errorf("Token is not valid, it should be in two parts")
	}
	rel := &url.URL{Path: uri}
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
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(responseBody)
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
