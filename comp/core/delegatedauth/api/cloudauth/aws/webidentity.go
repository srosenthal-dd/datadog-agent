// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

// Package aws provides the implementation for aws auth exchange
package aws

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/aws/creds"
)

const (
	awsWebIdentityTokenFileEnvVar = "AWS_WEB_IDENTITY_TOKEN_FILE"
	awsRoleARNEnvVar              = "AWS_ROLE_ARN"
	awsRoleSessionNameEnvVar      = "AWS_ROLE_SESSION_NAME"
	defaultRoleSessionName        = "datadog-agent"

	awsContainerRelativeURIEnvVar   = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
	awsContainerFullURIEnvVar       = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
	awsContainerAuthTokenEnvVar     = "AWS_CONTAINER_AUTHORIZATION_TOKEN"
	awsContainerAuthTokenFileEnvVar = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"
	containerCredentialsBaseURL     = "http://169.254.170.2"
)

// assumeRoleWithWebIdentityResponse is the parsed XML response from STS AssumeRoleWithWebIdentity
type assumeRoleWithWebIdentityResponse struct {
	XMLName xml.Name                        `xml:"AssumeRoleWithWebIdentityResponse"`
	Result  assumeRoleWithWebIdentityResult `xml:"AssumeRoleWithWebIdentityResult"`
}

type assumeRoleWithWebIdentityResult struct {
	Credentials stsCredentials `xml:"Credentials"`
}

type stsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

// resolveWebIdentityCredentials exchanges a web identity token for STS credentials.
// It reads the token from the file at AWS_WEB_IDENTITY_TOKEN_FILE and POSTs to STS.
// Returns nil if the required env vars are not set.
func (a *AWSAuth) resolveWebIdentityCredentials(ctx context.Context) (*creds.SecurityCredentials, error) {
	tokenFile := os.Getenv(awsWebIdentityTokenFileEnvVar)
	roleARN := os.Getenv(awsRoleARNEnvVar)
	if tokenFile == "" || roleARN == "" {
		return nil, nil
	}

	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read web identity token file %q: %w", tokenFile, err)
	}
	webIdentityToken := strings.TrimSpace(string(tokenBytes))

	sessionName := os.Getenv(awsRoleSessionNameEnvVar)
	if sessionName == "" {
		sessionName = defaultRoleSessionName
	}

	// Use the configured STS endpoint (same host resolution as signing code)
	stsURL, _, _ := a.getConnectionParameters()

	return doWebIdentityExchange(ctx, stsURL, roleARN, webIdentityToken, sessionName)
}

// doWebIdentityExchange performs the STS AssumeRoleWithWebIdentity HTTP call.
// Extracted for testability -- callers can inject a custom stsURL (e.g. httptest server).
func doWebIdentityExchange(ctx context.Context, stsURL, roleARN, webIdentityToken, roleSessionName string) (*creds.SecurityCredentials, error) {
	formData := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {roleARN},
		"WebIdentityToken": {webIdentityToken},
		"RoleSessionName":  {roleSessionName},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stsURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create STS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("STS AssumeRoleWithWebIdentity request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read STS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("STS AssumeRoleWithWebIdentity returned status %d: %s", resp.StatusCode, string(body))
	}

	var result assumeRoleWithWebIdentityResponse
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse STS response: %w", err)
	}

	c := result.Result.Credentials
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil, fmt.Errorf("STS response contained empty credentials")
	}

	return &creds.SecurityCredentials{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		Token:           c.SessionToken,
	}, nil
}

// containerCredentials is the JSON body returned by the container credentials endpoint
type containerCredentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
}

// resolveContainerCredentials fetches credentials from the container credentials endpoint.
// Supports both relative URI (ECS task role / EKS Pod Identity) and full URI variants.
// Returns nil if neither env var is set.
func resolveContainerCredentials(ctx context.Context) (*creds.SecurityCredentials, error) {
	var credURL string
	var authHeader string

	if relativeURI := os.Getenv(awsContainerRelativeURIEnvVar); relativeURI != "" {
		credURL = containerCredentialsBaseURL + relativeURI
	} else if fullURI := os.Getenv(awsContainerFullURIEnvVar); fullURI != "" {
		credURL = fullURI
		// Auth token from env var or file (full URI only)
		if token := os.Getenv(awsContainerAuthTokenEnvVar); token != "" {
			authHeader = token
		} else if tokenFile := os.Getenv(awsContainerAuthTokenFileEnvVar); tokenFile != "" {
			tokenBytes, err := os.ReadFile(tokenFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read container auth token file %q: %w", tokenFile, err)
			}
			authHeader = strings.TrimSpace(string(tokenBytes))
		}
	} else {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, credURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create container credentials request: %w", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("container credentials request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read container credentials response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("container credentials endpoint returned status %d", resp.StatusCode)
	}

	// Parse JSON
	var parsed containerCredentials
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse container credentials: %w", err)
	}

	if parsed.AccessKeyID == "" || parsed.SecretAccessKey == "" {
		return nil, fmt.Errorf("container credentials response contained empty credentials")
	}

	return &creds.SecurityCredentials{
		AccessKeyID:     parsed.AccessKeyID,
		SecretAccessKey: parsed.SecretAccessKey,
		Token:           parsed.Token,
	}, nil
}
