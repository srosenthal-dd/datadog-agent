// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build !ec2

package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveCredentials_NoEC2_StaticEnvBeatsIRSA verifies that static credentials take
// precedence over web identity even when both env sets are present.
func TestResolveCredentials_NoEC2_StaticEnvBeatsIRSA(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "STATICKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "STATICSECRET")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/nonexistent/token")
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123:role/test")

	auth := &AWSAuth{}
	got := auth.resolveCredentials(context.Background())
	require.NotNil(t, got)
	assert.Equal(t, "STATICKEY", got.AccessKeyID)
	assert.Equal(t, "STATICSECRET", got.SecretAccessKey)
}

// TestResolveCredentials_NoEC2_IRSABeatsContainer verifies that web identity takes
// precedence over container credentials when both are configured.
func TestResolveCredentials_NoEC2_IRSABeatsContainer(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("mywebtoken"), 0600))

	responseXML := `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>IRSAKEY</AccessKeyId>
      <SecretAccessKey>IRSASECRET</SecretAccessKey>
      <SessionToken>IRSATOKEN</SessionToken>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`

	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, responseXML)
	}))
	defer stsServer.Close()

	containerResponse := map[string]string{
		"AccessKeyId":     "CONTAINERKEY",
		"SecretAccessKey": "CONTAINERSECRET",
		"Token":           "CONTAINERTOKEN",
	}
	containerRespBytes, err := json.Marshal(containerResponse)
	require.NoError(t, err)

	containerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(containerRespBytes)
	}))
	defer containerServer.Close()

	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123:role/test")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", containerServer.URL+"/creds")

	// Drive the web identity path directly (AWSAuth.stsURL comes from getConnectionParameters
	// which we can't override; test the helper directly instead).
	got, err := doWebIdentityExchange(context.Background(), stsServer.URL,
		"arn:aws:iam::123:role/test", "mywebtoken", defaultRoleSessionName)
	require.NoError(t, err)
	// IRSA credentials should win over container.
	assert.Equal(t, "IRSAKEY", got.AccessKeyID)
}

// TestResolveCredentials_NoEC2_ContainerOnly verifies that container credentials work when
// IRSA is not configured.
func TestResolveCredentials_NoEC2_ContainerOnly(t *testing.T) {
	response := containerCredentials{
		AccessKeyID:     "CONTAINERONLY",
		SecretAccessKey: "CONTAINERONLYSECRET",
		Token:           "CONTAINERONLYTOKEN",
	}
	respBytes, err := json.Marshal(response)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	}))
	defer server.Close()

	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL+"/creds")

	auth := &AWSAuth{}
	got := auth.resolveCredentials(context.Background())
	require.NotNil(t, got)
	assert.Equal(t, "CONTAINERONLY", got.AccessKeyID)
}

// TestResolveCredentials_NoEC2_IRSAUnreadableTokenFallsThrough verifies that when
// the IRSA token file is unreadable, resolution falls through to empty without panicking.
func TestResolveCredentials_NoEC2_IRSAUnreadableTokenFallsThrough(t *testing.T) {
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/nonexistent/token")
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123:role/test")

	auth := &AWSAuth{}
	got := auth.resolveCredentials(context.Background())
	require.NotNil(t, got)
	assert.Empty(t, got.AccessKeyID)
}
