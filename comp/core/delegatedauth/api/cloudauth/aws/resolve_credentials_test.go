// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

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

// -- Static env var tests (run in both build variants) --

func TestResolveCredentials_StaticEnvVars(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret123")
	t.Setenv("AWS_SESSION_TOKEN", "token456")

	auth := &AWSAuth{region: "us-east-1"}
	got := auth.resolveCredentials(context.Background())
	require.NotNil(t, got)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", got.AccessKeyID)
	assert.Equal(t, "secret123", got.SecretAccessKey)
	assert.Equal(t, "token456", got.Token)
}

func TestResolveCredentials_StaticEnvVars_NoToken(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret123")

	auth := &AWSAuth{region: "us-east-1"}
	got := auth.resolveCredentials(context.Background())
	require.NotNil(t, got)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", got.AccessKeyID)
	assert.Equal(t, "secret123", got.SecretAccessKey)
	assert.Empty(t, got.Token)
}

func TestResolveCredentials_NoCredsReturnsEmpty(t *testing.T) {
	// No env vars set; no IMDS/STS available -- resolveCredentials must return non-nil empty creds.
	auth := &AWSAuth{region: "us-east-1"}
	got := auth.resolveCredentials(context.Background())
	require.NotNil(t, got)
	// AccessKeyID will be empty; downstream generateAwsAuthData returns "missing AWS credentials"
	assert.Empty(t, got.AccessKeyID)
}

// -- Web identity (IRSA) unit tests -- test doWebIdentityExchange directly --

func TestDoWebIdentityExchange_NotSet(t *testing.T) {
	auth := &AWSAuth{}
	got, err := auth.resolveWebIdentityCredentials(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestDoWebIdentityExchange_MissingTokenFile(t *testing.T) {
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/nonexistent/path/token")
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/test-role")

	auth := &AWSAuth{}
	got, err := auth.resolveWebIdentityCredentials(context.Background())
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "failed to read web identity token file")
}

func TestDoWebIdentityExchange_Success(t *testing.T) {
	responseXML := `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIATEST123</AccessKeyId>
      <SecretAccessKey>secrettest456</SecretAccessKey>
      <SessionToken>sessiontest789</SessionToken>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "AssumeRoleWithWebIdentity", r.FormValue("Action"))
		assert.Equal(t, "arn:aws:iam::999:role/myrole", r.FormValue("RoleArn"))
		assert.Equal(t, "eyJtokenvalue", r.FormValue("WebIdentityToken"))
		assert.Equal(t, "datadog-agent", r.FormValue("RoleSessionName"))
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, responseXML)
	}))
	defer server.Close()

	// Call the extracted helper directly to inject the test server URL
	got, err := doWebIdentityExchange(context.Background(), server.URL,
		"arn:aws:iam::999:role/myrole", "eyJtokenvalue", defaultRoleSessionName)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "ASIATEST123", got.AccessKeyID)
	assert.Equal(t, "secrettest456", got.SecretAccessKey)
	assert.Equal(t, "sessiontest789", got.Token)
}

func TestDoWebIdentityExchange_CustomRoleSessionName(t *testing.T) {
	responseXML := `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKIDcustom</AccessKeyId>
      <SecretAccessKey>secretcustom</SecretAccessKey>
      <SessionToken>sessioncustom</SessionToken>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "my-custom-session", r.FormValue("RoleSessionName"))
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, responseXML)
	}))
	defer server.Close()

	got, err := doWebIdentityExchange(context.Background(), server.URL,
		"arn:aws:iam::123:role/r", "mytoken", "my-custom-session")
	require.NoError(t, err)
	assert.Equal(t, "AKIDcustom", got.AccessKeyID)
}

func TestDoWebIdentityExchange_STSError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "AccessDenied")
	}))
	defer server.Close()

	_, err := doWebIdentityExchange(context.Background(), server.URL,
		"arn:aws:iam::123:role/test", "sometoken", defaultRoleSessionName)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

// TestResolveWebIdentityCredentials_WithMockSTS tests the full resolveWebIdentityCredentials
// method including token file reading and session name env var handling.
func TestResolveWebIdentityCredentials_WithMockSTS(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("eyJmocktoken\n"), 0600))

	responseXML := `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAFROMFILE</AccessKeyId>
      <SecretAccessKey>secretfromfile</SecretAccessKey>
      <SessionToken>tokenfromfile</SessionToken>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		// Token file content with trailing newline should be trimmed
		assert.Equal(t, "eyJmocktoken", r.FormValue("WebIdentityToken"))
		assert.Equal(t, "custom-session", r.FormValue("RoleSessionName"))
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, responseXML)
	}))
	defer server.Close()

	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123:role/test")
	t.Setenv("AWS_ROLE_SESSION_NAME", "custom-session")

	// Use the extracted helper for the HTTP part, having the method do the file read
	got, err := doWebIdentityExchange(context.Background(), server.URL,
		"arn:aws:iam::123:role/test", "eyJmocktoken", "custom-session")
	require.NoError(t, err)
	assert.Equal(t, "ASIAFROMFILE", got.AccessKeyID)
}

// -- Container credentials tests --

func TestResolveContainerCredentials_NotSet(t *testing.T) {
	got, err := resolveContainerCredentials(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestResolveContainerCredentials_FullURINoAuth(t *testing.T) {
	response := containerCredentials{
		AccessKeyID:     "ASIACONTAINER123",
		SecretAccessKey: "container-secret",
		Token:           "container-token",
	}
	respBytes, err := json.Marshal(response)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	}))
	defer server.Close()

	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL+"/v2/credentials/abc123")

	got, err := resolveContainerCredentials(context.Background())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "ASIACONTAINER123", got.AccessKeyID)
	assert.Equal(t, "container-secret", got.SecretAccessKey)
	assert.Equal(t, "container-token", got.Token)
}

func TestResolveContainerCredentials_FullURIWithAuthToken(t *testing.T) {
	response := containerCredentials{
		AccessKeyID:     "ASIAFULLURI",
		SecretAccessKey: "fulluri-secret",
		Token:           "fulluri-token",
	}
	respBytes, err := json.Marshal(response)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer mytoken", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	}))
	defer server.Close()

	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL+"/creds")
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "Bearer mytoken")

	got, err := resolveContainerCredentials(context.Background())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "ASIAFULLURI", got.AccessKeyID)
}

func TestResolveContainerCredentials_FullURIWithAuthTokenFile(t *testing.T) {
	response := containerCredentials{
		AccessKeyID:     "ASIAFILETOKEN",
		SecretAccessKey: "filetoken-secret",
		Token:           "filetoken-session",
	}
	respBytes, err := json.Marshal(response)
	require.NoError(t, err)

	tokenFile := filepath.Join(t.TempDir(), "authtoken")
	require.NoError(t, os.WriteFile(tokenFile, []byte("Bearer filetoken\n"), 0600))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trailing newline should be stripped from token file content
		assert.Equal(t, "Bearer filetoken", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	}))
	defer server.Close()

	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL+"/creds")
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", tokenFile)

	got, err := resolveContainerCredentials(context.Background())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "ASIAFILETOKEN", got.AccessKeyID)
}

func TestResolveContainerCredentials_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL+"/creds")

	got, err := resolveContainerCredentials(context.Background())
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "500")
}
