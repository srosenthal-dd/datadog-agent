// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build !ec2

package creds

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsRunningOnAWSNoEc2_IRSAEnvVars(t *testing.T) {
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/token")
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/test-role")
	assert.True(t, IsRunningOnAWS(context.Background()))
}

func TestIsRunningOnAWSNoEc2_ContainerRelativeURI(t *testing.T) {
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/abc123")
	assert.True(t, IsRunningOnAWS(context.Background()))
}

func TestIsRunningOnAWSNoEc2_ContainerFullURI(t *testing.T) {
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://localhost:8080/credentials")
	assert.True(t, IsRunningOnAWS(context.Background()))
}

func TestIsRunningOnAWSNoEc2_NoEnvVars(t *testing.T) {
	// Without any AWS-indicating env vars, should return false (no IMDS in non-ec2 build)
	assert.False(t, IsRunningOnAWS(context.Background()))
}

func TestGetAWSRegionNoEc2_EnvVar(t *testing.T) {
	t.Setenv("AWS_REGION", "eu-central-1")
	region, err := GetAWSRegion(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "eu-central-1", region)
}

func TestGetAWSRegionNoEc2_DefaultEnvVar(t *testing.T) {
	t.Setenv("AWS_DEFAULT_REGION", "ap-southeast-1")
	region, err := GetAWSRegion(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "ap-southeast-1", region)
}

func TestGetAWSRegionNoEc2_NoEnvVar(t *testing.T) {
	// No region in env -- should return error
	_, err := GetAWSRegion(context.Background())
	assert.Error(t, err)
}

func TestHasAWSWorkloadIdentityInEnvironment_BothSet(t *testing.T) {
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/token")
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/r")
	assert.True(t, HasAWSWorkloadIdentityInEnvironment())
}

func TestHasAWSWorkloadIdentityInEnvironment_OnlyToken(t *testing.T) {
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/token")
	assert.False(t, HasAWSWorkloadIdentityInEnvironment())
}

func TestHasAWSContainerCredentialsInEnvironment_RelativeURI(t *testing.T) {
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/creds")
	assert.True(t, HasAWSContainerCredentialsInEnvironment())
}
