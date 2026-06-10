// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build !ec2

package creds

import (
	"context"
	"errors"
	"os"
)

// HasAWSWorkloadIdentityInEnvironment returns true if IRSA (EKS web identity) env vars are present.
func HasAWSWorkloadIdentityInEnvironment() bool {
	return os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "" && os.Getenv("AWS_ROLE_ARN") != ""
}

// HasAWSContainerCredentialsInEnvironment returns true if ECS/EKS Pod Identity container credential env vars are present.
func HasAWSContainerCredentialsInEnvironment() bool {
	return os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "" ||
		os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") != ""
}

// IsRunningOnAWS returns true when IRSA or container credential env vars are present.
// IMDS is not available without the ec2 build tag.
func IsRunningOnAWS(_ context.Context) bool {
	return HasAWSWorkloadIdentityInEnvironment() || HasAWSContainerCredentialsInEnvironment()
}

// GetAWSRegion returns the AWS region from environment variables.
// IMDS is not available without the ec2 build tag.
func GetAWSRegion(_ context.Context) (string, error) {
	if region := os.Getenv("AWS_REGION"); region != "" {
		return region, nil
	}
	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" {
		return region, nil
	}
	return "", errors.New("no AWS region found in environment (AWS_REGION or AWS_DEFAULT_REGION)")
}
