// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build !ec2

package aws

import (
	"context"
	"os"

	"github.com/DataDog/datadog-agent/pkg/util/aws/creds"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// resolveCredentials implements an SDK-free credential chain for non-ec2 builds.
// Precedence (mirrors standard AWS SDK order for non-IMDS sources):
//  1. Static env vars (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)
//  2. Web identity / IRSA (AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ROLE_ARN)
//  3. Container credentials (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or _FULL_URI)
//  4. Empty -- downstream returns "missing AWS credentials"
func (a *AWSAuth) resolveCredentials(ctx context.Context) *creds.SecurityCredentials {
	// 1. Static env vars
	accessKeyID := os.Getenv(awsAccessKeyIDEnvVar)
	secretAccessKey := os.Getenv(awsSecretAccessKeyEnvVar)
	if accessKeyID != "" && secretAccessKey != "" {
		return &creds.SecurityCredentials{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
			Token:           os.Getenv(awsSessionTokenEnvVar),
		}
	}

	// 2. Web identity (IRSA / EKS OIDC)
	if os.Getenv(awsWebIdentityTokenFileEnvVar) != "" && os.Getenv(awsRoleARNEnvVar) != "" {
		c, err := a.resolveWebIdentityCredentials(ctx)
		if err != nil {
			log.Warnf("AWS web identity credential resolution failed: %v", err)
		} else if c != nil {
			return c
		}
	}

	// 3. Container credentials (ECS task role / EKS Pod Identity)
	if os.Getenv(awsContainerRelativeURIEnvVar) != "" || os.Getenv(awsContainerFullURIEnvVar) != "" {
		c, err := resolveContainerCredentials(ctx)
		if err != nil {
			log.Warnf("AWS container credential resolution failed: %v", err)
		} else if c != nil {
			return c
		}
	}

	return &creds.SecurityCredentials{}
}
