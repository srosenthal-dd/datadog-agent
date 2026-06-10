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
// This is a deliberate subset of the AWS SDK order -- shared config/SSO and IMDS
// are excluded; only env-based sources apply:
//  1. Static env vars (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)
//  2. Web identity / IRSA (AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ROLE_ARN)
//  3. Container credentials (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or _FULL_URI)
//  4. Empty -- downstream returns "missing AWS credentials"
func (a *AWSAuth) resolveCredentials(ctx context.Context) *creds.SecurityCredentials {
	// 1. Static env vars
	if creds.HasAWSCredentialsInEnvironment() {
		return &creds.SecurityCredentials{
			AccessKeyID:     os.Getenv(awsAccessKeyIDEnvVar),
			SecretAccessKey: os.Getenv(awsSecretAccessKeyEnvVar),
			Token:           os.Getenv(awsSessionTokenEnvVar),
		}
	}

	// 2. Web identity (IRSA / EKS OIDC)
	if creds.HasAWSWorkloadIdentityInEnvironment() {
		c, err := a.resolveWebIdentityCredentials(ctx)
		if err != nil {
			log.Warnf("AWS web identity credential resolution failed: %v", err)
		} else if c != nil {
			return c
		}
	}

	// 3. Container credentials (ECS task role / EKS Pod Identity)
	if creds.HasAWSContainerCredentialsInEnvironment() {
		c, err := resolveContainerCredentials(ctx)
		if err != nil {
			log.Warnf("AWS container credential resolution failed: %v", err)
		} else if c != nil {
			return c
		}
	}

	return &creds.SecurityCredentials{}
}
