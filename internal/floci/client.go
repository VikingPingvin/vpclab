// Package floci builds AWS SDK clients pointed at the local Floci endpoint.
package floci

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

const DefaultEndpoint = "http://localhost:4566"

// Endpoint returns FLOCI_ENDPOINT, or the default local endpoint.
func Endpoint() string {
	if e := os.Getenv("FLOCI_ENDPOINT"); e != "" {
		return e
	}
	return DefaultEndpoint
}

// Config returns an AWS config for Floci. vpcsim is a trusted system
// component, so it uses Floci's "test" key, which bypasses IAM enforcement;
// learners use real IAM users or roles.
func Config(ctx context.Context) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
		config.WithBaseEndpoint(Endpoint()),
	)
}

// EC2 returns an EC2 client for Floci.
func EC2(ctx context.Context) (*ec2.Client, error) {
	cfg, err := Config(ctx)
	if err != nil {
		return nil, err
	}
	return ec2.NewFromConfig(cfg), nil
}
