package engine

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"

	"github.com/aws/smithy-go"
	"github.com/x7ssss/x7/pkg/remediation/aws/logger"
)

// IsDependencyViolation checks whether an error indicates a transient dependency lock
// such as DependencyViolation or ResourceInUse.
func IsDependencyViolation(err error) bool {
	if err == nil {
		return false
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		switch code {
		case "DependencyViolation",
			"ResourceInUse",
			"InvalidGroup.InUse",
			"InvalidSubnetID.InUse",
			"Client.DependencyViolation",
			"SubnetInUse":
			return true
		}
	}

	msg := err.Error()
	return strings.Contains(msg, "DependencyViolation") ||
		strings.Contains(msg, "ResourceInUse") ||
		strings.Contains(msg, "is currently in use")
}

// CalculateFullJitter implements the AWS full-jitter formula:
// sleep = random(0, min(maxDelay, baseDelay * 2^attempt))
func CalculateFullJitter(attempt int, baseDelay time.Duration, maxDelay time.Duration, randFloat func() float64) time.Duration {
	if baseDelay <= 0 {
		baseDelay = 100 * time.Millisecond
	}
	if maxDelay <= 0 {
		maxDelay = 15 * time.Second
	}

	temp := float64(baseDelay) * math.Pow(2, float64(attempt))
	capDelay := float64(maxDelay)
	if temp > capDelay || math.IsInf(temp, 0) {
		temp = capDelay
	}

	if randFloat == nil {
		randFloat = rand.Float64
	}

	sleep := time.Duration(randFloat() * temp)
	if sleep < 0 {
		return baseDelay
	}
	return sleep
}

// RetryOnDependencyViolation retries an AWS deletion operation with full jitter backoff
// as long as DependencyViolation or ResourceInUse errors occur.
func RetryOnDependencyViolation(
	ctx context.Context,
	opName string,
	timeout time.Duration,
	baseDelay time.Duration,
	maxDelay time.Duration,
	fn func() error,
	log logger.Logger,
) error {
	deadline := time.Now().Add(timeout)
	attempt := 0

	for {
		err := fn()
		if err == nil || isNotFoundError(err) {
			return nil
		}

		if !IsDependencyViolation(err) {
			// Non-transient error, return immediately
			return err
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("operation %s timed out after %v waiting for dependency release: %w", opName, timeout, err)
		}

		sleep := CalculateFullJitter(attempt, baseDelay, maxDelay, rand.Float64)
		if log != nil {
			log.Debug("%s encountered transient dependency lock (%v); retrying in %v (attempt %d)...",
				opName, err, sleep, attempt+1)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}

		attempt++
	}
}
