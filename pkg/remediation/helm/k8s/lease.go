package k8s

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	defaultLeaseDurationSeconds int32 = 15
	defaultRenewInterval              = 5 * time.Second
)

// ErrLockActive is returned when a lease is currently held and not expired.
var ErrLockActive = errors.New("lease lock actively held by another process")

// LeaseLock represents an acquired distributed lease.
type LeaseLock struct {
	client      kubernetes.Interface
	namespace   string
	leaseName   string
	holderID    string
	stopRenewal chan struct{}
	wg          sync.WaitGroup
	released    bool
	mu          sync.Mutex
}

// LeaseStatus contains diagnostic information about a lease lock.
type LeaseStatus struct {
	Exists      bool
	Holder      string
	IsHeld      bool
	ExpiresIn   time.Duration
	LastRenewed time.Time
}

func ptrInt32(v int32) *int32 {
	return &v
}

// LeaseName returns the standard lease object name for a release.
func LeaseName(releaseName string) string {
	return fmt.Sprintf("helm-lock-%s", releaseName)
}

// GenerateHolderIdentity creates a unique holder identity.
func GenerateHolderIdentity() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown-host"
	}
	return fmt.Sprintf("%s_%d_%d", hostname, os.Getpid(), time.Now().UnixNano())
}

// CheckLease inspects whether a lease lock is currently active.
func CheckLease(ctx context.Context, client kubernetes.Interface, namespace, releaseName string) (*LeaseStatus, error) {
	name := LeaseName(releaseName)
	lease, err := client.CoordinationV1().Leases(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &LeaseStatus{Exists: false, IsHeld: false}, nil
		}
		return nil, fmt.Errorf("failed to get lease %s: %w", name, err)
	}

	holder := ""
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}

	if holder == "" {
		return &LeaseStatus{
			Exists: true,
			Holder: "",
			IsHeld: false,
		}, nil
	}

	now := time.Now()
	var lastRenewed time.Time
	if lease.Spec.RenewTime != nil {
		lastRenewed = lease.Spec.RenewTime.Time
	} else if lease.Spec.AcquireTime != nil {
		lastRenewed = lease.Spec.AcquireTime.Time
	}

	duration := time.Duration(defaultLeaseDurationSeconds) * time.Second
	if lease.Spec.LeaseDurationSeconds != nil {
		duration = time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second
	}

	expiresAt := lastRenewed.Add(duration)
	if now.Before(expiresAt) {
		return &LeaseStatus{
			Exists:      true,
			Holder:      holder,
			IsHeld:      true,
			ExpiresIn:   expiresAt.Sub(now),
			LastRenewed: lastRenewed,
		}, nil
	}

	return &LeaseStatus{
		Exists:      true,
		Holder:      holder,
		IsHeld:      false,
		ExpiresIn:   0,
		LastRenewed: lastRenewed,
	}, nil
}

// AcquireLease attempts to acquire the distributed lease lock for the release.
// It sets a 15-second duration and begins background renewal every 5 seconds.
func AcquireLease(ctx context.Context, client kubernetes.Interface, namespace, releaseName, holderID string) (*LeaseLock, error) {
	name := LeaseName(releaseName)
	if holderID == "" {
		holderID = GenerateHolderIdentity()
	}

	now := time.Now()
	microNow := metav1.MicroTime{Time: now}

	// Step 1: Check existing lease
	existing, err := client.CoordinationV1().Leases(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Create new lease
			newLease := &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
					Labels: map[string]string{
						"app.kubernetes.io/managed-by": "helm-unwedge",
						"helm.sh/release":             releaseName,
					},
				},
				Spec: coordinationv1.LeaseSpec{
					HolderIdentity:       &holderID,
					LeaseDurationSeconds: ptrInt32(defaultLeaseDurationSeconds),
					AcquireTime:          &microNow,
					RenewTime:            &microNow,
					LeaseTransitions:     ptrInt32(0),
				},
			}

			_, createErr := client.CoordinationV1().Leases(namespace).Create(ctx, newLease, metav1.CreateOptions{})
			if createErr == nil {
				lock := &LeaseLock{
					client:      client,
					namespace:   namespace,
					leaseName:   name,
					holderID:    holderID,
					stopRenewal: make(chan struct{}),
				}
				lock.startRenewal()
				return lock, nil
			}
			if !apierrors.IsAlreadyExists(createErr) {
				return nil, fmt.Errorf("failed to create lease %s: %w", name, createErr)
			}
			// If already exists, re-fetch below
			existing, err = client.CoordinationV1().Leases(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("failed to get lease %s after conflict: %w", name, err)
			}
		} else {
			return nil, fmt.Errorf("failed to inspect lease %s: %w", name, err)
		}
	}

	// Step 2: Validate if existing lease is expired or currently active
	if existing.Spec.HolderIdentity != nil && *existing.Spec.HolderIdentity != "" {
		var lastRenewed time.Time
		if existing.Spec.RenewTime != nil {
			lastRenewed = existing.Spec.RenewTime.Time
		} else if existing.Spec.AcquireTime != nil {
			lastRenewed = existing.Spec.AcquireTime.Time
		}

		duration := time.Duration(defaultLeaseDurationSeconds) * time.Second
		if existing.Spec.LeaseDurationSeconds != nil {
			duration = time.Duration(*existing.Spec.LeaseDurationSeconds) * time.Second
		}

		if now.Before(lastRenewed.Add(duration)) {
			remaining := lastRenewed.Add(duration).Sub(now)
			return nil, fmt.Errorf("%w: lease %s is held by %s (expires in %s)", ErrLockActive, name, *existing.Spec.HolderIdentity, remaining.Round(time.Second))
		}
	}

	// Step 3: Take over expired or unheld lease
	transitions := int32(0)
	if existing.Spec.LeaseTransitions != nil {
		transitions = *existing.Spec.LeaseTransitions + 1
	}
	existing.Spec.HolderIdentity = &holderID
	existing.Spec.LeaseDurationSeconds = ptrInt32(defaultLeaseDurationSeconds)
	existing.Spec.AcquireTime = &microNow
	existing.Spec.RenewTime = &microNow
	existing.Spec.LeaseTransitions = &transitions

	_, updateErr := client.CoordinationV1().Leases(namespace).Update(ctx, existing, metav1.UpdateOptions{})
	if updateErr != nil {
		return nil, fmt.Errorf("failed to acquire lease %s: %w", name, updateErr)
	}

	lock := &LeaseLock{
		client:      client,
		namespace:   namespace,
		leaseName:   name,
		holderID:    holderID,
		stopRenewal: make(chan struct{}),
	}
	lock.startRenewal()
	return lock, nil
}

func (l *LeaseLock) startRenewal() {
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		ticker := time.NewTicker(defaultRenewInterval)
		defer ticker.Stop()

		for {
			select {
			case <-l.stopRenewal:
				return
			case <-ticker.C:
				l.renewOnce()
			}
		}
	}()
}

func (l *LeaseLock) renewOnce() {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	lease, err := l.client.CoordinationV1().Leases(l.namespace).Get(ctx, l.leaseName, metav1.GetOptions{})
	if err != nil {
		return
	}

	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != l.holderID {
		return
	}

	now := metav1.MicroTime{Time: time.Now()}
	lease.Spec.RenewTime = &now
	_, _ = l.client.CoordinationV1().Leases(l.namespace).Update(ctx, lease, metav1.UpdateOptions{})
}

// Release stops background renewal and deletes the lease object.
func (l *LeaseLock) Release(ctx context.Context) error {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return nil
	}
	l.released = true
	close(l.stopRenewal)
	l.mu.Unlock()

	l.wg.Wait()

	deleteCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := l.client.CoordinationV1().Leases(l.namespace).Delete(deleteCtx, l.leaseName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to remove lease %s on release: %w", l.leaseName, err)
	}
	return nil
}
