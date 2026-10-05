package locking

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/pointer"
)

const (
	DefaultLeaseName      = "k8s-unstuck-lock"
	DefaultLeaseNamespace = "kube-system"
	DefaultLeaseDuration  = 60 // 60 seconds
)

// LeaseManager manages mutual exclusion using the Kubernetes coordination.k8s.io/v1 Lease API.
type LeaseManager interface {
	Acquire(ctx context.Context) error
	Release(ctx context.Context) error
	HolderIdentity() string
}

type k8sLeaseManager struct {
	client         kubernetes.Interface
	namespace      string
	leaseName      string
	durationSec    int32
	holderIdentity string

	mu        sync.Mutex
	stopRenew chan struct{}
	released  bool
}

// NewLeaseManager creates a new LeaseManager instance with a fresh execution UUID.
func NewLeaseManager(client kubernetes.Interface, namespace, leaseName string, durationSeconds int32) LeaseManager {
	if namespace == "" {
		namespace = DefaultLeaseNamespace
	}
	if leaseName == "" {
		leaseName = DefaultLeaseName
	}
	if durationSeconds <= 0 {
		durationSeconds = DefaultLeaseDuration
	}

	return &k8sLeaseManager{
		client:         client,
		namespace:      namespace,
		leaseName:      leaseName,
		durationSec:    durationSeconds,
		holderIdentity: uuid.New().String(),
		stopRenew:      make(chan struct{}),
	}
}

// HolderIdentity returns the unique execution identity for this manager.
func (m *k8sLeaseManager) HolderIdentity() string {
	return m.holderIdentity
}

// Acquire acquires or renews the lease, failing immediately if another active execution holds it.
func (m *k8sLeaseManager) Acquire(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	leaseClient := m.client.CoordinationV1().Leases(m.namespace)
	now := time.Now()
	nowMicro := metav1.MicroTime{Time: now}

	lease, err := leaseClient.Get(ctx, m.leaseName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Lease doesn't exist yet, create it
		newLease := &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:      m.leaseName,
				Namespace: m.namespace,
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       pointer.String(m.holderIdentity),
				LeaseDurationSeconds: pointer.Int32(m.durationSec),
				AcquireTime:          &nowMicro,
				RenewTime:            &nowMicro,
				LeaseTransitions:     pointer.Int32(0),
			},
		}

		if _, err := leaseClient.Create(ctx, newLease, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create lease %s/%s: %w", m.namespace, m.leaseName, err)
		}

		m.startHeartbeat()
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get lease %s/%s: %w", m.namespace, m.leaseName, err)
	}

	// Lease exists: check whether it is actively held by another process
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != "" && *lease.Spec.HolderIdentity != m.holderIdentity {
		var lastActive time.Time
		if lease.Spec.RenewTime != nil {
			lastActive = lease.Spec.RenewTime.Time
		} else if lease.Spec.AcquireTime != nil {
			lastActive = lease.Spec.AcquireTime.Time
		}

		duration := time.Duration(m.durationSec) * time.Second
		if lease.Spec.LeaseDurationSeconds != nil && *lease.Spec.LeaseDurationSeconds > 0 {
			duration = time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second
		}

		if !lastActive.IsZero() && now.Before(lastActive.Add(duration)) {
			// Lease is still valid and held by another instance!
			expiresIn := time.Until(lastActive.Add(duration)).Round(time.Second)
			return fmt.Errorf("contention detected: active lease %s/%s is held by %q (expires in %s at %s)",
				m.namespace, m.leaseName, *lease.Spec.HolderIdentity, expiresIn, lastActive.Add(duration).Format(time.RFC3339))
		}
	}

	// Lease is expired, unheld, or already held by us; update it to acquire
	var transitions int32
	if lease.Spec.LeaseTransitions != nil {
		transitions = *lease.Spec.LeaseTransitions + 1
	}

	lease.Spec.HolderIdentity = pointer.String(m.holderIdentity)
	lease.Spec.LeaseDurationSeconds = pointer.Int32(m.durationSec)
	lease.Spec.AcquireTime = &nowMicro
	lease.Spec.RenewTime = &nowMicro
	lease.Spec.LeaseTransitions = &transitions

	if _, err := leaseClient.Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to acquire existing lease %s/%s: %w", m.namespace, m.leaseName, err)
	}

	m.startHeartbeat()
	return nil
}

// startHeartbeat periodically updates RenewTime while the lease is held.
func (m *k8sLeaseManager) startHeartbeat() {
	renewInterval := time.Duration(m.durationSec/3) * time.Second
	if renewInterval < time.Second {
		renewInterval = time.Second
	}

	go func() {
		ticker := time.NewTicker(renewInterval)
		defer ticker.Stop()

		for {
			select {
			case <-m.stopRenew:
				return
			case <-ticker.C:
				m.renew()
			}
		}
	}()
}

func (m *k8sLeaseManager) renew() {
	m.mu.Lock()
	if m.released {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	leaseClient := m.client.CoordinationV1().Leases(m.namespace)
	lease, err := leaseClient.Get(ctx, m.leaseName, metav1.GetOptions{})
	if err != nil {
		return
	}

	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != m.holderIdentity {
		return
	}

	nowMicro := metav1.MicroTime{Time: time.Now()}
	lease.Spec.RenewTime = &nowMicro
	_, _ = leaseClient.Update(ctx, lease, metav1.UpdateOptions{})
}

// Release releases the lease by clearing the holder identity.
func (m *k8sLeaseManager) Release(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.released {
		return nil
	}
	m.released = true
	close(m.stopRenew)

	leaseClient := m.client.CoordinationV1().Leases(m.namespace)
	lease, err := leaseClient.Get(ctx, m.leaseName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to fetch lease for release: %w", err)
	}

	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == m.holderIdentity {
		lease.Spec.HolderIdentity = nil
		if _, err := leaseClient.Update(ctx, lease, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("failed to clear lease holder: %w", err)
		}
	}

	return nil
}
