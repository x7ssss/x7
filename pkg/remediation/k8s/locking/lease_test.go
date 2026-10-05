package locking

import (
	"context"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/pointer"
)

func TestLeaseManager_AcquireNew(t *testing.T) {
	client := fake.NewSimpleClientset()
	ctx := context.Background()

	mgr := NewLeaseManager(client, "kube-system", "test-lock", 60)
	err := mgr.Acquire(ctx)
	if err != nil {
		t.Fatalf("expected acquire on new lease to succeed, got: %v", err)
	}

	lease, err := client.CoordinationV1().Leases("kube-system").Get(ctx, "test-lock", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to retrieve lease: %v", err)
	}

	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != mgr.HolderIdentity() {
		t.Errorf("holder identity mismatch: got %v, want %s", lease.Spec.HolderIdentity, mgr.HolderIdentity())
	}

	// Release
	if err := mgr.Release(ctx); err != nil {
		t.Fatalf("expected release to succeed, got: %v", err)
	}

	leaseAfterRelease, err := client.CoordinationV1().Leases("kube-system").Get(ctx, "test-lock", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to retrieve lease after release: %v", err)
	}
	if leaseAfterRelease.Spec.HolderIdentity != nil {
		t.Errorf("expected holder identity to be nil after release, got %v", *leaseAfterRelease.Spec.HolderIdentity)
	}
}

func TestLeaseManager_Contention(t *testing.T) {
	client := fake.NewSimpleClientset()
	ctx := context.Background()

	// Pre-create an active lease held by someone else
	nowMicro := metav1.MicroTime{Time: time.Now()}
	existingLease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-lock",
			Namespace: "kube-system",
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       pointer.String("other-instance-uuid"),
			LeaseDurationSeconds: pointer.Int32(60),
			AcquireTime:          &nowMicro,
			RenewTime:            &nowMicro,
		},
	}
	_, err := client.CoordinationV1().Leases("kube-system").Create(ctx, existingLease, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create existing lease: %v", err)
	}

	mgr := NewLeaseManager(client, "kube-system", "test-lock", 60)
	err = mgr.Acquire(ctx)
	if err == nil {
		t.Fatalf("expected contention error when lease is actively held, got nil")
	}

	if !testing.Short() {
		t.Logf("Contention error received as expected: %v", err)
	}
}

func TestLeaseManager_AcquireExpired(t *testing.T) {
	client := fake.NewSimpleClientset()
	ctx := context.Background()

	// Pre-create an expired lease held by someone else (renewed 120s ago with 60s duration)
	pastMicro := metav1.MicroTime{Time: time.Now().Add(-120 * time.Second)}
	existingLease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-lock",
			Namespace: "kube-system",
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       pointer.String("old-crashed-instance"),
			LeaseDurationSeconds: pointer.Int32(60),
			AcquireTime:          &pastMicro,
			RenewTime:            &pastMicro,
			LeaseTransitions:     pointer.Int32(1),
		},
	}
	_, err := client.CoordinationV1().Leases("kube-system").Create(ctx, existingLease, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create expired lease: %v", err)
	}

	mgr := NewLeaseManager(client, "kube-system", "test-lock", 60)
	err = mgr.Acquire(ctx)
	if err != nil {
		t.Fatalf("expected acquire on expired lease to succeed, got: %v", err)
	}

	lease, err := client.CoordinationV1().Leases("kube-system").Get(ctx, "test-lock", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get lease: %v", err)
	}

	if *lease.Spec.HolderIdentity != mgr.HolderIdentity() {
		t.Errorf("expected holder identity to be %s, got %s", mgr.HolderIdentity(), *lease.Spec.HolderIdentity)
	}
	if *lease.Spec.LeaseTransitions != 2 {
		t.Errorf("expected leaseTransitions to increment to 2, got %d", *lease.Spec.LeaseTransitions)
	}

	_ = mgr.Release(ctx)
}
