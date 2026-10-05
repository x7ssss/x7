package k8s

import (
	"context"
	"errors"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAcquireAndReleaseLease(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	namespace := "default"
	releaseName := "my-service"

	// 1. Acquire lease
	lock, err := AcquireLease(ctx, client, namespace, releaseName, "worker-1")
	if err != nil {
		t.Fatalf("AcquireLease failed: %v", err)
	}

	// 2. Check lease status
	status, err := CheckLease(ctx, client, namespace, releaseName)
	if err != nil {
		t.Fatalf("CheckLease failed: %v", err)
	}
	if !status.Exists || !status.IsHeld || status.Holder != "worker-1" {
		t.Errorf("expected lease to be actively held by worker-1, got %+v", status)
	}

	// 3. Attempt concurrent acquire with different worker -> must fail with active lock error
	_, err = AcquireLease(ctx, client, namespace, releaseName, "worker-2")
	if err == nil {
		t.Fatalf("expected AcquireLease to fail on concurrent attempt, but succeeded")
	}
	if !errors.Is(err, ErrLockActive) {
		t.Errorf("expected ErrLockActive, got %v", err)
	}

	// 4. Release lock
	if err := lock.Release(ctx); err != nil {
		t.Fatalf("Release failed: %v", err)
	}

	// 5. Check lease after release -> should be removed
	statusAfter, err := CheckLease(ctx, client, namespace, releaseName)
	if err != nil {
		t.Fatalf("CheckLease after release failed: %v", err)
	}
	if statusAfter.Exists {
		t.Errorf("expected lease to be deleted after release, but exists")
	}
}

func TestAcquireExpiredLease(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	namespace := "default"
	releaseName := "stale-service"

	expiredTime := metav1.MicroTime{Time: time.Now().Add(-60 * time.Second)}
	expiredLease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      LeaseName(releaseName),
			Namespace: namespace,
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       func(s string) *string { return &s }("dead-worker"),
			LeaseDurationSeconds: ptrInt32(15),
			AcquireTime:          &expiredTime,
			RenewTime:            &expiredTime,
		},
	}

	_, err := client.CoordinationV1().Leases(namespace).Create(ctx, expiredLease, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to seed expired lease: %v", err)
	}

	// Acquire should take over expired lease
	lock, err := AcquireLease(ctx, client, namespace, releaseName, "new-worker")
	if err != nil {
		t.Fatalf("expected to acquire expired lease, got error: %v", err)
	}
	defer lock.Release(ctx)

	status, err := CheckLease(ctx, client, namespace, releaseName)
	if err != nil {
		t.Fatalf("CheckLease failed: %v", err)
	}
	if status.Holder != "new-worker" {
		t.Errorf("expected holder new-worker, got %s", status.Holder)
	}
}
