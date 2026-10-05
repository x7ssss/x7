package k8s

import (
	"context"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/x7ssss/x7/pkg/remediation/helm/codec"
)

func TestAtomicPatchRelease(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	releaseName := "redis"
	namespace := "default"
	rev := 2
	secretName := codec.SecretName(releaseName, rev)

	initialPayload := &codec.ReleasePayload{
		Name:      releaseName,
		Version:   rev,
		Namespace: namespace,
		Info: &codec.ReleaseInfo{
			Status:       codec.StatusPendingUpgrade,
			Description:  "Upgrade in progress",
			LastDeployed: time.Now().Add(-30 * time.Minute).UTC(),
		},
		Manifest: "apiVersion: v1\nkind: Service\n",
	}

	encodedData, err := codec.EncodeForSecretData(initialPayload)
	if err != nil {
		t.Fatalf("failed to encode initial payload: %v", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				"owner":      "helm",
				"name":       releaseName,
				"status":     codec.StatusPendingUpgrade,
				"version":    strconv.Itoa(rev),
				"modifiedAt": strconv.FormatInt(time.Now().Add(-30*time.Minute).Unix(), 10),
			},
		},
		Type: corev1.SecretType(codec.SecretType),
		Data: map[string][]byte{
			"release": encodedData,
		},
	}

	_, err = client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to create fake secret: %v", err)
	}

	// Fetch detail
	detail, err := GetLatestReleaseSecret(ctx, client, namespace, releaseName)
	if err != nil {
		t.Fatalf("GetLatestReleaseSecret failed: %v", err)
	}

	if detail.Status != codec.StatusPendingUpgrade {
		t.Errorf("expected initial status pending-upgrade, got %s", detail.Status)
	}

	// Perform atomic patch to mark-failed
	updatedSecret, err := AtomicPatchRelease(ctx, client, detail, codec.StatusFailed, "Unlocked by helm-unwedge", false)
	if err != nil {
		t.Fatalf("AtomicPatchRelease failed: %v", err)
	}

	// Verify Secret label was updated
	if updatedSecret.Labels["status"] != codec.StatusFailed {
		t.Errorf("secret label status was not updated to failed: got %s", updatedSecret.Labels["status"])
	}

	// Verify .data.release inside secret was updated
	patchedPayload, err := codec.DecodeFromSecretData(updatedSecret.Data["release"])
	if err != nil {
		t.Fatalf("failed to decode patched secret data: %v", err)
	}

	if patchedPayload.Info.Status != codec.StatusFailed {
		t.Errorf("payload status was not updated: got %s", patchedPayload.Info.Status)
	}
	if patchedPayload.Info.Description != "Unlocked by helm-unwedge" {
		t.Errorf("payload description mismatch: got %s", patchedPayload.Info.Description)
	}
}

func TestListAllStuckReleases(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	// Release 1: stuck in pending-install
	p1 := &codec.ReleasePayload{
		Name:      "vault",
		Version:   1,
		Namespace: "sec",
		Info:      &codec.ReleaseInfo{Status: codec.StatusPendingInstall},
	}
	d1, _ := codec.EncodeForSecretData(p1)
	s1 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      codec.SecretName("vault", 1),
			Namespace: "sec",
			Labels:    map[string]string{"owner": "helm", "name": "vault", "status": codec.StatusPendingInstall, "version": "1"},
		},
		Data: map[string][]byte{"release": d1},
	}

	// Release 2: healthy deployed
	p2 := &codec.ReleasePayload{
		Name:      "nginx",
		Version:   1,
		Namespace: "sec",
		Info:      &codec.ReleaseInfo{Status: codec.StatusDeployed},
	}
	d2, _ := codec.EncodeForSecretData(p2)
	s2 := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      codec.SecretName("nginx", 1),
			Namespace: "sec",
			Labels:    map[string]string{"owner": "helm", "name": "nginx", "status": codec.StatusDeployed, "version": "1"},
		},
		Data: map[string][]byte{"release": d2},
	}

	_, _ = client.CoreV1().Secrets("sec").Create(ctx, s1, metav1.CreateOptions{})
	_, _ = client.CoreV1().Secrets("sec").Create(ctx, s2, metav1.CreateOptions{})

	stuck, err := ListAllStuckReleases(ctx, client, "sec")
	if err != nil {
		t.Fatalf("ListAllStuckReleases failed: %v", err)
	}

	if len(stuck) != 1 {
		t.Fatalf("expected 1 stuck release, got %d", len(stuck))
	}
	if stuck[0].Name != "vault" {
		t.Errorf("expected vault to be stuck, got %s", stuck[0].Name)
	}
}

func TestPurgeReleaseSecret(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()

	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sh.helm.release.v1.demo.v1",
			Namespace: "default",
		},
	}
	_, _ = client.CoreV1().Secrets("default").Create(ctx, s, metav1.CreateOptions{})

	err := PurgeReleaseSecret(ctx, client, "default", "sh.helm.release.v1.demo.v1", false)
	if err != nil {
		t.Fatalf("PurgeReleaseSecret failed: %v", err)
	}

	secrets, _ := client.CoreV1().Secrets("default").List(ctx, metav1.ListOptions{})
	if len(secrets.Items) != 0 {
		t.Errorf("expected 0 secrets after purge, got %d", len(secrets.Items))
	}
}
