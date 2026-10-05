package k8s

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	"github.com/x7ssss/x7/pkg/remediation/helm/codec"
)

// ReleaseDetail combines secret metadata and decoded Helm payload.
type ReleaseDetail struct {
	SecretName string
	Namespace  string
	Name       string
	Revision   int
	Status     string
	ModifiedAt time.Time
	Payload    *codec.ReleasePayload
	Secret     *corev1.Secret
}

// GetLatestReleaseSecret finds the highest revision secret for a release name in a namespace.
func GetLatestReleaseSecret(ctx context.Context, client kubernetes.Interface, namespace, releaseName string) (*ReleaseDetail, error) {
	opts := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("owner=helm,name=%s", releaseName),
	}
	secretList, err := client.CoreV1().Secrets(namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets for release %s in %s: %w", releaseName, namespace, err)
	}

	// If no secrets found by label, fall back to searching by name prefix
	items := secretList.Items
	if len(items) == 0 {
		allSecrets, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to fallback list secrets in %s: %w", namespace, err)
		}
		for _, s := range allSecrets.Items {
			if rName, _, ok := codec.ParseSecretName(s.Name); ok && rName == releaseName {
				items = append(items, s)
			}
		}
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("no release secrets found for %s in namespace %s", releaseName, namespace)
	}

	// Sort by revision descending
	type revItem struct {
		secret   corev1.Secret
		revision int
	}
	var revs []revItem
	for _, s := range items {
		_, rev, ok := codec.ParseSecretName(s.Name)
		if !ok {
			if vStr, exists := s.Labels["version"]; exists {
				if v, err := strconv.Atoi(vStr); err == nil {
					rev = v
					ok = true
				}
			}
		}
		if ok {
			revs = append(revs, revItem{secret: s, revision: rev})
		}
	}

	if len(revs) == 0 {
		return nil, fmt.Errorf("could not parse any release revision for %s in %s", releaseName, namespace)
	}

	sort.Slice(revs, func(i, j int) bool {
		return revs[i].revision > revs[j].revision
	})

	latest := revs[0].secret
	latestRev := revs[0].revision

	rawData, hasData := latest.Data["release"]
	if !hasData {
		return nil, fmt.Errorf("secret %s has no 'release' data key", latest.Name)
	}

	payload, err := codec.DecodeFromSecretData(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode release payload from %s: %w", latest.Name, err)
	}

	status := latest.Labels["status"]
	if status == "" && payload.Info != nil {
		status = payload.Info.Status
	}

	var modTime time.Time
	if modStr, exists := latest.Labels["modifiedAt"]; exists {
		if unixSec, err := strconv.ParseInt(modStr, 10, 64); err == nil {
			modTime = time.Unix(unixSec, 0).UTC()
		}
	}
	if modTime.IsZero() && payload.Info != nil && !payload.Info.LastDeployed.IsZero() {
		modTime = payload.Info.LastDeployed.UTC()
	}

	return &ReleaseDetail{
		SecretName: latest.Name,
		Namespace:  namespace,
		Name:       releaseName,
		Revision:   latestRev,
		Status:     status,
		ModifiedAt: modTime,
		Payload:    payload,
		Secret:     &latest,
	}, nil
}

// ListAllStuckReleases scans the cluster or namespace for releases in pending status.
func ListAllStuckReleases(ctx context.Context, client kubernetes.Interface, namespace string) ([]ReleaseDetail, error) {
	opts := metav1.ListOptions{
		LabelSelector: "owner=helm",
	}

	secretList, err := client.CoreV1().Secrets(namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list helm secrets: %w", err)
	}

	// Group secrets by (namespace, releaseName) and find the latest revision of each
	groups := make(map[string][]corev1.Secret)
	for _, s := range secretList.Items {
		rName, _, ok := codec.ParseSecretName(s.Name)
		if !ok {
			rName = s.Labels["name"]
		}
		if rName == "" {
			continue
		}
		key := s.Namespace + "/" + rName
		groups[key] = append(groups[key], s)
	}

	var stuck []ReleaseDetail
	for _, secrets := range groups {
		// Find highest revision
		var highest corev1.Secret
		highestRev := -1
		for _, s := range secrets {
			_, rev, ok := codec.ParseSecretName(s.Name)
			if !ok {
				if vStr, exists := s.Labels["version"]; exists {
					rev, _ = strconv.Atoi(vStr)
				}
			}
			if rev > highestRev {
				highestRev = rev
				highest = s
			}
		}

		if highestRev == -1 {
			continue
		}

		status := highest.Labels["status"]
		// Check label or payload
		isStuck := codec.IsPending(status)

		var payload *codec.ReleasePayload
		if rawData, ok := highest.Data["release"]; ok {
			p, err := codec.DecodeFromSecretData(rawData)
			if err == nil {
				payload = p
				if !isStuck && p.Info != nil {
					isStuck = codec.IsPending(p.Info.Status)
				}
				if status == "" && p.Info != nil {
					status = p.Info.Status
				}
			}
		}

		if isStuck {
			rName, _, _ := codec.ParseSecretName(highest.Name)
			if rName == "" {
				rName = highest.Labels["name"]
			}

			var modTime time.Time
			if modStr, exists := highest.Labels["modifiedAt"]; exists {
				if unixSec, err := strconv.ParseInt(modStr, 10, 64); err == nil {
					modTime = time.Unix(unixSec, 0).UTC()
				}
			}
			if modTime.IsZero() && payload != nil && payload.Info != nil && !payload.Info.LastDeployed.IsZero() {
				modTime = payload.Info.LastDeployed.UTC()
			}

			stuck = append(stuck, ReleaseDetail{
				SecretName: highest.Name,
				Namespace:  highest.Namespace,
				Name:       rName,
				Revision:   highestRev,
				Status:     status,
				ModifiedAt: modTime,
				Payload:    payload,
				Secret:     &highest,
			})
		}
	}

	// Sort results by namespace and release name
	sort.Slice(stuck, func(i, j int) bool {
		if stuck[i].Namespace != stuck[j].Namespace {
			return stuck[i].Namespace < stuck[j].Namespace
		}
		return stuck[i].Name < stuck[j].Name
	})

	return stuck, nil
}

// AtomicPatchRelease applies the dual-mutation to update both Secret metadata labels
// (status and modifiedAt) and .data.release in a single atomic operation.
func AtomicPatchRelease(ctx context.Context, client kubernetes.Interface, detail *ReleaseDetail, newStatus, unlockDescription string, dryRun bool) (*corev1.Secret, error) {
	now := time.Now().UTC()
	nowUnix := strconv.FormatInt(now.Unix(), 10)

	// Mutate payload
	if detail.Payload.Info == nil {
		detail.Payload.Info = &codec.ReleaseInfo{}
	}
	detail.Payload.Info.Status = newStatus
	detail.Payload.Info.LastDeployed = now
	detail.Payload.Info.Description = unlockDescription

	// Re-encode payload with gzip level 9 compression
	newReleaseData, err := codec.EncodeForSecretData(detail.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode patched release data: %w", err)
	}

	var updatedSecret *corev1.Secret

	updateErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// Fetch fresh secret to preserve ResourceVersion
		latestSecret, err := client.CoreV1().Secrets(detail.Namespace).Get(ctx, detail.SecretName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if latestSecret.Labels == nil {
			latestSecret.Labels = make(map[string]string)
		}
		if latestSecret.Data == nil {
			latestSecret.Data = make(map[string][]byte)
		}

		// Dual-Mutation: simultaneously update labels and .data.release
		latestSecret.Labels["status"] = newStatus
		latestSecret.Labels["modifiedAt"] = nowUnix
		latestSecret.Data["release"] = newReleaseData

		updateOpts := metav1.UpdateOptions{}
		if dryRun {
			updateOpts.DryRun = []string{metav1.DryRunAll}
		}

		res, err := client.CoreV1().Secrets(detail.Namespace).Update(ctx, latestSecret, updateOpts)
		if err != nil {
			return err
		}
		updatedSecret = res
		return nil
	})

	if updateErr != nil {
		return nil, fmt.Errorf("failed to atomic patch secret %s: %w", detail.SecretName, updateErr)
	}

	return updatedSecret, nil
}

// PurgeReleaseSecret deletes the secret from Kubernetes, used for purge-v1 strategy.
func PurgeReleaseSecret(ctx context.Context, client kubernetes.Interface, namespace, secretName string, dryRun bool) error {
	deleteOpts := metav1.DeleteOptions{}
	if dryRun {
		deleteOpts.DryRun = []string{metav1.DryRunAll}
	}
	err := client.CoreV1().Secrets(namespace).Delete(ctx, secretName, deleteOpts)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to purge secret %s in %s: %w", secretName, namespace, err)
	}
	return nil
}
