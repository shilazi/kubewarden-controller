package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"path/filepath"
	"sigs.k8s.io/controller-runtime/pkg/client"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	"github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

func (r *Reconciler) reconcileValidatingWebhookConfiguration(
	ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	admissionSecret *corev1.Secret) error {
	err := r.Client.Create(ctx, r.validatingWebhookConfiguration(clusterAdmissionPolicy, admissionSecret))
	if err == nil {
		return nil
	}
	if apierrors.IsAlreadyExists(err) {
		validatingWebhookConfiguration := &admissionregistrationv1.ValidatingWebhookConfiguration{}
		if err = r.Client.Get(ctx, client.ObjectKey{
			Name: clusterAdmissionPolicy.Name,
		}, validatingWebhookConfiguration); err == nil {
			patch, _ := json.Marshal(r.validatingWebhookConfiguration(clusterAdmissionPolicy, admissionSecret))
			err = r.Client.Patch(ctx, validatingWebhookConfiguration, client.RawPatch(types.StrategicMergePatchType, patch))
			if err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("cannot reconcile validating webhook: %w", err)
}

func (r *Reconciler) validatingWebhookConfiguration(
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	admissionSecret *corev1.Secret,
) *admissionregistrationv1.ValidatingWebhookConfiguration {
	admissionPath := filepath.Join("/validate", clusterAdmissionPolicy.Name)
	admissionPort := int32(constants.PolicyServerPort)

	service := admissionregistrationv1.ServiceReference{
		Namespace: r.DeploymentsNamespace,
		Name:      constants.PolicyServerServiceName,
		Path:      &admissionPath,
		Port:      &admissionPort,
	}

	sideEffects := clusterAdmissionPolicy.Spec.SideEffects
	if sideEffects == nil {
		noneSideEffects := admissionregistrationv1.SideEffectClassNone
		sideEffects = &noneSideEffects
	}
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterAdmissionPolicy.Name,
			Labels: map[string]string{
				"kubewarden": "true",
			},
		},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name: fmt.Sprintf("%s.kubewarden.admission", clusterAdmissionPolicy.Name),
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service:  &service,
					CABundle: admissionSecret.Data[constants.PolicyServerCASecretKeyName],
				},
				Rules:                   clusterAdmissionPolicy.Spec.Rules,
				FailurePolicy:           clusterAdmissionPolicy.Spec.FailurePolicy,
				MatchPolicy:             clusterAdmissionPolicy.Spec.MatchPolicy,
				NamespaceSelector:       clusterAdmissionPolicy.Spec.NamespaceSelector,
				ObjectSelector:          clusterAdmissionPolicy.Spec.ObjectSelector,
				SideEffects:             sideEffects,
				TimeoutSeconds:          clusterAdmissionPolicy.Spec.TimeoutSeconds,
				AdmissionReviewVersions: []string{"v1"},
			},
		},
	}
}
