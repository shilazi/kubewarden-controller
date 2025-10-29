package admission

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-logr/logr"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policiesv1alpha2 "github.com/kubewarden/kubewarden-controller/apis/policies/v1alpha2"
	pkgconstants "github.com/kubewarden/kubewarden-controller/internal/pkg/constants"
)

type Reconciler struct {
	Client                        client.Client
	DeploymentsNamespace          string
	DeploymentsServiceAccountName string
	Log                           logr.Logger
}

type errorList []error

func (errorList errorList) Error() string {
	errors := []string{}
	for _, error := range errorList {
		errors = append(errors, error.Error())
	}
	return strings.Join(errors, ", ")
}

func (r *Reconciler) ReconcileDeletion(
	ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
) error {
	errors := errorList{}
	r.Log.Info("Removing deleted policy from PolicyServer ConfigMap")
	if err := r.reconcilePolicyServerConfigMap(ctx, clusterAdmissionPolicy, RemovePolicy); err != nil {
		r.Log.Error(err, "ReconcileDeletion: cannot update ConfigMap")
		errors = append(errors, err)
	}

	r.Log.Info("Removing ValidatingWebhookConfiguration associated with deleted policy")
	validatingWebhookConf := &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterAdmissionPolicy.Name,
		},
	}
	if err := r.Client.Delete(ctx, validatingWebhookConf); err != nil && !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot delete ValidatingWebhookConfiguration")
		errors = append(errors, err)
	}

	r.Log.Info("Removing MutatingWebhookConfiguration associated with deleted policy")
	mutatingWebhookConf := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterAdmissionPolicy.Name,
		},
	}
	if err := r.Client.Delete(ctx, mutatingWebhookConf); err != nil && !apierrors.IsNotFound(err) {
		r.Log.Error(err, "ReconcileDeletion: cannot delete MutatingWebhookConfiguration")
		errors = append(errors, err)
	}

	if err := r.reconcilePolicyServerDeployment(ctx); err != nil {
		r.Log.Error(err, "ReconcileDeletion: cannot reconcile PolicyServer deployment")
		errors = append(errors, err)
	}
	if len(errors) == 0 {
		return nil
	}

	return errors
}

func setFalseConditionType(
	conditions *[]metav1.Condition,
	conditionType policiesv1alpha2.PolicyConditionType,
	message string,
) {
	apimeta.SetStatusCondition(
		conditions,
		metav1.Condition{
			Type:    string(conditionType),
			Status:  metav1.ConditionFalse,
			Reason:  string(policiesv1alpha2.ReconciliationFailed),
			Message: message,
		},
	)
}

func setTrueConditionType(conditions *[]metav1.Condition, conditionType policiesv1alpha2.PolicyConditionType) {
	apimeta.SetStatusCondition(
		conditions,
		metav1.Condition{
			Type:   string(conditionType),
			Status: metav1.ConditionTrue,
			Reason: string(policiesv1alpha2.ReconciliationSucceeded),
		},
	)
}

func (r *Reconciler) webhookObjectSelector(objectSelector *metav1.LabelSelector) *metav1.LabelSelector {
	kubewardenLabelSelectorRequirement := metav1.LabelSelectorRequirement{
		Key:      pkgconstants.KubewardenLabelKey,
		Operator: metav1.LabelSelectorOpNotIn,
		Values:   []string{pkgconstants.KubewardenControllerLabelVal, pkgconstants.PolicyServerLabelVal},
	}
	matchExpressionKeyAndOperator := fmt.Sprintf("key=%s, operator=%s",
		pkgconstants.KubewardenLabelKey, metav1.LabelSelectorOpNotIn)

	if objectSelector == nil || objectSelector.MatchExpressions == nil || len(objectSelector.MatchExpressions) == 0 {
		objectSelector = &metav1.LabelSelector{}
		objectSelector.MatchExpressions = []metav1.LabelSelectorRequirement{
			kubewardenLabelSelectorRequirement,
		}
		r.Log.Info(fmt.Sprintf("Empty matchExpressions append %s, values=[%s, %s]",
			matchExpressionKeyAndOperator,
			pkgconstants.KubewardenControllerLabelVal,
			pkgconstants.PolicyServerLabelVal,
		))
		return objectSelector
	}

	for i := range objectSelector.MatchExpressions {
		matchExpression := &objectSelector.MatchExpressions[i]
		if matchExpression.Key == pkgconstants.KubewardenLabelKey && matchExpression.Operator == metav1.LabelSelectorOpNotIn {
			appendKubewardenControllerLabelVal := true
			appendPolicyServerLabelVal := true
			for _, labelVal := range matchExpression.Values {
				if !appendKubewardenControllerLabelVal && !appendPolicyServerLabelVal {
					break
				}
				switch labelVal {
				case pkgconstants.KubewardenControllerLabelVal:
					appendKubewardenControllerLabelVal = false
				case pkgconstants.PolicyServerLabelVal:
					appendPolicyServerLabelVal = false
				}
			}
			if appendKubewardenControllerLabelVal {
				matchExpression.Values = append(matchExpression.Values, pkgconstants.KubewardenControllerLabelVal)
				r.Log.Info(fmt.Sprintf("Match %s matchExpression append values=[%s]",
					matchExpressionKeyAndOperator,
					pkgconstants.KubewardenControllerLabelVal,
				))
			}
			if appendPolicyServerLabelVal {
				matchExpression.Values = append(matchExpression.Values, pkgconstants.PolicyServerLabelVal)
				r.Log.Info(fmt.Sprintf("Match %s matchExpression append values=[%s]",
					matchExpressionKeyAndOperator,
					pkgconstants.PolicyServerLabelVal,
				))
			}
			r.Log.Info(fmt.Sprintf("MatchExpressions exist %s, values=[%s, %s]",
				matchExpressionKeyAndOperator,
				pkgconstants.KubewardenControllerLabelVal,
				pkgconstants.PolicyServerLabelVal,
			))
			return objectSelector
		}
	}

	objectSelector.MatchExpressions = append(objectSelector.MatchExpressions, kubewardenLabelSelectorRequirement)
	r.Log.Info(fmt.Sprintf("Mismatch %s matchExpression append %s, values=[%s, %s]",
		matchExpressionKeyAndOperator,
		matchExpressionKeyAndOperator,
		pkgconstants.KubewardenControllerLabelVal,
		pkgconstants.PolicyServerLabelVal,
	))
	return objectSelector
}

func (r *Reconciler) Reconcile(
	ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
) error {
	policyServerSecret, err := r.fetchOrInitializePolicyServerSecret(ctx)
	if err != nil {
		setFalseConditionType(
			&clusterAdmissionPolicy.Status.Conditions,
			policiesv1alpha2.PolicyServerSecretReconciled,
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	if err := r.reconcileSecret(ctx, policyServerSecret); err != nil {
		setFalseConditionType(
			&clusterAdmissionPolicy.Status.Conditions,
			policiesv1alpha2.PolicyServerSecretReconciled,
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&clusterAdmissionPolicy.Status.Conditions,
		policiesv1alpha2.PolicyServerSecretReconciled,
	)

	if err := r.reconcilePolicyServerConfigMap(ctx, clusterAdmissionPolicy, AddPolicy); err != nil {
		setFalseConditionType(
			&clusterAdmissionPolicy.Status.Conditions,
			policiesv1alpha2.PolicyServerConfigMapReconciled,
			fmt.Sprintf("error reconciling configmap: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&clusterAdmissionPolicy.Status.Conditions,
		policiesv1alpha2.PolicyServerConfigMapReconciled,
	)

	if err := r.reconcilePolicyServerDeployment(ctx); err != nil {
		setFalseConditionType(
			&clusterAdmissionPolicy.Status.Conditions,
			policiesv1alpha2.PolicyServerDeploymentReconciled,
			fmt.Sprintf("error reconciling deployment: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&clusterAdmissionPolicy.Status.Conditions,
		policiesv1alpha2.PolicyServerDeploymentReconciled,
	)

	if err := r.reconcilePolicyServerService(ctx); err != nil {
		setFalseConditionType(
			&clusterAdmissionPolicy.Status.Conditions,
			policiesv1alpha2.PolicyServerServiceReconciled,
			fmt.Sprintf("error reconciling service: %v", err),
		)
		return err
	}

	setTrueConditionType(
		&clusterAdmissionPolicy.Status.Conditions,
		policiesv1alpha2.PolicyServerServiceReconciled,
	)

	return r.enablePolicyWebhook(ctx, clusterAdmissionPolicy, policyServerSecret)
}

func (r *Reconciler) enablePolicyWebhook(
	ctx context.Context,
	clusterAdmissionPolicy *policiesv1alpha2.ClusterAdmissionPolicy,
	policyServerSecret *corev1.Secret,
) error {
	policyServerReady, err := r.isPolicyServerReady(ctx)

	if err != nil {
		return err
	}

	if !policyServerReady {
		return errors.New("policy server not yet ready")
	}

	// register the new dynamic admission controller only once the policy is
	// served by the PolicyServer deployment
	if clusterAdmissionPolicy.Spec.Mutating {
		if err := r.reconcileMutatingWebhookConfiguration(ctx, clusterAdmissionPolicy, policyServerSecret); err != nil {
			setFalseConditionType(
				&clusterAdmissionPolicy.Status.Conditions,
				policiesv1alpha2.PolicyServerWebhookConfigurationReconciled,
				fmt.Sprintf("error reconciling mutating webhook configuration: %v", err),
			)
			return err
		}

		setTrueConditionType(
			&clusterAdmissionPolicy.Status.Conditions,
			policiesv1alpha2.PolicyServerWebhookConfigurationReconciled,
		)
	} else {
		if err := r.reconcileValidatingWebhookConfiguration(ctx, clusterAdmissionPolicy, policyServerSecret); err != nil {
			setFalseConditionType(
				&clusterAdmissionPolicy.Status.Conditions,
				policiesv1alpha2.PolicyServerWebhookConfigurationReconciled,
				fmt.Sprintf("error reconciling validating webhook configuration: %v", err),
			)
			return err
		}

		setTrueConditionType(
			&clusterAdmissionPolicy.Status.Conditions,
			policiesv1alpha2.PolicyServerWebhookConfigurationReconciled,
		)
	}

	return nil
}
