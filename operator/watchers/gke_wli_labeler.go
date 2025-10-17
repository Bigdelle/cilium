// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	gkeMetadataServerEnabledLabel   = "iam.gke.io/gke-metadata-server-enabled"
	gkeWorkloadIdentityEnabledLabel = "gke-wli-enabled"
)

// GKEWliLabeler is a controller that adds a label to pods on nodes with the GKE metadata server enabled.
type GKEWliLabeler struct {
	clientset k8sClient.Clientset
	logger    *slog.Logger
	nodeStore cache.Store
	podStore  cache.Store
}

// NewGKEWliLabeler creates a new GKEWliLabeler.
func NewGKEWliLabeler(clientset k8sClient.Clientset, logger *slog.Logger) *GKEWliLabeler {
	return &GKEWliLabeler{
		clientset: clientset,
		logger:    logger,
		nodeStore: nil,
		podStore:  nil,
	}
}

// Run starts the controller.
func (l *GKEWliLabeler) Run(stopCh <-chan struct{}) {
	l.logger.Info("Starting GKE WLI Labeler controller")

	podQueue := workqueue.NewTypedRateLimitingQueueWithConfig[string](
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](1*time.Second, 120*time.Second),
		workqueue.TypedRateLimitingQueueConfig[string]{Name: "gke-wli-labeler-pod-queue"},
	)

	// Informer for pods
	podStore, podController := informer.NewInformer(
		utils.ListerWatcherFromTyped[*slim_corev1.PodList](l.clientset.Slim().CoreV1().Pods("")),
		&slim_corev1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, _ := gkeWliQueueKeyFunc(obj)
				podQueue.Add(key)
			},
			UpdateFunc: func(_, newObj interface{}) {
				key, _ := gkeWliQueueKeyFunc(newObj)
				podQueue.Add(key)
			},
		},
		nil,
	)
	l.podStore = podStore

	// Informer for nodes
	nodeStore, nodeController := informer.NewInformer(
		utils.ListerWatcherFromTyped[*slim_corev1.NodeList](l.clientset.Slim().CoreV1().Nodes()),
		&slim_corev1.Node{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				l.enqueuePodsForNode(obj, podQueue)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldNode := oldObj.(*slim_corev1.Node)
				newNode := newObj.(*slim_corev1.Node)
				if oldNode.Labels[gkeMetadataServerEnabledLabel] != newNode.Labels[gkeMetadataServerEnabledLabel] {
					l.enqueuePodsForNode(newObj, podQueue)
				}
			},
		},
		nil,
	)
	l.nodeStore = nodeStore

	go podController.Run(stopCh)
	go nodeController.Run(stopCh)

	cache.WaitForCacheSync(stopCh, podController.HasSynced, nodeController.HasSynced)

	go l.processPodQueue(podQueue, stopCh)
}

func (l *GKEWliLabeler) enqueuePodsForNode(nodeObj interface{}, queue workqueue.TypedRateLimitingInterface[string]) {
	node := nodeObj.(*slim_corev1.Node)
	// Iterate over all pods in the store and enqueue those on the updated node. Can likely do this more efficiently with an indexer (TODO: BIGDELLE)
	for _, podObj := range l.podStore.List() {
		pod := podObj.(*slim_corev1.Pod)
		if pod.Spec.NodeName == node.Name {
			key, _ := gkeWliQueueKeyFunc(pod)
			queue.Add(key)
		}
	}
}

func (l *GKEWliLabeler) processPodQueue(queue workqueue.TypedRateLimitingInterface[string], stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
			key, quit := queue.Get()
			if quit {
				return
			}
			l.handlePodUpdate(key)
			queue.Done(key)
		}
	}
}

func (l *GKEWliLabeler) handlePodUpdate(podKey string) {
	podObj, exists, err := l.podStore.GetByKey(podKey)
	if err != nil {
		l.logger.Error("Failed to get pod from store", "key", podKey, "error", err)
		return
	}
	if !exists {
		// Pod was deleted
		return
	}

	pod := podObj.(*slim_corev1.Pod)
	if pod.Spec.NodeName == "" {
		// Pod not scheduled yet
		return
	}

	nodeObj, exists, err := l.nodeStore.GetByKey(pod.Spec.NodeName)
	if err != nil {
		l.logger.Error("Failed to get node from store", "node", pod.Spec.NodeName, "error", err)
		return
	}
	if !exists {
		return
	}

	node := nodeObj.(*slim_corev1.Node)
	shouldLabel := node.Labels[gkeMetadataServerEnabledLabel] == "true"

	l.updatePodLabel(pod, shouldLabel)
}

func (l *GKEWliLabeler) updatePodLabel(pod *slim_corev1.Pod, shouldLabel bool) {
	hasLabel := pod.Labels[gkeWorkloadIdentityEnabledLabel] == "true"

	if shouldLabel == hasLabel {
		return
	}

	podToPatch := pod.DeepCopy()

	if podToPatch.Labels == nil {
		podToPatch.Labels = make(map[string]string)
	}

	if shouldLabel {
		podToPatch.Labels[gkeWorkloadIdentityEnabledLabel] = "true"
	} else {
		delete(podToPatch.Labels, gkeWorkloadIdentityEnabledLabel)
	}

	// Generate the patch
	oldData, err := json.Marshal(pod)
	if err != nil {
		l.logger.Error("Failed to marshal old pod data for patch", "pod", pod.Name, "namespace", pod.Namespace, "error", err)
		return
	}

	newData, err := json.Marshal(podToPatch)
	if err != nil {
		l.logger.Error("Failed to marshal new pod data for patch", "pod", pod.Name, "namespace", pod.Namespace, "error", err)
		return
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, slim_corev1.Pod{})
	if err != nil {
		l.logger.Error("Failed to create patch bytes", "pod", pod.Name, "namespace", pod.Namespace, "error", err)
		return
	}

	// Apply the patch.
	_, err = l.clientset.Slim().CoreV1().Pods(pod.Namespace).Patch(context.Background(), pod.Name, types.StrategicMergePatchType, patchBytes, metav1.PatchOptions{})
	if err != nil {
		l.logger.Error("Failed to patch pod", "pod", pod.Name, "namespace", pod.Namespace, "error", err)
	}
}

func gkeWliQueueKeyFunc(obj interface{}) (string, error) {
	return cache.MetaNamespaceKeyFunc(obj)
}
