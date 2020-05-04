package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/kubernetes/pkg/apis/core/v1"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()

	// (https://github.com/kubernetes/kubernetes/issues/57982)
	defaulter = runtime.ObjectDefaulter(runtimeScheme)
)

var ignoredNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	admissionWebhookAnnotationInjectKey = "sidecar-injector-webhook.morven.me/inject"
	admissionWebhookAnnotationStatusKey = "sidecar-injector-webhook.morven.me/status"
	BusinessNameLabelKey                = "app_name"
	ServiceNameLabelKey                 = "service_name"
	ServiceBindingLabelKey              = "service_binding"

	ArsenalBusinessNameEnvKey      = "ARSENAL_BUSINESS_NAME"
	ArsenalServiceNameEnvKey       = "ARSENAL_SERVICE_NAME"
	ArsenalServiceProtocolsEnvKey  = "ARSENAL_SERVICE_PROTOCOLS"
	ArsenalServiceTagsEnvKey       = "ARSENAL_SERVICE_TAGS"
	ArsenalUseSidecarEnvKey        = "ARSENAL_USE_SIDECAR"
	ArsenalIsArsenalServiceEnvKey  = "ARSENAL_IS_ARSENAL_SERVICE"
	ArsenalUseServiceSidecarEnvKey = "ARSENAL_USE_SERVICE_SIDECAR"
)

type WebhookServer struct {
	sidecarConfig *Config
	server        *http.Server
}

// Webhook Server parameters
type WhSvrParameters struct {
	port           int    // webhook server port
	certFile       string // path to the x509 certificate for https
	keyFile        string // path to the x509 private key matching `CertFile`
	sidecarCfgFile string // path to sidecar injector configuration file
}

type Config struct {
	Containers     []corev1.Container `yaml:"containers"`
	InitContainers []corev1.Container `yaml:"containers"`
	//	Volumes        []corev1.Volume    `yaml:"volumes"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
	// defaulting with webhooks:
	// https://github.com/kubernetes/kubernetes/issues/57982
	_ = v1.AddToScheme(runtimeScheme)
}

// (https://github.com/kubernetes/kubernetes/issues/57982)
func applyDefaultsWorkaround(containers []corev1.Container) {
	defaulter.Default(&corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: containers,
		},
	})
}

func loadConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta) bool {
	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			glog.Infof("Skip mutation for %v for it's in special namespace:%v", metadata.Name, metadata.Namespace)
			return false
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == "injected" {
		required = false
	} else {
		switch strings.ToLower(annotations[admissionWebhookAnnotationInjectKey]) {
		default:
			required = false
		case "y", "yes", "true", "on":
			required = true
		}
	}

	glog.Infof("Mutation policy for %v/%v: status: %q required:%v", metadata.Namespace, metadata.Name, status, required)
	return required
}

func addContainer(target, added []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addVolume(target, added []corev1.Volume, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	for key, value := range added {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation{
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return patch
}

func getEnv(pod *corev1.Pod) ([]corev1.EnvVar, error) {
	envVars := []corev1.EnvVar{}
	// THS_TIER
	// ARSENAL_BUSINESS_NAME
	// ARSENAL_USE_SIDECAR
	// ARSENAL_IS_ARSENAL_SERVICE
	// ARSENAL_SERVICE_PROTOCOLS
	// ARSENAL_USE_SERVICE_SIDECAR
	// ARSENAL_SERVICE_SIDECAR_MODE
	// ARSENAL_SVC_..._HTTP
	labels := pod.ObjectMeta.Labels
	if businessName, exists := labels[BusinessNameLabelKey]; !exists {
		return nil, fmt.Errorf("not found business name: %s", BusinessNameLabelKey)
	} else {
		envVars = append(envVars, corev1.EnvVar{Name: ArsenalBusinessNameEnvKey, Value: businessName})
	}

	if serviceName, exists := labels[ServiceNameLabelKey]; exists && "" != strings.TrimSpace(serviceName) {
		serviceProtocols := getServiceProtocols(pod)
		if "" != serviceProtocols {
			envVars = append(envVars, corev1.EnvVar{Name: ArsenalServiceNameEnvKey, Value: serviceName})
			envVars = append(envVars, corev1.EnvVar{Name: ArsenalIsArsenalServiceEnvKey, Value: "true"})
			envVars = append(envVars, corev1.EnvVar{Name: ArsenalUseServiceSidecarEnvKey, Value: "true"})
			envVars = append(envVars, corev1.EnvVar{Name: ArsenalServiceProtocolsEnvKey, Value: serviceProtocols})
			envVars = append(envVars, corev1.EnvVar{Name: ArsenalServiceTagsEnvKey, Value: getServiceTag(pod)})
		}
	}

	if serviceBinding, exists := labels[ServiceBindingLabelKey]; exists {
		serviceBindings := strings.Split("|", strings.TrimSpace(serviceBinding))
		if 0 != len(serviceBindings) {
			for _, serviceName := range serviceBindings {
				envVars = append(envVars, corev1.EnvVar{Name: getServiceBindingEnvKey(serviceName), Value: generateIPAndPort(serviceName)})
			}
			envVars = append(envVars, corev1.EnvVar{Name: ArsenalUseSidecarEnvKey, Value: "true"})
		}
	}
	return envVars, nil
}

func getServiceTag(pod *corev1.Pod) string {
	return ""
}

func getServiceProtocols(pod *corev1.Pod) string {
	protocolPorts := []string{}
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			protocol := "tcp"
			if "http" != port.Protocol {
				protocol = "http"
			}
			protocolPort := fmt.Sprintf("%s:%d", protocol, port.ContainerPort)
			protocolPorts = append(protocolPorts, protocolPort)
		}
	}
	return strings.Join(protocolPorts, "|")
}

func getServiceBindingEnvKey(serviceName string, protocol string) string {
	upperServiceName := strings.ToUpper(serviceName)
	upperProtocol := strings.ToUpper(protocol)
	return fmt.Sprintf("ARSENAL_SVC_%s_%s_HOST", upperServiceName, upperProtocol)
}

func generateIPAndPort(serviceName string) string {

	return ""
}

// create mutation patch for resoures
func createPatch(pod *corev1.Pod, sidecarConfig *Config, annotations map[string]string) ([]byte, error) {
	var patch []patchOperation

	patch = append(patch, addContainer(pod.Spec.Containers, sidecarConfig.Containers, "/spec/containers")...)
	patch = append(patch, addContainer(pod.Spec.InitContainers, sidecarConfig.InitContainers, "/spec/InitContainers")...)
	//	patch = append(patch, addVolume(pod.Spec.Volumes, sidecarConfig.Volumes, "/spec/volumes")...)
	patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)

	return json.Marshal(patch)
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		glog.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	// determine whether to perform mutation
	if !mutationRequired(ignoredNamespaces, &pod.ObjectMeta) {
		glog.Infof("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	// Workaround: https://github.com/kubernetes/kubernetes/issues/57982
	applyDefaultsWorkaround(whsvr.sidecarConfig.Containers)
	annotations := map[string]string{admissionWebhookAnnotationStatusKey: "injected"}
	patchBytes, err := createPatch(&pod, whsvr.sidecarConfig, annotations)
	if err != nil {
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
