package bitnami

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	sealer "github.com/teko-vn/k8s-sealer"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"
)

// SealService seals secrets using Bitnami's Sealed-secret
type SealService struct {
	outputFormat   string
	controllerNs   string
	controllerName string
	registryHost   string
}

// NewSealService creates an instance of SealService
func NewSealService(outputFormat, controllerNs, controllerName, registryHost string) *SealService {
	s := &SealService{
		outputFormat:   outputFormat,
		controllerNs:   controllerNs,
		controllerName: controllerName,
		registryHost:   registryHost,
	}
	if s.outputFormat == "" {
		s.outputFormat = "json"
	}
	if s.controllerName == "" {
		s.controllerName = "sealed-secrets-controller"
	}
	if s.controllerNs == "" {
		s.controllerNs = metav1.NamespaceSystem
	}
	return s
}

func clientConfig(kubeconfig string) clientcmd.ClientConfig {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.DefaultClientConfig = &clientcmd.DefaultClientConfig
	loadingRules.ExplicitPath = kubeconfig
	overrides := clientcmd.ConfigOverrides{}
	conf := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &overrides)
	return conf
}

// SealOpaque seals an opaque type secret
func (s *SealService) SealOpaque(out io.Writer, cluster, name, ns string, data map[string][]byte) error {
	certFilePath, err := sealer.CertFilePath(cluster)
	if err != nil {
		return err
	}
	kubeconfig, err := sealer.KubeconfigFile(cluster)
	if err != nil {
		return err
	}
	secret := sealer.CreateSecret(name, ns, v1.SecretTypeOpaque, data)
	return s.seal(secret, certFilePath, kubeconfig, out)
}

// SealDockerconfigjson seals a dockerconfigjson type secret
func (s *SealService) SealDockerconfigjson(out io.Writer, cluster, name, ns, username, password string) error {
	certFilePath, err := sealer.CertFilePath(cluster)
	if err != nil {
		return err
	}
	kubeconfig, err := sealer.KubeconfigFile(cluster)
	if err != nil {
		return err
	}
	data := map[string][]byte{
		v1.DockerConfigJsonKey: sealer.CreateDockerconfigjson(s.registryHost, username, password),
	}
	secret := sealer.CreateSecret(name, ns, v1.SecretTypeDockerConfigJson, data)
	return s.seal(secret, certFilePath, kubeconfig, out)
}

// SealTLS seals a tls type secret
func (s *SealService) SealTLS(out io.Writer, cluster, ns, domain string) error {
	certFilePath, err := sealer.CertFilePath(cluster)
	if err != nil {
		return err
	}
	kubeconfig, err := sealer.KubeconfigFile(cluster)
	if err != nil {
		return err
	}

	cert, key, err := sealer.GetTLS(domain)
	if err != nil {
		return err
	}
	data := map[string][]byte{
		v1.TLSCertKey:       cert,
		v1.TLSPrivateKeyKey: key,
	}

	name := domain + "-tls"
	secret := sealer.CreateSecret(name, ns, v1.SecretTypeTLS, data)
	return s.seal(secret, certFilePath, kubeconfig, out)
}

func (s *SealService) seal(secret *v1.Secret, certFilePath, kubeconfig string, out io.Writer) error {
	// Strip read-only server-side ObjectMeta (if present)
	secret.SetSelfLink("")
	secret.SetUID("")
	secret.SetResourceVersion("")
	secret.Generation = 0
	secret.SetCreationTimestamp(metav1.Time{})
	secret.SetDeletionTimestamp(nil)
	secret.DeletionGracePeriodSeconds = nil

	f, err := s.openCert(certFilePath, kubeconfig)
	if err != nil {
		return fmt.Errorf("Cannot open cert: %v", err)
	}
	defer f.Close()

	pubKey, err := parseKey(f)
	if err != nil {
		return fmt.Errorf("Cannot parse pub key: %v", err)
	}

	codecs := scheme.Codecs

	ssecret, err := ssv1alpha1.NewSealedSecret(codecs, pubKey, secret)
	if err != nil {
		return fmt.Errorf("Cannot create sealed secret: %v", err)
	}
	if err = s.sealedSecretOutput(out, codecs, ssecret); err != nil {
		return fmt.Errorf("Cannot write sealed secret to output: %v", err)
	}
	return nil
}

func (s *SealService) sealedSecretOutput(out io.Writer, codecs runtimeserializer.CodecFactory, ssecret *ssv1alpha1.SealedSecret) error {
	var contentType string
	switch strings.ToLower(s.outputFormat) {
	case "json", "":
		contentType = runtime.ContentTypeJSON
	case "yaml":
		contentType = "application/yaml"
	default:
		return fmt.Errorf("unsupported output format: %s", s.outputFormat)
	}
	prettyEnc, err := s.prettyEncoder(codecs, contentType, ssv1alpha1.SchemeGroupVersion)
	if err != nil {
		return err
	}
	buf, err := runtime.Encode(prettyEnc, ssecret)
	if err != nil {
		return fmt.Errorf("Cannot encode sealed secret: %v", err)
	}
	out.Write(buf)
	fmt.Fprint(out, "\n")
	return nil
}

func (s *SealService) prettyEncoder(codecs runtimeserializer.CodecFactory, mediaType string, gv runtime.GroupVersioner) (runtime.Encoder, error) {
	info, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), mediaType)
	if !ok {
		return nil, fmt.Errorf("binary can't serialize %s", mediaType)
	}

	prettyEncoder := info.PrettySerializer
	if prettyEncoder == nil {
		prettyEncoder = info.Serializer
	}

	enc := codecs.EncoderForVersion(prettyEncoder, gv)
	return enc, nil
}

func (s *SealService) openCertHTTP(c corev1.CoreV1Interface, namespace, name string) (io.ReadCloser, error) {
	f, err := c.
		Services(namespace).
		ProxyGet("http", name, "", "/v1/cert.pem", nil).
		Stream()
	if err != nil {
		return nil, fmt.Errorf("Error fetching certificate: %v", err)

	}
	return f, nil

}

func (s *SealService) openCert(certFilePath, kubeconfig string) (io.ReadCloser, error) {
	if certFilePath != "" {
		return os.Open(certFilePath)
	}
	conf, err := clientConfig(kubeconfig).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("Cannot create *rest.Config: %v", err)

	}
	conf.AcceptContentTypes = "application/x-pem-file, */*"
	restClient, err := corev1.NewForConfig(conf)
	if err != nil {
		return nil, fmt.Errorf("Cannot create rest client: %v", err)

	}
	return s.openCertHTTP(restClient, s.controllerNs, s.controllerName)
}

func parseKey(r io.Reader) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err

	}

	certs, err := cert.ParseCertsPEM(data)
	if err != nil {
		return nil, err

	}

	// ParseCertsPem returns error if len(certs) == 0, but best to be sure...
	if len(certs) == 0 {
		return nil, errors.New("Failed to read any certificates")

	}

	cert, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Expected RSA public key but found %v", certs[0].PublicKey)

	}

	return cert, nil

}
