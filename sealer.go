package sealer

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SealService represents a service that seals secrets
type SealService interface {
	SealOpaque(out io.Writer, cluster, name, ns string, data map[string][]byte) error
	SealDockerconfigjson(out io.Writer, cluster, name, ns, username, password string) error
	SealTLS(out io.Writer, cluster, ns, domain string) error
}

// CreateSecret creates a raw kubernetes secret
func CreateSecret(name, ns string, typ v1.SecretType, data map[string][]byte) *v1.Secret {
	s := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Type: typ,
	}
	s.Data = data

	return s
}

// CreateDockerconfigjson creates a docker config.json for registry authentication
func CreateDockerconfigjson(host, username, password string) []byte {
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	out := fmt.Sprintf(`{"auths":{"%s":{"auth": "%s"}}}`, host, auth)
	return []byte(out)
}

// CertFilePath get cluster's sealed secret pub cert from env vars
func CertFilePath(cluster string) (string, error) {
	switch cluster {
	case "production":
		return os.Getenv("PROD_CERT_FILE"), nil
	case "lab":
		return os.Getenv("LAB_CERT_FILE"), nil
	case "dev":
		return os.Getenv("DEV_CERT_FILE"), nil
	case "stage":
		return os.Getenv("STAGE_CERT_FILE"), nil
	default:
		return "", fmt.Errorf("Invalid cluster: %s", cluster)
	}
}

// KubeconfigFile get cluster's kube config from env vars
func KubeconfigFile(cluster string) (string, error) {
	switch cluster {
	case "production":
		return os.Getenv("PROD_KUBECONFIG_FILE"), nil
	case "lab":
		return os.Getenv("LAB_KUBECONFIG_FILE"), nil
	case "dev":
		return os.Getenv("DEV_KUBECONFIG_FILE"), nil
	case "stage":
		return os.Getenv("STAGE_KUBECONFIG_FILE"), nil
	default:
		return "", fmt.Errorf("Invalid cluster: %s", cluster)
	}
}

// GetTLS get TLS for given domain from env vars
func GetTLS(domain string) ([]byte, []byte, error) {
	var certFile, keyFile string
	if strings.HasSuffix(domain, ".services.teko.vn") {
		certFile = os.Getenv("SERVICES_TLS_CERT_FILE")
		keyFile = os.Getenv("SERVICES_TLS_KEY_FILE")
	} else if strings.HasSuffix(domain, ".teko.vn") {
		certFile = os.Getenv("TEKO_TLS_CERT_FILE")
		keyFile = os.Getenv("TEKO_TLS_KEY_FILE")
	} else if strings.HasSuffix(domain, ".vnshop.vn") {
		certFile = os.Getenv("VNSHOP_TLS_CERT_FILE")
		keyFile = os.Getenv("VNSHOP_TLS_KEY_FILE")
	} else {
		return nil, nil, fmt.Errorf("Unsupported domain: %s. Domain must be *.teko.vn or *.services.teko.vn or *.vnshop.vn", domain)
	}
	certData, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, nil, errors.New("Cannot read tls cert file")
	}
	keyData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, errors.New("Cannot read tls key file")
	}
	return certData, keyData, nil
}
