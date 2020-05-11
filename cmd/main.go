package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/teko-vn/k8s-sealer/bitnami"
	"github.com/teko-vn/k8s-sealer/rest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	server := rest.NewServer()
	sealHandler := rest.NewSealHandler()
	format := os.Getenv("OUTPUT_FORMAT")
	registry := os.Getenv("REGISTRY_HOST")
	sealHandler.SealService = bitnami.NewSealService(format, metav1.NamespaceSystem, "sealed-secrets-controller", registry)
	server.Handler = &rest.Handler{
		SealHandler: sealHandler,
	}
	server.Open()
	defer server.Close()
	// Interrupt handler.
	errc := make(chan error)
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)

	}()

	log.Fatal(fmt.Sprintf("exit %v", <-errc))
}
