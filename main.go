package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/ext"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/aquasecurity/starboard/pkg/plugin/trivy"
	"github.com/aquasecurity/starboard/pkg/runner"
	"github.com/aquasecurity/starboard/pkg/starboard"
	"github.com/aquasecurity/starboard/pkg/vulnerabilityreport"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

// TODO: Remove job after successfull
func main() {
	ctx := context.Background()
	config := kubeRestConfig()

	cl, err := controllerClient(config)
	if err != nil {
		log.Fatalf("new controllerClient: %v", err)
	}

	kubeClient, err := kubeClient(config)
	if err != nil {
		log.Fatalf("new kubeclient: %v", err)
	}

	plugin := trivy.NewPlugin(ext.NewSystemClock(), ext.NewSimpleIDGenerator(), cl)
	plugCtx := starboard.NewPluginContext().
		WithClient(cl).
		WithNamespace("default").
		//WithServiceAccountName("trivy-sa").
		WithName(trivy.Plugin).
		Get()

	err = plugin.Init(plugCtx)
	if err != nil {
		log.Fatalf("initializing trivy: %v", err)
	}

	job, secrets, err := vulnerabilityreport.NewScanJobBuilder().
		WithPlugin(plugin).
		WithObject(newMockPod("test", "default")).
		WithPluginContext(plugCtx).
		Get()

	if err != nil {
		log.Fatalf("scanjobbuiler: %v", err)
	}

	err = runner.New().Run(ctx, kube.NewRunnableJob(cl.Scheme(), kubeClient, job, secrets...))
	if err != nil {
		log.Fatalf("running scan job: %v", err)
	}

	logsReader := kube.NewLogsReader(kubeClient)

	containerImages, err := kube.GetContainerImagesFromJob(job)
	if err != nil {
		log.Fatalf("getting container images: %v", err)
	}

	var reports []v1alpha1.VulnerabilityReport
	for containerName, containerImage := range containerImages {
		logsStream, err := logsReader.GetLogsByJobAndContainerName(ctx, job, containerName)
		if err != nil {
			log.Fatalf("getting job logs for %v: %v", containerName, err)
		}
		reportData, err := plugin.ParseVulnerabilityReportData(plugCtx, containerImage, logsStream)
		if err != nil {
			log.Fatalf("parsing vuln report data for %v: %v", containerName, err)
		}

		_ = logsStream.Close()

		report := v1alpha1.VulnerabilityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("test-%v", containerName),
				Namespace: "default",
			},
			Report: reportData,
		}
		reports = append(reports, report)
	}

	writer := vulnerabilityreport.NewReadWriter(cl)
	err = writer.Write(ctx, reports)
	if err != nil {
		log.Fatalf("writing reports: %v", err)
	}
}

func controllerClient(config *rest.Config) (client.Client, error) {
	return client.New(config, client.Options{
		Scheme: starboard.NewScheme(),
	})
}

func kubeRestConfig() *rest.Config {
	return config.GetConfigOrDie()
}

func kubeClient(config *rest.Config) (*kubernetes.Clientset, error) {
	return kubernetes.NewForConfig(config)
}

func newMockPod(name, namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "lul1",
					Image: "ubuntu:focal",
				},
			},
		},
	}
}
