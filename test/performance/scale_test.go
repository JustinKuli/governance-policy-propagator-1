// Copyright (c) 2022 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package performance

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	v1 "open-cluster-management.io/governance-policy-propagator/api/v1"
	"open-cluster-management.io/governance-policy-propagator/test/utils"
	appsv1 "open-cluster-management.io/multicloud-operators-subscription/pkg/apis/apps/placementrule/v1"
)

var _ = Describe("Performance information gathering", Ordered, func() {
	policyNames := []string{
		"snivy",
		"tepig",
		"oshawott",
		"chespin",
		"fennekin",
		"froakie",
	}

	managedClusterCount := 0

	ensureManagedCount := func(want int) error {
		if managedClusterCount >= want {
			return nil
		}

		var wg sync.WaitGroup
		var collectErr error
		start := managedClusterCount
		for start < want {
			// create managed clusters in parallel to speed it up (hopefully)
			end := start + 100
			if end > want {
				end = want
			}

			wg.Add(1)
			go func(start, end int) {
				err := createManagedClusters(start, end)
				if err != nil {
					collectErr = err
				}
				wg.Done()
			}(start, end)

			start += 100
		}

		wg.Wait()

		managedClusterCount = want

		return collectErr
	}

	metricsPollCtx, metricsPollCancel := context.WithCancel(context.Background())

	BeforeAll(func() {
		_, err := os.Stat("./out")
		if err != nil {
			Expect(os.IsNotExist(err))
		} else {
			By("saving old output")
			os.Rename("./out", "out-bak-"+time.Now().Format(time.RFC3339))
		}

		By("Creating a new output directory")
		err = os.Mkdir("./out", 0o755)
		Expect(err).To(BeNil())

		By("Creating some policies")
		resint := clientHubDynamic.Resource(gvrPolicy).Namespace(testNamespace)
		for _, pName := range policyNames {
			p := simplePolicy(pName)
			_, err := resint.Create(context.TODO(), &p, metav1.CreateOptions{})
			if err != nil {
				Expect(errors.IsAlreadyExists(err)).To(BeTrue())
			}
		}

		By("Starting something to poll the metrics endpoint")
		err = os.Mkdir("./out/metrics", 0o755)
		Expect(err).To(BeNil())

		go func() {
			for i := 0; i < 360; i++ { // max 1 hour, just for safety
				loopstart := time.Now()

				select {
				case <-metricsPollCtx.Done():
					return
				default:
					exec.Command(
						"curl", "--silent",
						"--output", "./out/metrics/"+strconv.Itoa(i)+"-at-"+time.Now().Format(time.RFC3339),
						"localhost:8383/metrics",
					).CombinedOutput()

					time.Sleep(time.Until(loopstart.Add(10 * time.Second)))
				}
			}
		}()
	})

	AfterAll(func() {
		metricsPollCancel()
	})

	It("Baseline", func() {
		By("Waiting 10s for everything to be happily started...")
		time.Sleep(10 * time.Second)

		err := profile("baseline")
		Expect(err).To(BeNil())
	})

	type perftest struct {
		policyName   string
		clusterCount int
		profileCount int
	}

	tests := []perftest{{
		// 	policyName:   policyNames[0],
		// 	clusterCount: 100,
		// 	profileCount: 1,
		// }, {
		policyName:   policyNames[1],
		clusterCount: 300,
		profileCount: 2,
	}, {
		// 	policyName:   policyNames[2],
		// 	clusterCount: 600,
		// 	profileCount: 1,
		// }, {
		policyName:   policyNames[3],
		clusterCount: 1000,
		profileCount: 2,
	}, {
		policyName:   policyNames[4],
		clusterCount: 2000,
		profileCount: 2,
	}, {
		policyName:   policyNames[5],
		clusterCount: 3000,
		profileCount: 2,
	}}

	for _, test := range tests {
		test := test
		It("testing "+strconv.Itoa(test.clusterCount)+" clusters", func() {
			By("ensuring the right number of managed clusters")
			err := ensureManagedCount(test.clusterCount)
			Expect(err).To(BeNil())

			By("placing " + test.policyName + " on the clusters")
			err = placePoliciesOnClusters(test.clusterCount, test.policyName)
			Expect(err).To(BeNil())

			By("Wait 10s for things to stabilize after adding policies")
			time.Sleep(10 * time.Second)

			chaosCtx, cancel := context.WithCancel(context.Background())
			defer cancel()

			By("Launching chaos threads")
			for i := 0; i < test.clusterCount; i += 50 {
				go chaos(chaosCtx, test.policyName, i, test.clusterCount)
				time.Sleep(200 * time.Millisecond)
			}

			By("Wait 10s for things to get chaotic")
			time.Sleep(10 * time.Second)

			for i := 0; i < test.profileCount; i++ {
				err := profile(fmt.Sprintf("busy%v-%v", test.clusterCount, i))
				Expect(err).To(BeNil())
			}
		})
	}
})

func simplePolicy(name string) unstructured.Unstructured {
	return unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": v1.GroupVersion.String(),
			"kind":       v1.Kind,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": testNamespace,
			},
			"spec": map[string]interface{}{
				"remediationAction": "inform",
				"disabled":          false,
				"policy-templates": []map[string]interface{}{
					{
						"objectDefinition": map[string]interface{}{
							"apiVersion": "policies.dev/v1alpha1",
							"kind":       "PerformancePolicy",
							"metadata": map[string]interface{}{
								"name": name,
							},
							"spec": map[string]interface{}{
								"severity": "low",
								"namespaceSelector": map[string]interface{}{
									"include": []string{"default"},
									"exclude": []string{"kube-system"},
								},
								"remediationAction": "inform",
							},
						},
					},
				},
			},
		},
	}
}

func profile(name string) error {
	err := os.MkdirAll("out/"+name, 0o755)
	if err != nil {
		return err
	}

	_, err = exec.Command(
		"curl", "--silent",
		"--output", "./out/"+name+"/heap-start.pprof",
		"localhost:6060/debug/pprof/heap",
	).CombinedOutput()
	if err != nil {
		return err
	}

	By("Starting 60s profile for " + name)
	_, err = exec.Command(
		"curl", "--silent",
		"--output", "./out/"+name+"/cpu60s.pprof",
		"localhost:6060/debug/pprof/profile?seconds=60",
	).CombinedOutput()
	if err != nil {
		return err
	}

	_, err = exec.Command(
		"curl", "--silent",
		"--output", "./out/"+name+"/heap-end.pprof",
		"localhost:6060/debug/pprof/heap",
	).CombinedOutput()
	if err != nil {
		return err
	}

	return err
}

func createManagedClusters(present, want int) error {
	dynClient := NewKubeClientDynamic("", "", "")
	mcInt := dynClient.Resource(gvrManagedCluster)
	client := NewKubeClient("", "", "")
	nsInt := client.CoreV1().Namespaces()
	for present < want {
		name := clusterName(present)

		mc := unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "cluster.open-cluster-management.io/v1",
				"kind":       "ManagedCluster",
				"metadata": map[string]interface{}{
					"name": name,
				},
			},
		}

		_, err := mcInt.Create(context.TODO(), &mc, metav1.CreateOptions{})
		if err != nil {
			return err
		}

		ns := corev1.Namespace{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Namespace",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		}

		_, err = nsInt.Create(context.TODO(), &ns, metav1.CreateOptions{})
		if err != nil {
			return err
		}

		present++
	}

	return nil
}

func clusterName(i int) string {
	return fmt.Sprintf("perfmc-%04d", i)
}

func placePoliciesOnClusters(count int, name string) error {
	clusters := make([]string, count)
	for i := 0; i < count; i++ {
		clusters[i] = clusterName(i)
	}

	plr := appsv1.PlacementRule{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps.open-cluster-management.io/v1",
			Kind:       "PlacementRule",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec:   appsv1.PlacementRuleSpec{},
		Status: *utils.GeneratePlrStatus(clusters...),
	}

	plrObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&plr)
	if err != nil {
		return err
	}

	plrUnstruct := unstructured.Unstructured{
		Object: plrObj,
	}

	plrInterface := clientHubDynamic.Resource(gvrPlacementRule).Namespace(testNamespace)

	plrCreated, err := plrInterface.Create(context.TODO(), &plrUnstruct, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	plrCreated.Object["status"] = plrUnstruct.Object["status"]
	_, err = plrInterface.UpdateStatus(context.TODO(), plrCreated, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	pb := v1.PlacementBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1.GroupVersion.String(),
			Kind:       "PlacementBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		PlacementRef: v1.PlacementSubject{
			APIGroup: "apps.open-cluster-management.io",
			Kind:     "PlacementRule",
			Name:     name,
		},
		Subjects: []v1.Subject{
			{
				APIGroup: v1.GroupVersion.Group,
				Kind:     v1.Kind,
				Name:     name,
			},
		},
	}

	pbObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pb)
	if err != nil {
		return err
	}

	pbUnstruct := unstructured.Unstructured{
		Object: pbObj,
	}

	pbInterface := clientHubDynamic.Resource(gvrPlacementBinding).Namespace(testNamespace)
	_, err = pbInterface.Create(context.TODO(), &pbUnstruct, metav1.CreateOptions{})

	return err
}

func setRandomCompliance(ctx context.Context, client dynamic.Interface, policyName string, cluster int) error {
	polInt := client.Resource(gvrPolicy).Namespace(clusterName(cluster))
	replPolicyName := testNamespace + "." + policyName

	policy, err := polInt.Get(ctx, replPolicyName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	compliance := "Compliant"
	message := "Compliant; notification - the fates smile upon you"
	if rand.Intn(100) < 50 {
		compliance = "NonCompliant"
		message = "NonCompliant; violation - just unlucky"
	}

	now := time.Now()
	eventName := fmt.Sprintf("%s.%s.%x", testNamespace, policyName, now.UnixNano())

	policy.Object["status"] = map[string]interface{}{
		"compliant": compliance,
		"details": []map[string]interface{}{
			{
				"compliant": compliance,
				"history": []map[string]interface{}{
					{
						"eventName":     eventName,
						"lastTimestamp": metav1.Time{Time: now},
						"message":       message,
					},
				},
				"templateMeta": map[string]interface{}{
					"creationTimestamp": nil,
					"name":              policyName,
				},
			},
		},
	}

	updatedPolicy, err := polInt.UpdateStatus(ctx, policy, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	gotCompliance, found, err := unstructured.NestedString(updatedPolicy.Object, "status", "compliant")
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("did not find compliance after updating policy")
	}
	if gotCompliance != compliance {
		return fmt.Errorf("compliance mismatch: got '%v', expected '%v'", gotCompliance, compliance)
	}

	return nil
}

func chaos(ctx context.Context, policyName string, i, max int) {
	client := NewKubeClientDynamic("", "", "")
	for {
		loopstart := time.Now()
		select {
		case <-ctx.Done():
			return
		default:
			err := setRandomCompliance(ctx, client, policyName, i)
			if err != nil {
				fmt.Println("setRandomCompliance err", policyName, i, err)
			}

			i = (i + 1) % max

			time.Sleep(time.Until(loopstart.Add(2 * time.Second)))
		}
	}
}
