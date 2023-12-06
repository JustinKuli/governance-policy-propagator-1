// Copyright Contributors to the Open Cluster Management project

package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/lib/pq"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"

	"open-cluster-management.io/governance-policy-propagator/controllers/complianceeventsapi"
)

func getTableNames(db *sql.DB) ([]string, error) {
	tableNameRows, err := db.Query("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
	if err != nil {
		return nil, err
	} else if tableNameRows.Err() != nil {
		return nil, err
	}

	defer tableNameRows.Close()

	tableNames := []string{}

	for tableNameRows.Next() {
		var tableName string

		err := tableNameRows.Scan(&tableName)
		if err != nil {
			return nil, err
		}

		tableNames = append(tableNames, tableName)
	}

	return tableNames, nil
}

// Note: These tests require a running Postgres server running in the Kind cluster from the "postgres" Make target.
var _ = Describe("Test policy webhook", Label("compliance-events-api"), Ordered, func() {
	var k8sConfig *rest.Config
	var db *sql.DB

	BeforeAll(func(ctx context.Context) {
		var err error

		k8sConfig, err = LoadConfig("", "", "")
		Expect(err).ToNot(HaveOccurred())

		db, err = sql.Open("postgres", "postgresql://grc:grc@localhost:5432/ocm-compliance-history?sslmode=disable")
		DeferCleanup(func() {
			if db == nil {
				return
			}

			Expect(db.Close()).To(Succeed())
		})

		Expect(err).ToNot(HaveOccurred())

		Expect(db.Ping()).To(Succeed())

		// Drop all tables to start fresh
		tableNameRows, err := db.Query("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
		Expect(err).ToNot(HaveOccurred())

		defer tableNameRows.Close()

		tableNames, err := getTableNames(db)
		Expect(err).ToNot(HaveOccurred())

		for _, tableName := range tableNames {
			_, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS "+tableName+" CASCADE")
			Expect(err).ToNot(HaveOccurred())
		}

		mgrCtx, mgrCancel := context.WithCancel(context.Background())

		err = complianceeventsapi.StartManager(mgrCtx, k8sConfig, false)
		DeferCleanup(func() {
			mgrCancel()
		})

		Expect(err).ToNot(HaveOccurred())
	})

	Describe("Test the database migrations", func() {
		It("Initializes from a fresh database", func(ctx context.Context) {
			Eventually(func(g Gomega) {
				tableNames, err := getTableNames(db)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(tableNames).To(ContainElements("clusters", "parent_policies", "policies", "compliance_events"))

				migrationVersionRows := db.QueryRow("SELECT version, dirty FROM schema_migrations")
				var version int
				var dirty bool
				err = migrationVersionRows.Scan(&version, &dirty)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(version).To(Equal(1))
				g.Expect(dirty).To(BeFalse())
			}, defaultTimeoutSeconds, 1).Should(Succeed())
		})
	})

	Describe("Test POSTing Events", func() {
		const apiURL = "http://localhost:5480/api/v1/compliance-events"

		Describe("POST one valid event with including all the optional fields", func() {
			payload := []byte(`{
				"cluster": {
					"name": "cluster1",
					"cluster_id": "test1-cluster1-fake-uuid-1"
				},
				"parent_policy": {
					"name": "policies.etcd-encryption1",
					"categories": ["cat-1", "cat-2"],
					"controls": ["ctrl-1"],
					"standards": ["stand-1"]
				},
				"policy": {
					"apiGroup": "policy.open-cluster-management.io",
					"kind": "ConfigurationPolicy",
					"name": "etcd-encryption1",
					"spec": "{\"test\":\"one\",\"severity\":\"low\"}"
				},
				"event": {
					"compliance": "NonCompliant",
					"message": "configmaps [etcd] not found in namespace default",
					"timestamp": "2023-01-01T01:01:01.111Z",
					"metadata": {"test": true},
					"reported_by": "optional-test"
				}
			}`)

			BeforeAll(func(ctx context.Context) {
				By("POST the event")
				Eventually(postEvent(ctx, apiURL, payload), "5s", "1s").ShouldNot(HaveOccurred())
			})

			It("Should have created the cluster in a table", func() {
				rows, err := db.Query("SELECT * FROM clusters WHERE cluster_id = $1", "test1-cluster1-fake-uuid-1")
				Expect(err).ToNot(HaveOccurred())

				count := 0
				for rows.Next() {
					var (
						id        int
						name      string
						clusterId string
					)
					err := rows.Scan(&id, &name, &clusterId)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					Expect(name).To(Equal("cluster1"))
					count++
				}

				Expect(count).To(Equal(1))
			})

			It("Should have created the parent policy in a table", func() {
				rows, err := db.Query("SELECT * FROM parent_policies WHERE name = $1", "policies.etcd-encryption1")
				Expect(err).ToNot(HaveOccurred())

				count := 0
				for rows.Next() {
					var (
						id     int
						name   string
						cats   pq.StringArray
						ctrls  pq.StringArray
						stands pq.StringArray
					)

					err := rows.Scan(&id, &name, &cats, &ctrls, &stands)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					Expect(cats).To(ContainElements("cat-1", "cat-2"))
					Expect(ctrls).To(ContainElements("ctrl-1"))
					Expect(stands).To(ContainElements("stand-1"))
					count++
				}

				Expect(count).To(Equal(1))
			})

			It("Should have created the policy in a table", func() {
				rows, err := db.Query("SELECT * FROM policies WHERE name = $1", "etcd-encryption1")
				Expect(err).ToNot(HaveOccurred())

				count := 0
				for rows.Next() {
					var (
						id       int
						kind     string
						apiGroup string
						name     string
						ns       *string
						pid      *int
						spec     *string
						specHash *string
						severity *string
					)

					err := rows.Scan(&id, &kind, &apiGroup, &name, &ns, &pid, &spec, &specHash, &severity)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					Expect(kind).To(Equal("ConfigurationPolicy"))
					Expect(apiGroup).To(Equal("policy.open-cluster-management.io"))
					Expect(pid).ToNot(BeNil())
					Expect(*pid).ToNot(Equal(0))
					Expect(spec).ToNot(BeNil())
					Expect(*spec).To(Equal(`{"test":"one","severity":"low"}`))
					Expect(specHash).ToNot(BeNil())
					Expect(*specHash).To(Equal("cb84fe29e44202e3aeb46d39ba46993f60cdc6af"))
					Expect(severity).ToNot(BeNil())
					Expect(*severity).To(Equal("low"))

					count++
				}

				Expect(count).To(Equal(1))
			})

			It("Should have created the event in a table", func() {
				rows, err := db.Query("SELECT * FROM compliance_events WHERE timestamp = $1", "2023-01-01T01:01:01.111Z")
				Expect(err).ToNot(HaveOccurred())

				count := 0
				for rows.Next() {
					var (
						id         int
						clusterId  int
						policyId   int
						compliance string
						message    string
						timestamp  string
						metadata   *string
						reportedBy *string
					)

					err := rows.Scan(&id, &clusterId, &policyId, &compliance, &message, &timestamp, &metadata, &reportedBy)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					Expect(clusterId).NotTo(Equal(0))
					Expect(policyId).NotTo(Equal(0))
					Expect(compliance).To(Equal("NonCompliant"))
					Expect(message).To(Equal("configmaps [etcd] not found in namespace default"))
					Expect(timestamp).To(Equal("2023-01-01T01:01:01.111Z"))
					Expect(metadata).ToNot(BeNil())
					Expect(*metadata).To(Equal(`{"test":true}`))
					Expect(reportedBy).ToNot(BeNil())
					Expect(*reportedBy).To(Equal("optional-test"))
					count++
				}

				Expect(count).To(Equal(1))
			})
		})

		Describe("POST two minimally-valid events on different clusters and policies", func() {
			payload1 := []byte(`{
				"cluster": {
					"name": "cluster2",
					"cluster_id": "test2-cluster2-fake-uuid-2"
				},
				"policy": {
					"apiGroup": "policy.open-cluster-management.io",
					"kind": "ConfigurationPolicy",
					"name": "etcd-encryption2",
					"spec": "{\"test\":\"two\"}"
				},
				"event": {
					"compliance": "NonCompliant",
					"message": "configmaps [etcd] not found in namespace default",
					"timestamp": "2023-02-02T02:02:02.222Z"
				}
			}`)

			payload2 := []byte(`{
				"cluster": {
					"name": "cluster3",
					"cluster_id": "test2-cluster3-fake-uuid-3"
				},
				"policy": {
					"apiGroup": "policy.open-cluster-management.io",
					"kind": "ConfigurationPolicy",
					"name": "etcd-encryption2",
					"spec_hash": "cb84fe29e44202e3aeb46d39ba46993f60cdc6af"
				},
				"event": {
					"compliance": "Compliant",
					"message": "configmaps [etcd] found in namespace default",
					"timestamp": "2023-02-02T02:02:02.222Z"
				}
			}`)

			BeforeAll(func(ctx context.Context) {
				By("POST the events")
				Eventually(postEvent(ctx, apiURL, payload1), "5s", "1s").ShouldNot(HaveOccurred())
				Eventually(postEvent(ctx, apiURL, payload2), "5s", "1s").ShouldNot(HaveOccurred())
			})

			It("Should have created both clusters in a table", func() {
				rows, err := db.Query("SELECT * FROM clusters")
				Expect(err).ToNot(HaveOccurred())

				clusternames := make([]string, 0)

				for rows.Next() {
					var (
						id        int
						name      string
						clusterId string
					)
					err := rows.Scan(&id, &name, &clusterId)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					clusternames = append(clusternames, name)
				}

				Expect(clusternames).To(ContainElements("cluster2", "cluster3"))
			})

			It("Should have created two policies in a table despite having the same name", func() {
				rows, err := db.Query("SELECT * FROM policies WHERE name = $1", "etcd-encryption2")
				Expect(err).ToNot(HaveOccurred())

				hashes := make([]string, 0)
				for rows.Next() {
					var (
						id       int
						kind     string
						apiGroup string
						name     string
						ns       *string
						pid      *int
						spec     *string
						specHash *string
						severity *string
					)

					err := rows.Scan(&id, &kind, &apiGroup, &name, &ns, &pid, &spec, &specHash, &severity)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					Expect(specHash).ToNot(BeNil())
					hashes = append(hashes, *specHash)
				}

				Expect(hashes).To(ConsistOf(
					"cb84fe29e44202e3aeb46d39ba46993f60cdc6af",
					"2c6c7170351bfaa98eb45453b93766c18d24fa04",
				))
			})

			It("Should have created both events in a table", func() {
				rows, err := db.Query("SELECT * FROM compliance_events WHERE timestamp = $1", "2023-02-02T02:02:02.222Z")
				Expect(err).ToNot(HaveOccurred())

				messages := make([]string, 0)
				for rows.Next() {
					var (
						id         int
						clusterId  int
						policyId   int
						compliance string
						message    string
						timestamp  string
						metadata   *string
						reportedBy *string
					)

					err := rows.Scan(&id, &clusterId, &policyId, &compliance, &message, &timestamp, &metadata, &reportedBy)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					Expect(clusterId).NotTo(Equal(0))
					Expect(policyId).NotTo(Equal(0))

					messages = append(messages, message)
				}

				Expect(messages).To(ConsistOf(
					"configmaps [etcd] found in namespace default",
					"configmaps [etcd] not found in namespace default",
				))
			})
		})

		Describe("POST two events on the same cluster and policy", func() {
			// payload1 defines most things, and should cause the cluster, parent, and policy to be created.
			payload1 := []byte(`{
				"cluster": {
					"name": "cluster4",
					"cluster_id": "test3-cluster4-fake-uuid-4"
				},
				"parent_policy": {
					"name": "policies.common-parent",
					"categories": ["cat-3", "cat-4"],
					"controls": ["ctrl-2"],
					"standards": ["stand-2"]
				},
				"policy": {
					"apiGroup": "policy.open-cluster-management.io",
					"kind": "ConfigurationPolicy",
					"name": "common",
					"spec": "{\"test\":\"three\",\"severity\":\"low\"}"
				},
				"event": {
					"compliance": "NonCompliant",
					"message": "configmaps [common] not found in namespace default",
					"timestamp": "2023-03-03T03:03:03.333Z"
				}
			}`)

			// payload2 does not define the parent policy, but it should be inferred because
			// the policy is the same, even though it isn't identical.
			payload2 := []byte(`{
				"cluster": {
					"name": "cluster4",
					"cluster_id": "test3-cluster4-fake-uuid-4"
				},
				"policy": {
					"apiGroup": "policy.open-cluster-management.io",
					"kind": "ConfigurationPolicy",
					"name": "common",
					"spec_hash": "5382228c69c6017d4efbd6e42717930cb2020da0",
					"severity": "low"
				},
				"event": {
					"compliance": "NonCompliant",
					"message": "configmaps [common] not found in namespace default",
					"timestamp": "2023-04-04T04:04:04.444Z"
				}
			}`)

			BeforeAll(func(ctx context.Context) {
				By("POST the events")
				Eventually(postEvent(ctx, apiURL, payload1), "5s", "1s").ShouldNot(HaveOccurred())
				Eventually(postEvent(ctx, apiURL, payload2), "5s", "1s").ShouldNot(HaveOccurred())
			})

			It("Should have only created one cluster in the table", func() {
				rows, err := db.Query("SELECT * FROM clusters WHERE name = $1", "cluster4")
				Expect(err).ToNot(HaveOccurred())

				count := 0
				for rows.Next() {
					var (
						id        int
						name      string
						clusterId string
					)
					err := rows.Scan(&id, &name, &clusterId)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					count++
				}

				Expect(count).To(Equal(1))
			})

			It("Should have only created one parent policy in a table", func() {
				rows, err := db.Query("SELECT * FROM parent_policies WHERE name = $1", "policies.common-parent")
				Expect(err).ToNot(HaveOccurred())

				count := 0
				for rows.Next() {
					var (
						id     int
						name   string
						cats   pq.StringArray
						ctrls  pq.StringArray
						stands pq.StringArray
					)

					err := rows.Scan(&id, &name, &cats, &ctrls, &stands)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					count++
				}

				Expect(count).To(Equal(1))
			})

			It("Should have only created one policy in a table", func() {
				rows, err := db.Query("SELECT * FROM policies WHERE name = $1", "common")
				Expect(err).ToNot(HaveOccurred())

				hashes := make([]string, 0)
				for rows.Next() {
					var (
						id       int
						kind     string
						apiGroup string
						name     string
						ns       *string
						pid      *int
						spec     *string
						specHash *string
						severity *string
					)

					err := rows.Scan(&id, &kind, &apiGroup, &name, &ns, &pid, &spec, &specHash, &severity)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					Expect(specHash).ToNot(BeNil())
					hashes = append(hashes, *specHash)
				}

				Expect(hashes).To(ConsistOf(
					"5382228c69c6017d4efbd6e42717930cb2020da0",
				))
			})

			It("Should have created both events in a table", func() {
				rows, err := db.Query("SELECT * FROM compliance_events WHERE message = $1", "configmaps [common] not found in namespace default")
				Expect(err).ToNot(HaveOccurred())

				timestamps := make([]string, 0)
				for rows.Next() {
					var (
						id         int
						clusterId  int
						policyId   int
						compliance string
						message    string
						timestamp  string
						metadata   *string
						reportedBy *string
					)

					err := rows.Scan(&id, &clusterId, &policyId, &compliance, &message, &timestamp, &metadata, &reportedBy)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					Expect(clusterId).NotTo(Equal(0))
					Expect(policyId).NotTo(Equal(0))

					timestamps = append(timestamps, timestamp)
				}

				Expect(timestamps).To(ConsistOf(
					"2023-03-03T03:03:03.333Z",
					"2023-04-04T04:04:04.444Z",
				))
			})
		})

		Describe("POST events to check parent policy matching", func() {
			// payload1 defines most things, and should cause the cluster, parent, and policy to be created.
			payload1 := []byte(`{
				"cluster": {
					"name": "cluster5",
					"cluster_id": "test5-cluster5-fake-uuid-5"
				},
				"parent_policy": {
					"name": "policies.parent-a",
					"standards": ["stand-3"]
				},
				"policy": {
					"apiGroup": "policy.open-cluster-management.io",
					"kind": "ConfigurationPolicy",
					"name": "common-a",
					"spec": "{\"test\":\"four\",\"severity\":\"low\"}"
				},
				"event": {
					"compliance": "Compliant",
					"message": "configmaps [common] found in namespace default",
					"timestamp": "2023-05-05T05:05:05.555Z"
				}
			}`)

			// payload2 skips the standards array on the parent policy, but it should still be found
			payload2 := []byte(`{
				"cluster": {
					"name": "cluster5",
					"cluster_id": "test5-cluster5-fake-uuid-5"
				},
				"parent_policy": {
					"name": "policies.parent-a"
				},
				"policy": {
					"apiGroup": "policy.open-cluster-management.io",
					"kind": "ConfigurationPolicy",
					"name": "common-a",
					"spec": "{\"test\":\"four\",\"severity\":\"low\"}"
				},
				"event": {
					"compliance": "Compliant",
					"message": "configmaps [common] found in namespace default",
					"timestamp": "2023-06-06T06:06:06.666Z"
				}
			}`)

			// payload3 defines a different standards array on the parent policy, which should cause
			// a new parent policy to be created and linked to
			payload3 := []byte(`{
				"cluster": {
					"name": "cluster5",
					"cluster_id": "test5-cluster5-fake-uuid-5"
				},
				"parent_policy": {
					"name": "policies.parent-a",
					"standards": ["stand-4"]
				},
				"policy": {
					"apiGroup": "policy.open-cluster-management.io",
					"kind": "ConfigurationPolicy",
					"name": "common-a",
					"spec": "{\"test\":\"four\",\"severity\":\"low\"}"
				},
				"event": {
					"compliance": "Compliant",
					"message": "configmaps [common] found in namespace default",
					"timestamp": "2023-07-07T07:07:07.777Z"
				}
			}`)

			BeforeAll(func(ctx context.Context) {
				By("POST the events")
				Eventually(postEvent(ctx, apiURL, payload1), "5s", "1s").ShouldNot(HaveOccurred())
				Eventually(postEvent(ctx, apiURL, payload2), "5s", "1s").ShouldNot(HaveOccurred())
				Eventually(postEvent(ctx, apiURL, payload3), "5s", "1s").ShouldNot(HaveOccurred())
			})

			It("Should have created two parent policies", func() {
				rows, err := db.Query("SELECT * FROM parent_policies WHERE name = $1", "policies.parent-a")
				Expect(err).ToNot(HaveOccurred())

				standardArrays := make([]pq.StringArray, 0)
				for rows.Next() {
					var (
						id     int
						name   string
						cats   pq.StringArray
						ctrls  pq.StringArray
						stands pq.StringArray
					)

					err := rows.Scan(&id, &name, &cats, &ctrls, &stands)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					standardArrays = append(standardArrays, stands)
				}

				Expect(standardArrays).To(ConsistOf(
					pq.StringArray{"stand-3"},
					pq.StringArray{"stand-4"},
				))
			})

			It("Should have created two policies in a table, with different parents", func() {
				rows, err := db.Query("SELECT * FROM policies WHERE name = $1", "common-a")
				Expect(err).ToNot(HaveOccurred())

				ids := make([]int, 0)
				names := make([]string, 0)
				pids := make([]int, 0)
				hashes := make([]string, 0)
				for rows.Next() {
					var (
						id       int
						kind     string
						apiGroup string
						name     string
						ns       *string
						pid      *int
						spec     *string
						specHash *string
						severity *string
					)

					err := rows.Scan(&id, &kind, &apiGroup, &name, &ns, &pid, &spec, &specHash, &severity)
					Expect(err).ToNot(HaveOccurred())

					Expect(id).NotTo(Equal(0))
					Expect(specHash).ToNot(BeNil())
					ids = append(ids, id)
					names = append(names, name)
					pids = append(pids, *pid)
					hashes = append(hashes, *specHash)
				}

				Expect(ids).To(HaveLen(2))
				Expect(ids[0]).ToNot(Equal(ids[1]))
				Expect(names[0]).To(Equal(names[1]))
				Expect(pids[0]).ToNot(Equal(pids[1]))
				Expect(hashes[0]).To(Equal(hashes[1]))
			})
		})
	})
})

func postEvent(ctx context.Context, apiURL string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	errs := make([]error, 0, 0)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		errs = append(errs, err)
	}

	if resp != nil {
		defer resp.Body.Close()

		fmt.Println("Response Status:", resp.Status)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			errs = append(errs, err)
		}
		fmt.Println("Response Body:", string(body))

		if resp.StatusCode != 200 {
			errs = append(errs, fmt.Errorf("Got non-200 status code %v", resp.StatusCode))
		}
	}

	return errors.Join(errs...)
}
