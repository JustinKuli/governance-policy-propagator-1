package complianceeventsapi

import (
	"bytes"
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/doug-martin/goqu/v9"
	_ "github.com/doug-martin/goqu/v9/dialect/postgres" // blank import the dialect driver
	_ "github.com/lib/pq"
)

var (
	clusterKeyCache      sync.Map
	parentPolicyKeyCache sync.Map
	policyKeyCache       sync.Map
)

type databaseAPIServer struct {
	Lock      *sync.Mutex
	server    *http.Server
	isRunning bool
}

// Start starts the http server. If it is already running, it has no effect.
func (s *databaseAPIServer) Start(dbURL string) error {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	if s.isRunning {
		return nil
	}

	mux := http.NewServeMux()

	s.server = &http.Server{
		Addr:    ":5480",
		Handler: mux,

		// need to investigate ideal values for these
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return err
	}

	goquDB := goqu.New("postgres", db)

	// register handlers here
	mux.HandleFunc("/api/v1/compliance-events", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			postComplianceEvent(goquDB)(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	go func() {
		err := s.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Error(err, "Error starting compliance events api server")
		}
	}()

	s.isRunning = true

	return nil
}

// Stop stops the http server. If it is not currently running, it has no effect.
func (s *databaseAPIServer) Stop() {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	if !s.isRunning {
		return
	}

	if err := s.server.Shutdown(context.TODO()); err != nil {
		log.Error(err, "Error stopping compliance events api server")
	}

	s.isRunning = false
}

func postComplianceEvent(goquDB *goqu.Database) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error(err, "error reading")
			http.Error(w, "Error reading request body", http.StatusBadRequest)

			return
		}

		reqEvent := &ComplianceEvent{}

		if err := json.Unmarshal(body, reqEvent); err != nil {
			log.Error(err, "error unmarshalling")
			http.Error(w, "Incorrectly formatted request body", http.StatusBadRequest)

			return
		}

		if err := reqEvent.Validate(); err != nil {
			log.Error(err, "error validating")
			http.Error(w, "Invalid request body", http.StatusBadRequest)

			return
		}

		clusterFK, err := getClusterForeignKey(r.Context(), goquDB, reqEvent.Cluster)
		if err != nil {
			log.Error(err, "error getting cluster foreign key")
			http.Error(w, "Internal Error", http.StatusInternalServerError)

			return
		}

		reqEvent.Event.ClusterID = clusterFK

		if reqEvent.ParentPolicy != nil {
			pfk, err := getParentPolicyForeignKey(r.Context(), goquDB, *reqEvent.ParentPolicy)
			if err != nil {
				log.Error(err, "error getting parent policy foreign key")
				http.Error(w, "Internal Error", http.StatusInternalServerError)

				return
			}

			reqEvent.Policy.ParentPolicyID = &pfk
		}

		policyFK, err := getPolicyForeignKey(r.Context(), goquDB, reqEvent.Policy)
		if err != nil {
			log.Error(err, "error getting policy foreign key")
			http.Error(w, "Internal Error", http.StatusInternalServerError)

			return
		}

		reqEvent.Event.PolicyID = policyFK

		insert := goquDB.Insert("compliance_events").Rows(reqEvent.Event).Executor()

		_, err = insert.Exec()
		if err != nil {
			log.Error(err, "error inserting compliance event")
			http.Error(w, "Internal Error", http.StatusInternalServerError)
		}
	}
}

// NOTE: it is tempting to refactor these get*ForeignKey functions to something more generic.
// But right now, that is a trap - these are very simple queries which make them look the same!
// The constraints on each different table means that the `Where` query will probably need to be
// more specific for each different kind... that might still be possible to abstract via methods and
// a common interface, but right now, things are not ready for that. And it's not clear if that will
// be useful.

func getClusterForeignKey(ctx context.Context, goquDB *goqu.Database, cluster Cluster) (int, error) {
	// Check cache
	key, ok := clusterKeyCache.Load(cluster.ClusterID)
	if ok {
		return key.(int), nil
	}

	foundCluster := new(Cluster)

	found, err := goquDB.From("clusters").
		Where(goqu.Ex{"cluster_id": cluster.ClusterID}).
		ScanStructContext(ctx, foundCluster)
	if err != nil {
		return 0, err
	}

	// If the row already exists
	if found {
		clusterKeyCache.Store(cluster.ClusterID, foundCluster.KeyID)

		return foundCluster.KeyID, nil
	}

	// Otherwise, create a new row in the table
	insert := goquDB.Insert("clusters").Returning("id").Rows(cluster).Executor()

	id := new(int)
	if _, err := insert.ScanValContext(ctx, id); err != nil {
		return 0, err
	}

	clusterKeyCache.Store(cluster.ClusterID, *id)

	return *id, nil
}

func getParentPolicyForeignKey(ctx context.Context, goquDB *goqu.Database, parent ParentPolicy) (int, error) {
	// Check cache
	parKey := parent.key()

	key, ok := parentPolicyKeyCache.Load(parKey)
	if ok {
		return key.(int), nil
	}

	foundParent := new(ParentPolicy)

	uniqueFieldsMatch := goqu.Ex{
		"name": parent.Name,
	}

	if len(parent.Categories) > 0 {
		uniqueFieldsMatch["categories"] = goqu.L("?::text[]", parent.Categories)
	}

	if len(parent.Controls) > 0 {
		uniqueFieldsMatch["controls"] = goqu.L("?::text[]", parent.Controls)
	}

	if len(parent.Standards) > 0 {
		uniqueFieldsMatch["standards"] = goqu.L("?::text[]", parent.Standards)
	}

	qu := goquDB.From("parent_policies").Where(uniqueFieldsMatch)

	found, err := qu.ScanStructContext(ctx, foundParent)
	if err != nil {
		return 0, err
	}

	// If the row already exists
	if found {
		parentPolicyKeyCache.Store(parKey, foundParent.KeyID)

		return foundParent.KeyID, nil
	}

	// Otherwise, create a new row in the table
	insert := goquDB.Insert("parent_policies").Returning("id").Rows(parent).Executor()

	id := new(int)
	if _, err := insert.ScanValContext(ctx, id); err != nil {
		return 0, err
	}

	parentPolicyKeyCache.Store(parKey, *id)

	return *id, nil
}

func getPolicyForeignKey(ctx context.Context, goquDB *goqu.Database, pol Policy) (int, error) {
	// Fill in missing fields that can be inferred from other fields
	if pol.SpecHash == nil {
		var buf bytes.Buffer
		if err := json.Compact(&buf, []byte(*pol.Spec)); err != nil {
			return 0, err // This kind of error would have been found during validation
		}

		sum := sha1.Sum(buf.Bytes())
		hash := hex.EncodeToString(sum[:])
		pol.SpecHash = &hash
	}

	if pol.Severity == nil && pol.Spec != nil {
		var specData map[string]interface{}
		if err := json.Unmarshal([]byte(*pol.Spec), &specData); err != nil {
			return 0, err // This kind of error would have been found during validation
		}

		if sev, found := specData["severity"]; found {
			if sevStr, ok := sev.(string); ok {
				pol.Severity = &sevStr
			}
		}
	}

	// Check cache
	polKey := pol.key()

	key, ok := policyKeyCache.Load(polKey)
	if ok {
		return key.(int), nil
	}

	foundPolicy := new(Policy)

	uniqueFieldsMatch := goqu.Ex{
		"kind":      pol.Kind,
		"api_group": pol.APIGroup,
		"name":      pol.Name,
		"spec_hash": pol.SpecHash,
	}

	if pol.Namespace != nil {
		uniqueFieldsMatch["namespace"] = *pol.Namespace
	}

	if pol.ParentPolicyID != nil {
		uniqueFieldsMatch["parent_policy_id"] = *pol.ParentPolicyID
	}

	if pol.Severity != nil {
		uniqueFieldsMatch["severity"] = *pol.Severity
	}

	found, err := goquDB.From("policies").Where(uniqueFieldsMatch).ScanStructContext(ctx, foundPolicy)
	if err != nil {
		return 0, err
	}

	// If the row already exists
	if found {
		policyKeyCache.Store(polKey, foundPolicy.KeyID)

		return foundPolicy.KeyID, nil
	}

	// Otherwise, create a new row in the table
	insert := goquDB.Insert("policies").Returning("id").Rows(pol).Executor()

	id := new(int)
	if _, err := insert.ScanValContext(ctx, id); err != nil {
		return 0, err
	}

	policyKeyCache.Store(polKey, *id)

	return *id, nil
}
