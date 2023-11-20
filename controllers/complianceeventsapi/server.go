package complianceeventsapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/doug-martin/goqu/v9"
	_ "github.com/doug-martin/goqu/v9/dialect/postgres"
	_ "github.com/lib/pq"
)

var clusterKeyCache sync.Map

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

	if err := s.server.Shutdown(nil); err != nil {
		log.Error(err, "Error stopping compliance events api server")
	}

	s.isRunning = false
}

func postComplianceEvent(goquDB *goqu.Database) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Println(err, "error reading")
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}

		reqEvent := &ComplianceEvent{}

		if err := json.Unmarshal(body, reqEvent); err != nil {
			fmt.Println(err, "error unmarshalling")
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if err := reqEvent.Validate(); err != nil {
			fmt.Println(err, "error validating")
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		_, _ = getClusterForeignKey(r.Context(), goquDB, reqEvent.Cluster)
	}
}

func getClusterForeignKey(ctx context.Context, goquDB *goqu.Database, cluster Cluster) (int, error) {
	// Check cache
	key, ok := clusterKeyCache.Load(cluster.ClusterId)
	if ok {
		return key.(int), nil
	}

	foundCluster := &Cluster{}
	found, err := goquDB.From("clusters").
		Where(goqu.Ex{"cluster_id": cluster.ClusterId}).
		ScanStructContext(ctx, foundCluster)
	if err != nil {
		return 0, err
	}

	// If the row already exists
	if found {
		clusterKeyCache.Store(cluster.ClusterId, foundCluster.KeyId)

		return foundCluster.KeyId, nil
	}

	// Otherwise, create a new row in the clusters table
	insert := goquDB.Insert("clusters").Returning("id").Rows(cluster).Executor()

	var newId int
	if _, err := insert.ScanValContext(ctx, &newId); err != nil {
		return 0, err
	}

	clusterKeyCache.Store(cluster.ClusterId, newId)

	return newId, nil
}
