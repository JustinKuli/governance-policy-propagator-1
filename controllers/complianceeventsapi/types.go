package complianceeventsapi

import (
	"bytes"
	"crypto/sha1"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

var (
	errRequiredFieldNotProvided = errors.New("required field not provided")
	errInvalidInput             = errors.New("invalid input")
)

type ComplianceEvent struct {
	Cluster      Cluster       `json:"cluster"`
	Event        EventDetails  `json:"event"`
	ParentPolicy *ParentPolicy `json:"parent_policy,omitempty"`
	Policy       Policy        `json:"policy"`
}

func (ce ComplianceEvent) Validate() error {
	errs := make([]error, 0, 0)

	if err := ce.Cluster.Validate(); err != nil {
		errs = append(errs, err)
	}

	if ce.ParentPolicy != nil {
		if err := ce.ParentPolicy.Validate(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := ce.Event.Validate(); err != nil {
		errs = append(errs, err)
	}

	if err := ce.Policy.Validate(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

type Cluster struct {
	KeyId     int    `db:"id" json:"-" goqu:"skipinsert"`
	Name      string `db:"name" json:"name"`
	ClusterId string `db:"cluster_id" json:"cluster_id"`
}

func (c Cluster) Validate() error {
	errs := make([]error, 0, 0)

	if c.Name == "" {
		errs = append(errs, fmt.Errorf("%w: cluster.name", errRequiredFieldNotProvided))
	}

	if c.ClusterId == "" {
		errs = append(errs, fmt.Errorf("%w: cluster.cluster_id", errRequiredFieldNotProvided))
	}

	return errors.Join(errs...)
}

type EventDetails struct {
	KeyId      int       `db:"id" json:"-" goqu:"skipinsert"`
	ClusterId  int       `db:"cluster_id" json:"-"`
	PolicyId   int       `db:"policy_id" json:"-"`
	Compliance string    `db:"compliance" json:"compliance"`
	Message    string    `db:"message" json:"message"`
	Timestamp  time.Time `db:"timestamp" json:"timestamp"`
	Metadata   JsonMap   `db:"metadata" json:"metadata,omitempty"`
	ReportedBy *string   `db:"reported_by" json:"reported_by,omitempty"`
}

func (e EventDetails) Validate() error {
	errs := make([]error, 0, 0)

	if e.Compliance == "" {
		errs = append(errs, fmt.Errorf("%w: event.compliance", errRequiredFieldNotProvided))
	} else {
		switch e.Compliance {
		case "Compliant", "compliant", "NonCompliant", "noncompliant":
		default:
			errs = append(errs, fmt.Errorf("%w: event.compliance should be Compliant or NonCompliant, got %v",
				errInvalidInput, e.Compliance))
		}
	}

	if e.Message == "" {
		errs = append(errs, fmt.Errorf("%w: event.message", errRequiredFieldNotProvided))
	}

	// TODO: check this one
	if e.Timestamp.IsZero() {
		errs = append(errs, fmt.Errorf("%w: event.timestamp", errRequiredFieldNotProvided))
	}

	return errors.Join(errs...)
}

type ParentPolicy struct {
	KeyId      int            `db:"id" json:"-" goqu:"skipinsert"`
	Name       string         `db:"name" json:"name"`
	Categories pq.StringArray `db:"categories" json:"categories,omitempty"`
	Controls   pq.StringArray `db:"controls" json:"controls,omitempty"`
	Standards  pq.StringArray `db:"standards" json:"standards,omitempty"`
}

func (p ParentPolicy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("%w: parent_policy.name", errRequiredFieldNotProvided)
	}

	return nil
}

func (p ParentPolicy) Key() parentPolicyKey {
	cats := make([]string, len(p.Categories))
	for i, c := range p.Categories {
		cats[i] = fmt.Sprintf("%q", c) // double-quoted and safely escaped with Go syntax
	}

	ctrls := make([]string, len(p.Controls))
	for i, c := range p.Controls {
		ctrls[i] = fmt.Sprintf("%q", c) // double-quoted and safely escaped with Go syntax
	}

	stands := make([]string, len(p.Standards))
	for i, c := range p.Standards {
		stands[i] = fmt.Sprintf("%q", c) // double-quoted and safely escaped with Go syntax
	}

	return parentPolicyKey{
		Name:       p.Name,
		Categories: fmt.Sprintf("[%v]", strings.Join(cats, ",")),
		Controls:   fmt.Sprintf("[%v]", strings.Join(ctrls, ",")),
		Standards:  fmt.Sprintf("[%v]", strings.Join(stands, ",")),
	}
}

type parentPolicyKey struct {
	Name       string
	Categories string
	Controls   string
	Standards  string
}

type Policy struct {
	KeyId          int     `db:"id" json:"-" goqu:"skipinsert"`
	Kind           string  `db:"kind" json:"kind"`
	ApiGroup       string  `db:"api_group" json:"apiGroup"`
	Name           string  `db:"name" json:"name"`
	Namespace      *string `db:"namespace" json:"namespace,omitempty"`
	ParentPolicyId *int    `db:"parent_policy_id" json:"-"`
	Spec           *string `db:"spec" json:"spec,omitempty"`
	SpecHash       *string `db:"spec_hash" json:"spec_hash,omitempty"`
	Severity       *string `db:"severity" json:"severity,omitempty"`
}

func (p *Policy) Validate() error {
	errs := make([]error, 0, 0)

	if p.ApiGroup == "" {
		errs = append(errs, fmt.Errorf("%w: policy.apiGroup", errRequiredFieldNotProvided))
	}

	if p.Kind == "" {
		errs = append(errs, fmt.Errorf("%w: policy.kind", errRequiredFieldNotProvided))
	}

	if p.Name == "" {
		errs = append(errs, fmt.Errorf("%w: policy.apiGroup", errRequiredFieldNotProvided))
	}

	if p.Spec == nil && p.SpecHash == nil {
		errs = append(errs, fmt.Errorf("%w: policy.spec or policy.specHash", errRequiredFieldNotProvided))
	}

	if p.Spec != nil {
		var buf bytes.Buffer
		if err := json.Compact(&buf, []byte(*p.Spec)); err != nil {
			errs = append(errs, fmt.Errorf("%w: policy.spec is not valid JSON: %w", errInvalidInput, err))
		} else if buf.String() != *p.Spec {
			errs = append(errs, fmt.Errorf("%w: policy.spec is not minified JSON", errInvalidInput))
		} else if p.SpecHash != nil {
			sum := sha1.Sum(buf.Bytes())

			if *p.SpecHash != hex.EncodeToString(sum[:]) {
				errs = append(errs, fmt.Errorf("%w: policy.specHash does not match the minified policy.Spec",
					errInvalidInput))
			}
		}
	}

	return errors.Join(errs...)
}

func (p *Policy) Key() policyKey {
	key := policyKey{
		Kind:     p.Kind,
		ApiGroup: p.ApiGroup,
		Name:     p.Name,
	}

	if p.Namespace != nil {
		key.Namespace = *p.Namespace
	}

	if p.ParentPolicyId != nil {
		key.ParentId = strconv.Itoa(*p.ParentPolicyId)
	}

	if p.SpecHash != nil {
		key.SpecHash = *p.SpecHash
	}

	if p.Severity != nil {
		key.Severity = *p.Severity
	}

	return key
}

type policyKey struct {
	Kind      string
	ApiGroup  string
	Name      string
	Namespace string
	ParentId  string
	SpecHash  string
	Severity  string
}

type JsonMap map[string]interface{}

func (j JsonMap) Value() (driver.Value, error) {
	return json.Marshal(j)
}

func (j *JsonMap) Scan(src interface{}) error {
	var source []byte

	switch src.(type) {
	case string:
		source = []byte(src.(string))
	case []byte:
		source = src.([]byte)
	case nil:
		source = nil
	default:
		return errors.New("Incompatible type for JsonMap")
	}

	return json.Unmarshal(source, j)
}
