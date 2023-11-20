package complianceeventsapi

import (
	"errors"
	"fmt"
	"time"
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

	if err := ce.Event.Validate(); err != nil {
		errs = append(errs, err)
	}

	if err := ce.Policy.Validate(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

type Cluster struct {
	KeyId     int    `db:"id" json:"-"`
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
	Compliance string                  `json:"compliance"`
	Message    string                  `json:"message"`
	Metadata   *map[string]interface{} `json:"metadata,omitempty"`
	Timestamp  time.Time               `json:"timestamp"`
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
	Categories *[]string `json:"categories,omitempty"`
	Controls   *[]string `json:"controls,omitempty"`
	Name       *string   `json:"name,omitempty"`
	Standards  *[]string `json:"standards,omitempty"`
}

type Policy struct {
	ApiGroup string  `json:"apiGroup"`
	Kind     string  `json:"kind"`
	Name     string  `json:"name"`
	Spec     *string `json:"spec,omitempty"`
	SpecHash *string `json:"specHash,omitempty"`
}

func (p Policy) Validate() error {
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

	return errors.Join(errs...)
}
