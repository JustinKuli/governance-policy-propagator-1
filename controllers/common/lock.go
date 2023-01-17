// Copyright Contributors to the Open Cluster Management project

package common

import (
	"sync"

	"k8s.io/apimachinery/pkg/types"
)

// PoliciesLock allows locking at the root policy level so that multiple controllers/goroutines don't race with each
// other and cause unnecessary reconcile retries.
type PoliciesLock struct {
	policies     map[types.NamespacedName]*sync.Mutex
	internalLock sync.Mutex
}

func (p *PoliciesLock) Lock(policy types.NamespacedName) {
	p.internalLock.Lock()

	if p.policies == nil {
		p.policies = map[types.NamespacedName]*sync.Mutex{}
	}

	if _, ok := p.policies[policy]; !ok {
		p.policies[policy] = &sync.Mutex{}
	}

	lock := p.policies[policy]

	p.internalLock.Unlock()

	lock.Lock()
}

func (p *PoliciesLock) Unlock(policy types.NamespacedName) {
	p.internalLock.Lock()

	lock := p.policies[policy]

	p.internalLock.Unlock()

	lock.Unlock()
}
