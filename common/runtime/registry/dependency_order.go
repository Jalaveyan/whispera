package registry

import (
	"fmt"
	"sort"
)

func (r *registry) computeStartOrder() ([]string, error) {
	inDegree := make(map[string]int)
	deps := make(map[string][]string)

	for name := range r.modules {
		inDegree[name] = 0
		deps[name] = make([]string, 0)
	}

	for name, entry := range r.modules {
		for _, dep := range entry.module.Dependencies() {
			if _, exists := r.modules[dep]; !exists {
				return nil, fmt.Errorf("module %q depends on unregistered module %q", name, dep)
			}
			deps[dep] = append(deps[dep], name)
			inDegree[name]++
		}
	}

	queue := make([]string, 0)
	for name, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}

	sort.Strings(queue)

	order := make([]string, 0, len(r.modules))
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		order = append(order, name)

		dependents := deps[name]
		sort.Strings(dependents)
		for _, dependent := range dependents {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	if len(order) != len(r.modules) {
		return nil, fmt.Errorf("circular dependency detected in modules")
	}

	return order, nil
}
