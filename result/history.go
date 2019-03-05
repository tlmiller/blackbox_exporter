// Copyright 2017 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package result

import (
	"sync"
)

type Result struct {
	Id          int64
	ModuleName  string
	Target      string
	DebugOutput string
	Success     bool
}

type ResultHistory struct {
	Mu         sync.Mutex
	NextId     int64
	Results    []*Result
	MaxResults uint
}

// Add a result to the history.
func (rh *ResultHistory) Add(moduleName, target, debugOutput string, success bool) {
	rh.Mu.Lock()
	defer rh.Mu.Unlock()

	r := &Result{
		Id:          rh.NextId,
		ModuleName:  moduleName,
		Target:      target,
		DebugOutput: debugOutput,
		Success:     success,
	}
	rh.NextId++

	rh.Results = append(rh.Results, r)
	if uint(len(rh.Results)) > rh.MaxResults {
		results := make([]*Result, len(rh.Results)-1)
		copy(results, rh.Results[1:])
		rh.Results = results
	}
}

// Return a list of all results.
func (rh *ResultHistory) List() []*Result {
	rh.Mu.Lock()
	defer rh.Mu.Unlock()

	return rh.Results[:]
}

// Return a given result.
func (rh *ResultHistory) Get(id int64) *Result {
	rh.Mu.Lock()
	defer rh.Mu.Unlock()

	for _, r := range rh.Results {
		if r.Id == id {
			return r
		}
	}

	return nil
}
