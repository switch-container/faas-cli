package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/openfaas/faas-provider/types"
	"github.com/pkg/errors"
)

// DeployFunction first tries to deploy a function and if it exists will then attempt
// a rolling update. Warnings are suppressed for the second API call (if required.)
func (c *Client) RegisterFunction(context context.Context, spec *DeployFunctionSpec) error {
	// Need to alter Gateway to allow nil/empty string as fprocess, to avoid this repetition.
	var fprocessTemplate string
	if len(spec.FProcess) > 0 {
		fprocessTemplate = spec.FProcess
	}

	if spec.Replace {
		c.DeleteFunction(context, spec.FunctionName, spec.Namespace)
	}

	req := types.FunctionDeployment{
		EnvProcess:             fprocessTemplate,
		Image:                  spec.Image,
		Service:                spec.FunctionName,
		EnvVars:                spec.EnvVars,
		Constraints:            spec.Constraints,
		Secrets:                spec.Secrets,
		Labels:                 &spec.Labels,
		Annotations:            &spec.Annotations,
		ReadOnlyRootFilesystem: spec.ReadOnlyRootFilesystem,
		Namespace:              spec.Namespace,
		Language:               spec.Language,
	}

	hasLimits := false
	req.Limits = &types.FunctionResources{}
	if spec.FunctionResourceRequest.Limits != nil && len(spec.FunctionResourceRequest.Limits.Memory) > 0 {
		hasLimits = true
		req.Limits.Memory = spec.FunctionResourceRequest.Limits.Memory
	}
	if spec.FunctionResourceRequest.Limits != nil && len(spec.FunctionResourceRequest.Limits.CPU) > 0 {
		hasLimits = true
		req.Limits.CPU = spec.FunctionResourceRequest.Limits.CPU
	}
	if !hasLimits {
		req.Limits = nil
	}

	hasRequests := false
	req.Requests = &types.FunctionResources{}
	if spec.FunctionResourceRequest.Requests != nil && len(spec.FunctionResourceRequest.Requests.Memory) > 0 {
		hasRequests = true
		req.Requests.Memory = spec.FunctionResourceRequest.Requests.Memory
	}
	if spec.FunctionResourceRequest.Requests != nil && len(spec.FunctionResourceRequest.Requests.CPU) > 0 {
		hasRequests = true
		req.Requests.CPU = spec.FunctionResourceRequest.Requests.CPU
	}

	if !hasRequests {
		req.Requests = nil
	}

	reqBytes, _ := json.Marshal(&req)
	reader := bytes.NewReader(reqBytes)

	var request *http.Request
	query := url.Values{}
	var err error
	request, err = c.newRequest(http.MethodPost, "/system/register", query, reader)
	if err != nil {
		return err
	}

	res, err := c.doRequest(context, request)

	if err != nil {
		return errors.Wrap(err, "Is OpenFaaS deployed? Do you need to specify the --gateway flag?: %s")
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	switch res.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
	case http.StatusUnauthorized:
		return fmt.Errorf("unauthorized access, run \"faas-cli login\" to setup authentication for this server")
	default:
		bytesOut, err := io.ReadAll(res.Body)
		if err == nil {
			return fmt.Errorf("Unexpected status: %d, message: %s\n", res.StatusCode, string(bytesOut))
		}
		return err
	}
	return nil
}
