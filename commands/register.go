// Copyright (c) Alex Ellis 2017. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/openfaas/faas-cli/builder"
	"github.com/openfaas/faas-cli/proxy"
	"github.com/openfaas/faas-cli/schema"
	"github.com/openfaas/faas-cli/stack"
	"github.com/openfaas/faas-cli/util"

	"github.com/spf13/cobra"
)

// NOTE by huang-jl: `register` is almost the same as `deploy`
// which is a new feature that I added to faasd to support scaling.
//
// I remove some options existing in `deploy` for simplicity.

// RegisterFlags holds flags that are to be added to commands.
type RegisterFlags struct {
	envvarOpts  []string
	constraints []string
	labelOpts   []string
	secrets     []string
}

var registerFlags RegisterFlags

func init() {
	// Setup flags that are used by multiple commands (variables defined in faas.go)
	registerCmd.Flags().StringVar(&fprocess, "fprocess", "", "fprocess value to be run as a serverless function by the watchdog")
	registerCmd.Flags().StringVarP(&gateway, "gateway", "g", defaultGateway, "Gateway URL starting with http(s)://")
	registerCmd.Flags().StringVar(&handler, "handler", "", "Directory with handler for function, e.g. handler.js")
	registerCmd.Flags().StringVar(&image, "image", "", "Docker image name to build")
	registerCmd.Flags().StringVar(&language, "lang", "", "Programming language template")
	registerCmd.Flags().StringVar(&functionName, "name", "", "Name of the registered function")
	registerCmd.Flags().StringVar(&network, "network", defaultNetwork, "Name of the network")
	registerCmd.Flags().StringVarP(&functionNamespace, "namespace", "n", "", "Namespace of the function")

	// Setup flags that are used only by this command (variables defined above)
	registerCmd.Flags().StringArrayVarP(&registerFlags.envvarOpts, "env", "e", []string{}, "Set one or more environment variables (ENVVAR=VALUE)")

	registerCmd.Flags().StringArrayVarP(&registerFlags.labelOpts, "label", "l", []string{}, "Set one or more label (LABEL=VALUE)")

	registerCmd.Flags().StringArrayVar(&registerFlags.constraints, "constraint", []string{}, "Apply a constraint to the function")
	registerCmd.Flags().StringArrayVar(&registerFlags.secrets, "secret", []string{}, "Give the function access to a secure secret")

	registerCmd.Flags().Var(&tagFormat, "tag", "Override latest tag on function Docker image, accepts 'latest', 'sha', 'branch', or 'describe'")

	registerCmd.Flags().BoolVar(&tlsInsecure, "tls-no-verify", false, "Disable TLS validation")
	registerCmd.Flags().BoolVar(&envsubst, "envsubst", true, "Substitute environment variables in stack.yml file")
	registerCmd.Flags().StringVarP(&token, "token", "k", "", "Pass a JWT token to use instead of basic auth")
	// Set bash-completion.
	_ = registerCmd.Flags().SetAnnotation("handler", cobra.BashCompSubdirsInDir, []string{})
	registerCmd.Flags().BoolVar(&readTemplate, "read-template", true, "Read the function's template")

	registerCmd.Flags().DurationVar(&timeoutOverride, "timeout", commandTimeout, "Timeout for any HTTP calls made to the OpenFaaS API.")

	faasCmd.AddCommand(registerCmd)
}

// registerCmd handles deploying OpenFaaS function containers
var registerCmd = &cobra.Command{
	Use: `register -f YAML_FILE [--replace=false]
  faas-cli register --image IMAGE_NAME
                  --name FUNCTION_NAME
                  [--lang <ruby|python|node|csharp>]
                  [--gateway GATEWAY_URL]
                  [--network NETWORK_NAME]
                  [--handler HANDLER_DIR]
                  [--fprocess PROCESS]
                  [--env ENVVAR=VALUE ...]
				  [--label LABEL=VALUE ...]
                  [--constraint PLACEMENT_CONSTRAINT ...]
                  [--regex "REGEX"]
                  [--filter "WILDCARD"]
				  [--secret "SECRET_NAME"]
				  [--tag <sha|branch|describe>]
				  [--readonly=false]
				  [--tls-no-verify]`,

	Short: "Register OpenFaaS functions",
	Long: `Register OpenFaaS function containers either via the supplied YAML config using
the "--yaml" flag (which may contain multiple function definitions), or directly
via flags.`,
	Example: `  faas-cli deploy -f https://domain/path/myfunctions.yml
  faas-cli register -f ./stack.yml
  faas-cli register -f ./stack.yml --label canary=true
  faas-cli register -f ./stack.yml --filter "*gif*" --secret dockerhuborg
  faas-cli register -f ./stack.yml --regex "fn[0-9]_.*"
  faas-cli register -f ./stack.yml --tag sha
  faas-cli register -f ./stack.yml --tag branch
  faas-cli register -f ./stack.yml --tag describe
  faas-cli register --image=alexellis/faas-url-ping --name=url-ping
  faas-cli register --image=my_image --name=my_fn --handler=/path/to/fn/
                  --gateway=http://remote-site.com:8080 --lang=python
                  --env=MYVAR=myval`,
	PreRunE: preRunRegister,
	RunE:    runRegister,
}

// preRunDeploy validates args & flags
func preRunRegister(cmd *cobra.Command, args []string) error {
	language, _ = validateLanguageFlag(language)

	return nil
}

func runRegister(cmd *cobra.Command, args []string) error {
	return runRegisterCommand(args, image, fprocess, functionName, registerFlags, tagFormat)
}

func runRegisterCommand(args []string, image string, fprocess string, functionName string, registerFlags RegisterFlags, tagMode schema.BuildFormat) error {
	var services stack.Services
	if len(yamlFile) > 0 {
		parsedServices, err := stack.ParseYAMLFile(yamlFile, regex, filter, envsubst)
		if err != nil {
			return err
		}

		if parsedServices != nil {
			parsedServices.Provider.GatewayURL = getGatewayURL(gateway, defaultGateway, parsedServices.Provider.GatewayURL, os.Getenv(openFaaSURLEnvironment))
			services = *parsedServices
		}
	}

	transport := GetDefaultCLITransport(tlsInsecure, &timeoutOverride)
	ctx := context.Background()

	var failedErrors = make(map[string]error)
	if len(services.Functions) > 0 {

		cliAuth, err := proxy.NewCLIAuth(token, services.Provider.GatewayURL)
		if err != nil {
			return err
		}

		proxyClient, err := proxy.NewClient(cliAuth, services.Provider.GatewayURL, transport, &timeoutOverride)
		if err != nil {
			return err
		}

		for k, function := range services.Functions {

			functionSecrets := registerFlags.secrets

			function.Name = k
			fmt.Printf("Registering: %s.\n", function.Name)

			var functionConstraints []string
			if function.Constraints != nil {
				functionConstraints = *function.Constraints
			} else if len(registerFlags.constraints) > 0 {
				functionConstraints = registerFlags.constraints
			}

			if len(function.Secrets) > 0 {
				functionSecrets = util.MergeSlice(function.Secrets, functionSecrets)
			}

			// Check if there is a functionNamespace flag passed, if so, override the namespace value
			// defined in the stack.yaml
			function.Namespace = getNamespace(functionNamespace, function.Namespace)

			fileEnvironment, err := readFiles(function.EnvironmentFile)
			if err != nil {
				return err
			}

			labelMap := map[string]string{}
			if function.Labels != nil {
				labelMap = *function.Labels
			}

			labelArgumentMap, labelErr := util.ParseMap(registerFlags.labelOpts, "label")
			if labelErr != nil {
				return fmt.Errorf("error parsing labels: %v", labelErr)
			}

			allLabels := util.MergeMap(labelMap, labelArgumentMap)

			allEnvironment, envErr := compileEnvironment(registerFlags.envvarOpts, function.Environment, fileEnvironment)
			if envErr != nil {
				return envErr
			}

			if readTemplate {
				// Get FProcess to use from the ./template/template.yml, if a template is being used
				if languageExistsNotDockerfile(function.Language) {
					var fprocessErr error

					function.FProcess, fprocessErr = deriveFprocess(function)
					if fprocessErr != nil {
						return fmt.Errorf(`template directory may be missing or invalid, please run "faas-cli template pull"
Error: %s`, fprocessErr.Error())
					}
				}
			}

			functionResourceRequest := proxy.FunctionResourceRequest{
				Limits:   function.Limits,
				Requests: function.Requests,
			}

			var annotations map[string]string
			if function.Annotations != nil {
				annotations = *function.Annotations
			}

			branch, sha, err := builder.GetImageTagValues(tagMode, function.Handler)
			if err != nil {
				return err
			}

			function.Image = schema.BuildImageName(tagMode, function.Image, sha, branch)

			deploySpec := &proxy.DeployFunctionSpec{
				FProcess:                function.FProcess,
				FunctionName:            function.Name,
				Image:                   function.Image,
				Language:                function.Language,
				Replace:                 false,
				EnvVars:                 allEnvironment,
				Constraints:             functionConstraints,
				Secrets:                 functionSecrets,
				Labels:                  allLabels,
				Annotations:             annotations,
				FunctionResourceRequest: functionResourceRequest,
				ReadOnlyRootFilesystem:  false,
				TLSInsecure:             tlsInsecure,
				Token:                   token,
				Namespace:               function.Namespace,
			}

			if msg := checkTLSInsecure(services.Provider.GatewayURL, deploySpec.TLSInsecure); len(msg) > 0 {
				fmt.Println(msg)
			}
			if err = proxyClient.RegisterFunction(ctx, deploySpec); err != nil {
				failedErrors[k] = err
			}
		}
	} else {
		if len(image) == 0 || len(functionName) == 0 {
			return fmt.Errorf("to register a function give --yaml/-f or a --image and --name flag")
		}
		gateway = getGatewayURL(gateway, defaultGateway, "", os.Getenv(openFaaSURLEnvironment))
		cliAuth, err := proxy.NewCLIAuth(token, gateway)
		if err != nil {
			return err
		}
		proxyClient, err := proxy.NewClient(cliAuth, gateway, transport, &commandTimeout)
		if err != nil {
			return err
		}

		// default to a readable filesystem until we get more input about the expected behavior
		// and if we want to add another flag for this case
		defaultReadOnlyRFS := false
		err = registerImage(ctx, proxyClient, image, fprocess, functionName, "", registerFlags,
			tlsInsecure, defaultReadOnlyRFS, token, functionNamespace)
		if err != nil {
			failedErrors[functionName] = err
		}
	}

	if len(failedErrors) == 0 {
		return nil
	}
	var allErrors []string
	for funcName, err := range failedErrors {
		errMsg := fmt.Sprintf("function '%s' failed to register: %s", funcName, err)
		allErrors = append(allErrors, errMsg)
	}
	return fmt.Errorf(strings.Join(allErrors, "\n"))
}

// registerImage register a function with the given image
func registerImage(
	ctx context.Context,
	client *proxy.Client,
	image string,
	fprocess string,
	functionName string,
	registryAuth string,
	registerFlags RegisterFlags,
	tlsInsecure bool,
	readOnlyRootFilesystem bool,
	token string,
	namespace string,
) error {

	readOnlyRFS := readOnlyRootFilesystem
	envvars, err := util.ParseMap(registerFlags.envvarOpts, "env")
	if err != nil {
		return fmt.Errorf("error parsing envvars: %v", err)
	}

	labelMap, labelErr := util.ParseMap(registerFlags.labelOpts, "label")

	if labelErr != nil {
		return fmt.Errorf("error parsing labels: %v", labelErr)
	}

	deploySpec := &proxy.DeployFunctionSpec{
		FProcess:                fprocess,
		FunctionName:            functionName,
		Image:                   image,
		Language:                language,
		EnvVars:                 envvars,
		Network:                 network,
		Constraints:             registerFlags.constraints,
		Secrets:                 registerFlags.secrets,
		Labels:                  labelMap,
		Annotations:             map[string]string{},
		FunctionResourceRequest: proxy.FunctionResourceRequest{},
		ReadOnlyRootFilesystem:  readOnlyRFS,
		TLSInsecure:             tlsInsecure,
		Token:                   token,
		Namespace:               namespace,
	}

	if msg := checkTLSInsecure(gateway, deploySpec.TLSInsecure); len(msg) > 0 {
		fmt.Println(msg)
	}

	return client.RegisterFunction(ctx, deploySpec)
}
