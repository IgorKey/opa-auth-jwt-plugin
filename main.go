package main

import (
	"fmt"
	"github.com/open-policy-agent/opa-envoy-plugin/plugin"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/runtime"
	"opa-auth-plugin/auth"
	"os"
)

func main() {
	runtime.RegisterPlugin("envoy_ext_authz_grpc", plugin.Factory{})
	runtime.RegisterPlugin(auth.PluginName, &auth.PluginFactory{})

	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
