package openstack

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/pagination"
)

type Provider struct{}

func (p *Provider) Help() string {
	return `OpenStack:

    provider:       "openstack"
    auth_url:       The OpenStack identity endpoint URL.
    cacert:         CA certificate file to use for validation.
    cert:           Client certificate file.
    key:            Private key file for the client certificate.
    user_id:        The OpenStack user ID.
    user_name:      The OpenStack username.
    password:       The Openstack password.
    tenant_id:      The OpenStack tenant ID.
    tenant_name:    The OpenStack tenant name.
    domain_id:      The OpenStack tenant ID.
    domain_name:    The OpenStack tenant name.
    token:          The Openstack authentication token.
    region:         The OpenStack region.
    metadata_key:   The instance metadata key to filter on
    metadata_value: The instance metadata value to filter on
    networks:       The network names to use (comma-separated)
    address_type:   "fixed" (default) or "floating"
`
}

func (p *Provider) Addrs(args map[string]string, l *log.Logger) ([]string, error) {
	if args["provider"] != "openstack" {
		return nil, fmt.Errorf("discover-openstack: invalid provider " + args["provider"])
	}

	if l == nil {
		l = log.New(ioutil.Discard, "", 0)
	}

	var networks []string = nil
	if args["networks"] != "" {
		networks = strings.Split(args["networks"], ",")
	}

	metadata_key := args["metadata_key"]
	metadata_value := args["metadata_value"]

	address_type := args["address_type"]
	if address_type == "" {
		address_type = "fixed"
	}

	auth_opts := gophercloud.AuthOptions{
		IdentityEndpoint: args["auth_url"],
		UserID:           args["user_id"],
		Username:         args["user_name"],
		Password:         args["password"],
		TenantID:         args["tenant_id"],
		TenantName:       args["tenant_name"],
		DomainID:         args["domain_id"],
		DomainName:       args["domain_name"],
		TokenID:          args["token"],
	}

	provider, err := openstack.AuthenticatedClient(auth_opts)
	if err != nil {
		return nil, fmt.Errorf("discover-openstack: Failed to authenticate: %s", err)
	}

	client, err := openstack.NewComputeV2(provider, gophercloud.EndpointOpts{
		Region: args["region"],
	})
	if err != nil {
		return nil, fmt.Errorf("discover-openstack: Failed to create Compute client: %s", err)
	}
	client.UserAgent.Prepend("go-discover")

	addrs := []string{}
	err = servers.List(client, nil).EachPage(func(page pagination.Page) (bool, error) {
		svrs, err := servers.ExtractServers(page)
		if err != nil {
			return false, err
		}

		for _, svr := range svrs {
			if metadata_key != "" && svr.Metadata != nil && svr.Metadata[metadata_key] != metadata_value {
				continue
			}

			if port := getPort(svr, networks); port != nil {
				if addr := getAddr(port, address_type); addr != "" {
					addrs = append(addrs, addr)
				}
			}
		}

		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover-openstack: %s", err)
	}

	return addrs, nil
}

func tlsConfig(cacertFile string, certFile stirng, keyFile string) (*tls.Config, error) {
	config := &tls.Config{}

	if cacertFile != "" {
		pem, err := ioutil.ReadFile(cacertFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to load CA certificates: %s", err)
		}

		pool := x509.NewCertPool()
		pool.AddCertFromPEM(pem)
		config.RootCAs = pool
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to load client certificate: %s", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	return
}

func getPort(server servers.Server, networks []string) []interface{} {
	for net, port := range server.Addresses {
		port, ok := port.([]interface{})
		if !ok {
			continue
		}

		if networks == nil {
			return port
		}

		for _, expected_net := range networks {
			if net == expected_net {
				return port
			}
		}
	}

	return nil
}

func getAddr(port []interface{}, address_type string) string {
	for _, addr := range port {
		attrs, ok := addr.(map[string]interface{})
		if !ok {
			continue
		}

		if attrs["OS-EXT-IPS:type"] == address_type {
			return attrs["addr"].(string)
		}
	}
	return ""
}
