package util

import (
	"fmt"
	"net/url"
	"strings"
)

const NS_DELIMITER = "-"
const DOMAIN_DELIMITER = "."

// NamespaceToDomain converts a kube namespace to an Athenz domain
func NamespaceToDomain(ns, pre, d, suf string) (domain string) {
	if d == "" {
		return pre + ns + suf
	}
	return pre + d + suf
}

// ServiceAccountToService converts a kube serviceaccount name to an Athenz service
func ServiceAccountToService(svc string) string {
	return svc
}

// ServiceSpiffeURI returns the SPIFFE URI for the specified Athenz domain and service.
func ServiceSpiffeURI(domain, service string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf("spiffe://%s/sa/%s", domain, service))
}

// RoleSpiffeURI returns the SPIFFE URI for the specified Athenz domain and service.
func RoleSpiffeURI(domain, role string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf("spiffe://%s/ra/%s", domain, role))
}

// RoleAthenzURI returns the Athenz URI for the specified Athenz domain and service.
func RoleAthenzURI(domain, service string) (*url.URL, error) {
	return url.Parse(fmt.Sprintf("athenz://principal/%s.%s", domain, service))
}

// DomainToDNSPart converts the Athenz domain into a DNS label
func DomainToDNSPart(domain string) (part string) {
	return strings.Replace(domain, ".", "-", -1)
}
