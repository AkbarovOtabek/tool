// Package scope — страховка от выхода за границы разрешённого теста.
// Любой хост/IP перед сканированием проверяется через InScope. Это защищает
// и клиента, и тебя: нельзя случайно ударить по чужой инфраструктуре.
package scope

import (
	"net"
	"strings"

	"pentkit/internal/config"
)

// Scope — скомпилированные границы работы.
type Scope struct {
	domains    []string // корневые домены (совпадение по суффиксу)
	cidrs      []*net.IPNet
	outDomains []string
	outIPs     map[string]bool
}

// Compile готовит scope из конфига.
func Compile(c config.Scope) (*Scope, error) {
	s := &Scope{outIPs: map[string]bool{}}
	for _, d := range c.Domains {
		s.domains = append(s.domains, normalizeDomain(d))
	}
	for _, cidr := range c.CIDRs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, err
		}
		s.cidrs = append(s.cidrs, n)
	}
	for _, o := range c.OutOfScope {
		o = strings.TrimSpace(o)
		if ip := net.ParseIP(o); ip != nil {
			s.outIPs[ip.String()] = true
		} else {
			s.outDomains = append(s.outDomains, normalizeDomain(o))
		}
	}
	return s, nil
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	return strings.TrimSuffix(d, ".")
}

// InScope проверяет хост (домен или IP). Исключения (out_of_scope) имеют приоритет.
func (s *Scope) InScope(host string) bool {
	host = normalizeDomain(host)
	if host == "" {
		return false
	}
	// IP?
	if ip := net.ParseIP(host); ip != nil {
		if s.outIPs[ip.String()] {
			return false
		}
		for _, n := range s.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	// Домен.
	for _, od := range s.outDomains {
		if host == od || strings.HasSuffix(host, "."+od) {
			return false
		}
	}
	for _, d := range s.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Filter оставляет только хосты в скоупе.
func (s *Scope) Filter(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		if s.InScope(h) {
			out = append(out, h)
		}
	}
	return out
}

// Domains возвращает корневые домены скоупа (точки входа для recon).
func (s *Scope) Domains() []string { return s.domains }
