// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"strconv"
	"strings"

	"github.com/gopacket/gopacket/layers"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

func decodeDNS(flowType accesslog.FlowType, dns *accesslog.LogRecordDNS) *flowpb.Layer7_Dns {
	var qtypes []string
	if len(dns.QTypes) > 0 {
		qtypes = make([]string, len(dns.QTypes))
		for i, qtype := range dns.QTypes {
			qtypes[i] = layers.DNSType(qtype).String()
		}
	}
	if flowType == accesslog.TypeRequest {
		// Set only fields that are relevant for requests.
		return &flowpb.Layer7_Dns{
			Dns: &flowpb.DNS{
				Query:             dns.Query,
				ObservationSource: string(dns.ObservationSource),
				Qtypes:            qtypes,
			},
		}
	}
	var ips []string
	if len(dns.IPs) == 1 {
		ips = []string{dns.IPs[0].String()}
	} else if len(dns.IPs) > 1 {
		ips = make([]string, len(dns.IPs))
		var sb strings.Builder
		sb.Grow(len(dns.IPs) * 16)
		var buf [40]byte
		offsets := make([]int, len(dns.IPs)+1)
		for i, ip := range dns.IPs {
			b := ip.AppendTo(buf[:0])
			sb.Write(b)
			offsets[i+1] = sb.Len()
		}
		all := sb.String()
		for i := range dns.IPs {
			ips[i] = all[offsets[i]:offsets[i+1]]
		}
	}
	var rtypes []string
	if len(dns.AnswerTypes) > 0 {
		rtypes = make([]string, len(dns.AnswerTypes))
		for i, rtype := range dns.AnswerTypes {
			rtypes[i] = layers.DNSType(rtype).String()
		}
	}
	return &flowpb.Layer7_Dns{
		Dns: &flowpb.DNS{
			Query:             dns.Query,
			Ips:               ips,
			Ttl:               dns.TTL,
			Cnames:            dns.CNAMEs,
			ObservationSource: string(dns.ObservationSource),
			Rcode:             uint32(dns.RCode),
			Qtypes:            qtypes,
			Rrtypes:           rtypes,
		},
	}
}

func dnsSummary(flowType accesslog.FlowType, dns *accesslog.LogRecordDNS) string {
	switch flowType {
	case accesslog.TypeRequest:
		var sb strings.Builder
		sb.Grow(12 + len(dns.Query) + len(dns.QTypes)*5)
		sb.WriteString("DNS Query ")
		sb.WriteString(dns.Query)
		sb.WriteByte(' ')
		for i, t := range dns.QTypes {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(layers.DNSType(t).String())
		}
		return sb.String()
	case accesslog.TypeResponse:
		var sb strings.Builder
		sb.Grow(40 + len(dns.Query) + len(dns.IPs)*16 + len(dns.CNAMEs)*24)
		sb.WriteString("DNS Answer ")
		rcode := layers.DNSResponseCode(dns.RCode)
		if rcode != layers.DNSResponseCodeNoErr {
			sb.WriteString("RCode: ")
			sb.WriteString(rcode.String())
		} else {
			wrote := false
			if len(dns.IPs) > 0 {
				var ipBuf strings.Builder
				ipBuf.Grow(len(dns.IPs) * 16)
				var b40 [40]byte
				for i, ip := range dns.IPs {
					if i > 0 {
						ipBuf.WriteByte(',')
					}
					ipBuf.Write(ip.AppendTo(b40[:0]))
				}
				var qBuf [64]byte
				sb.Write(strconv.AppendQuote(qBuf[:0], ipBuf.String()))
				wrote = true
			}
			if len(dns.CNAMEs) > 0 {
				if wrote {
					sb.WriteByte(' ')
				}
				sb.WriteString("CNAMEs: ")
				var qBuf [64]byte
				sb.Write(strconv.AppendQuote(qBuf[:0], strings.Join(dns.CNAMEs, ",")))
			}
		}
		sb.WriteString(" TTL: ")
		var ttlBuf [16]byte
		sb.Write(strconv.AppendUint(ttlBuf[:0], uint64(dns.TTL), 10))
		sb.WriteString(" (")
		if dns.ObservationSource == accesslog.DNSSourceProxy {
			sb.WriteString("Proxy ")
		} else {
			sb.WriteString("Query ")
		}
		sb.WriteString(dns.Query)
		sb.WriteByte(' ')
		for i, t := range dns.QTypes {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(layers.DNSType(t).String())
		}
		sb.WriteByte(')')
		return sb.String()
	}

	return ""
}
