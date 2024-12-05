package main

import (
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
	"github.com/tochusc/godns/dns/xperi"
)

// 通过一个65KB的TXT记录来拉大解析器需验证的RDATA长度
var TXTSizeC = 65000

// 拥有的错误签名数量
// Unbound最多失败8次，然后放弃验证
var wSigNumC = 0

func getRandomString(size int) string {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetLen := len(charset)
	result := make([]byte, size)
	for i := range result {
		result[i] = charset[rand.Intn(charsetLen)]
	}
	return string(result)
}

type LRDATAResponser struct {
	ServerConf    godns.DNSServerConfig
	DNSSECManager godns.DNSSECManager
}

func (r *LRDATAResponser) Response(connInfo godns.ConnectionInfo) (dns.DNSMessage, error) {
	// 解析查询信息
	qry, err := godns.ParseQuery(connInfo)
	if err != nil {
		return dns.DNSMessage{}, err
	}

	// 初始化 回复信息
	resp := godns.InitNXDOMAIN(qry)

	qType := qry.Question[0].Type
	// 将可能启用0x20混淆的查询名称转换为小写
	qName := strings.ToLower(qry.Question[0].Name)

	switch qType {
	case dns.DNSRRTypeA:
		// 生成 A 记录
		rr := dns.DNSResourceRecord{
			Name:  qName,
			Type:  dns.DNSRRTypeA,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: 0,
			RData: &dns.DNSRDATAA{Address: r.ServerConf.IP},
		}
		resp.Answer = append(resp.Answer, rr)
	case dns.DNSRRTypeNS:
		// 生成 NS 记录
		rr := dns.DNSResourceRecord{
			Name:  qName,
			Type:  dns.DNSRRTypeNS,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: 0,
			RData: &dns.DNSRDATANS{NSDNAME: qName},
		}
		resp.Answer = append(resp.Answer, rr)
	case dns.DNSRRTypeTXT:
		rdata := dns.DNSRDATATXT{
			TXT: getRandomString(TXTSizeC),
		}

		// 生成 TXT 记录
		rr := dns.DNSResourceRecord{
			Name:  qName,
			Type:  dns.DNSRRTypeTXT,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: uint16(rdata.Size()),
			RData: &rdata,
		}
		resp.Answer = append(resp.Answer, rr)

		uName := dns.GetUpperDomainName(&qName)
		dMat := godns.GetDNSSECMaterial(r.DNSSECManager.DNSSECConf, r.DNSSECManager.DNSSECMap, uName)

		// 生成错误签名
		for i := 0; i < wSigNumC; i++ {
			wRR := xperi.GenerateRandomRRRRSIG(
				[]dns.DNSResourceRecord{rr},
				r.DNSSECManager.DNSSECConf.DAlgo,
				uint32(time.Now().UTC().Unix()+86400-3600),
				uint32(time.Now().UTC().Unix()-3600),
				uint16(dMat.ZSKTag),
				uName,
			)

			resp.Answer = append(resp.Answer, wRR)
		}

		// 正确签名
		sig := xperi.GenerateRRRRSIG(
			[]dns.DNSResourceRecord{rr},
			r.DNSSECManager.DNSSECConf.DAlgo,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dMat.ZSKTag),
			uName,
			dMat.PrivateZSK,
		)
		resp.Answer = append(resp.Answer, sig)
	}

	// 为回复信息添加 DNSSEC 记录
	if qType != dns.DNSRRTypeTXT {
		r.DNSSECManager.EnableDNSSEC(qry, &resp)
	}

	// 设置RCODE，修正计数字段，返回回复信息
	resp.Header.RCode = dns.DNSResponseCodeNoErr
	godns.FixCount(&resp)
	return resp, nil
}

func main() {
	sConf := godns.DNSServerConfig{
		IP:   net.IPv4(10, 10, 3, 3),
		Port: 53,
		MTU:  1500,
	}

	// 设置DNSSEC配置
	var dConf = godns.DNSSECConfig{
		DAlgo: dns.DNSSECAlgorithmECDSAP384SHA384,
		DType: dns.DNSSECDigestTypeSHA1,
	}

	// 生成 KSK 和 ZSK
	// 使用ParseKeyBase64解析预先生成的公钥，
	// 该公钥应确保能够被解析器通过 信任锚（Trust Anchor）建立的 信任链（Chain of Trust） 所验证。
	kBytes := xperi.ParseKeyBase64("MzJsFTtAo0j8qGpDIhEMnK4ImTyYwMwDPU5gt/FaXd6TOw6AvZDAj2hlhZvaxMXV6xCw1MU5iPv5ZQrb3NDLUU+TW07imJ5GD9YKi0Qiiypo+zhtL4aGaOG+870yHwuY")
	pkBytes := xperi.ParseKeyBase64("ppaXHmb7u1jOxEzrLzuGKzbjmSLIK4gEhQOvws+cpBQyJbCwIM1Nrk4j5k94CP9e")

	tAnchor := godns.InitTrustAnchor("test", dConf, kBytes, pkBytes)

	server := godns.GoDNSServer{
		ServerConfig: sConf,
		Netter: godns.Netter{
			Config: godns.NetterConfig{
				Port: sConf.Port,
				MTU:  sConf.MTU,
			},
		},
		Responer: &LRDATAResponser{
			ServerConf: sConf,
			DNSSECManager: godns.DNSSECManager{
				DNSSECConf: dConf,
				DNSSECMap:  tAnchor,
			},
		},
	}
	server.Start()
}
