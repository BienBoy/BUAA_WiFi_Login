package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"math"
)

// InfoParams info参数结构
type InfoParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IP       string `json:"ip"`
	AcID     string `json:"acid"`
	EncVer   string `json:"enc_ver"`
}

// BuildInfo 构造info参数（简化版本）
func BuildInfo(username, password, ip, acID, encVer string) (string, error) {
	params := InfoParams{
		Username: username,
		Password: password,
		IP:       ip,
		AcID:     acID,
		EncVer:   encVer,
	}

	jsonBytes, err := json.Marshal(params)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// GetPasswordMD5Raw 获取原始MD5值（不带{MD5}前缀）
func GetPasswordMD5Raw(password, token string) string {
	h := hmac.New(md5.New, []byte(token))
	h.Write([]byte(password))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// BuildInfoEncoded 构造加密的info参数
func BuildInfoEncoded(infoJSON, token string, alphabet *string) string {
	encoded := XEncode(infoJSON, token)
	base64Str := CustomBase64Encode(encoded, alphabet)
	return "{SRBX1}" + base64Str
}

// BuildChecksum 构造chksum参数
func BuildChecksum(token, username, passwordMD5, acID, ip, n, typ, infoEncoded string) string {
	// chkstr = token+username+token+md5pwd+token+ac_id+token+ip+token+n+token+type+token+info
	chkstr := token + username +
		token + passwordMD5 +
		token + acID +
		token + ip +
		token + n +
		token + typ +
		token + infoEncoded

	h := sha1.New()
	h.Write([]byte(chkstr))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// XEncode xencode加密算法
func XEncode(msg, key string) string {
	if msg == "" {
		return ""
	}

	pwd := sEncode(msg, true)
	pwdk := sEncode(key, false)

	// 确保pwdk至少有4个元素
	for len(pwdk) < 4 {
		pwdk = append(pwdk, 0)
	}

	n := len(pwd) - 1
	z := pwd[n]
	y := pwd[0]
	c := uint32(0x86014019 | 0x183639A0)
	m := uint32(0)
	e := uint32(0)
	p := 0
	q := int(math.Floor(6 + 52/float64(n+1)))
	d := uint32(0)

	for q > 0 {
		d = (d + c) & (0x8CE0D9BF | 0x731F2640)
		e = (d >> 2) & 3

		for p = 0; p < n; p++ {
			y = pwd[p+1]
			m = (z>>5 ^ y<<2) + ((y>>3 ^ z<<4) ^ (d ^ y)) + (pwdk[(p&3)^int(e)] ^ z)
			pwd[p] = (pwd[p] + m) & (0xEFB8D130 | 0x10472ECF)
			z = pwd[p]
		}

		y = pwd[0]
		m = (z>>5 ^ y<<2) + ((y>>3 ^ z<<4) ^ (d ^ y)) + (pwdk[(p&3)^int(e)] ^ z)
		pwd[n] = (pwd[n] + m) & (0xBB390742 | 0x44C6F8BD)
		z = pwd[n]

		q--
	}

	return lEncode(pwd, false)
}

func sEncode(msg string, key bool) []uint32 {
	l := len(msg)
	pwd := []uint32{}

	for i := 0; i < l; i += 4 {
		pwd = append(pwd,
			uint32(ordat(msg, i))|
				uint32(ordat(msg, i+1))<<8|
				uint32(ordat(msg, i+2))<<16|
				uint32(ordat(msg, i+3))<<24)
	}

	if key {
		pwd = append(pwd, uint32(l))
	}

	return pwd
}

func lEncode(msg []uint32, key bool) string {
	l := len(msg)
	ll := (l - 1) << 2

	if key {
		m := msg[l-1]
		if m < uint32(ll-3) || m > uint32(ll) {
			return ""
		}
		ll = int(m)
	}

	result := make([]byte, 0, l*4)
	for i := 0; i < l; i++ {
		result = append(result,
			byte(msg[i]&0xFF),
			byte((msg[i]>>8)&0xFF),
			byte((msg[i]>>16)&0xFF),
			byte((msg[i]>>24)&0xFF))
	}

	if key {
		return string(result[:ll])
	}
	return string(result)
}

func ordat(msg string, idx int) int {
	if len(msg) > idx {
		return int(msg[idx])
	}
	return 0
}

// CustomBase64Encode 自定义Base64编码
func CustomBase64Encode(s string, alphabet *string) string {
	alpha := "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
	if alphabet != nil && len(*alphabet) == 64 {
		alpha = *alphabet
	}

	padChar := "="
	result := []byte{}
	length := len(s)
	imax := length - length%3

	if length == 0 {
		return s
	}

	for i := 0; i < imax; i += 3 {
		b10 := (int(s[i]) << 16) | (int(s[i+1]) << 8) | int(s[i+2])
		result = append(result,
			alpha[b10>>18],
			alpha[(b10>>12)&63],
			alpha[(b10>>6)&63],
			alpha[b10&63])
	}

	switch length - imax {
	case 1:
		b10 := int(s[imax]) << 16
		result = append(result,
			alpha[b10>>18],
			alpha[(b10>>12)&63])
		result = append(result, padChar[0], padChar[0])
	case 2:
		b10 := (int(s[imax]) << 16) | (int(s[imax+1]) << 8)
		result = append(result,
			alpha[b10>>18],
			alpha[(b10>>12)&63],
			alpha[(b10>>6)&63])
		result = append(result, padChar[0])
	}

	return string(result)
}
