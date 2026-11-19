// Дополнительные пассивные источники кандидатов origin за Cloudflare:
//   - favicon-hash: mmh3-хэш фавикона + поиск в Shodan (http.favicon.hash);
//   - Censys: поиск хостов, связанных с доменом;
//   - SPF/MX: IP из SPF-записи и адреса MX — часто это та же инфраструктура вне CF.
// Всё это легитимная OSINT-разведка: находит то, что организация сама выставила.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// faviconHashOrigins считает Shodan-хэш фавикона цели и ищет хосты с таким же
// фавиконом — среди них часто реальный origin за Cloudflare.
func faviconHashOrigins(ctx context.Context, shodanKey, domain string) []string {
	fav := fetchBytes(ctx, "https://"+domain+"/favicon.ico")
	if len(fav) == 0 {
		return nil
	}
	hash := mmh3_32(b64mime(fav))
	q := url.Values{}
	q.Set("key", shodanKey)
	q.Set("query", fmt.Sprintf("http.favicon.hash:%d", hash))
	u := "https://api.shodan.io/shodan/host/search?" + q.Encode()
	var body struct {
		Matches []struct {
			IPStr string `json:"ip_str"`
		} `json:"matches"`
	}
	if !getJSON(ctx, u, nil, &body) {
		return nil
	}
	var out []string
	for _, m := range body.Matches {
		if m.IPStr != "" {
			out = append(out, m.IPStr)
		}
	}
	return out
}

// censysOrigins ищет хосты, связанные с доменом, через Censys (API v2, ключ id:secret).
func censysOrigins(ctx context.Context, key, domain string) []string {
	id, secret, ok := strings.Cut(key, ":")
	if !ok || id == "" || secret == "" {
		return nil
	}
	q := url.Values{}
	q.Set("q", domain)
	q.Set("per_page", "50")
	u := "https://search.censys.io/api/v2/hosts/search?" + q.Encode()
	auth := base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
	var body struct {
		Result struct {
			Hits []struct {
				IP string `json:"ip"`
			} `json:"hits"`
		} `json:"result"`
	}
	if !getJSON(ctx, u, map[string]string{"Authorization": "Basic " + auth}, &body) {
		return nil
	}
	var out []string
	for _, h := range body.Result.Hits {
		if h.IP != "" {
			out = append(out, h.IP)
		}
	}
	return out
}

// spfMXOrigins достаёт IP из SPF-записи (ip4:) и адреса MX-хостов домена.
func spfMXOrigins(ctx context.Context, domain string) []string {
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var out []string
	if txts, err := resolver.LookupTXT(cctx, domain); err == nil {
		for _, t := range txts {
			if !strings.HasPrefix(t, "v=spf1") {
				continue
			}
			for _, f := range strings.Fields(t) {
				if v, ok := strings.CutPrefix(f, "ip4:"); ok && !strings.Contains(v, "/") {
					out = append(out, v) // одиночный IP; CIDR-диапазоны пропускаем (слишком широко)
				}
			}
		}
	}
	if mxs, err := resolver.LookupMX(cctx, domain); err == nil {
		for _, mx := range mxs {
			out = append(out, resolve(ctx, strings.TrimSuffix(mx.Host, "."))...)
		}
	}
	return out
}

func fetchBytes(ctx context.Context, u string) []byte {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "pentkit-recon")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return b
}

// b64mime кодирует как Python base64.encodebytes (строки по 76 символов + \n),
// именно так Shodan считает фавикон-хэш.
func b64mime(data []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(data)
	var b bytes.Buffer
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// mmh3_32 — MurmurHash3 x86_32 (seed 0), результат как signed int32 (формат Shodan).
func mmh3_32(data []byte) int32 {
	const c1 = 0xcc9e2d51
	const c2 = 0x1b873593
	var h uint32
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := binary.LittleEndian.Uint32(data[i*4:])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[n*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}
