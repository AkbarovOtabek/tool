package ad

import (
	"strings"
	"testing"
)

func TestHashLineDetectsNTLMDump(t *testing.T) {
	ok := []string{
		"Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::",
		"svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::",
	}
	for _, l := range ok {
		if !hashLine(l) {
			t.Errorf("не распознана строка NTLM-дампа: %s", l)
		}
	}
	no := []string{
		"[*] Dumping Domain Credentials",
		"user:notahash:x:y:::",
		"just text",
	}
	for _, l := range no {
		if hashLine(l) {
			t.Errorf("ложно распознана строка: %s", l)
		}
	}
}

func TestRedactHashHidesNT(t *testing.T) {
	in := "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
	out := redactHash(in)
	if strings.Contains(out, "31d6cfe0d16ae931b73c59d7e0c089c0") {
		t.Error("NT-хэш не должен светиться целиком в доказательстве")
	}
	if !strings.HasPrefix(out, "Administrator:") {
		t.Error("имя пользователя должно оставаться видимым")
	}
	if !strings.Contains(out, "…") {
		t.Error("ожидалось сокращение хэша")
	}
}

func TestIsHex32(t *testing.T) {
	if !isHex32("31d6cfe0d16ae931b73c59d7e0c089c0") {
		t.Error("валидный 32-hex не распознан")
	}
	if isHex32("short") || isHex32("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") {
		t.Error("невалидные значения распознаны как hex32")
	}
}
