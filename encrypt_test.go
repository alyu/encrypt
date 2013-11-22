package encrypt

import "testing"

var (
	g_secretKey = []byte("gcZI9-ak_hIw^QI*uVPyXWpW&0fWRNp-")
	g_encrypted []byte
)

const (
	TEXT_TO_ENCRYPT = `
Two roads diverged in a yellow wood,
And sorry I could not travel both
And be one traveler, long I stood
And looked down one as far as I could
To where it bent in the undergrowth; 

Then took the other, as just as fair,
And having perhaps the better claim
Because it was grassy and wanted wear,
Though as for that the passing there
Had worn them really about the same,

And both that morning equally lay
In leaves no step had trodden black.
Oh, I kept the first for another day! 
Yet knowing how way leads on to way
I doubted if I should ever come back.

I shall be telling this with a sigh
Somewhere ages and ages hence:
Two roads diverged in a wood, and I,
I took the one less traveled by,
And that has made all the difference.
`
)

func TestEncrypt(t *testing.T) {
	g_encrypted = Encrypt(g_secretKey, []byte(TEXT_TO_ENCRYPT))
	t.Log(EncodeBase64(g_encrypted))
	t.Log("sha1:", Sha1([]byte(TEXT_TO_ENCRYPT)))
}

func TestDecrypt(t *testing.T) {
	decrypt := Decrypt(g_secretKey, g_encrypted)
	t.Log(decrypt)
	sha1 := Sha1([]byte(decrypt))
	sha2 := Sha1([]byte(TEXT_TO_ENCRYPT))
	t.Log("sha1:", sha1)
	if sha1 != sha2 {
		t.Error("Sha1 sum does not match!")
	}
}
