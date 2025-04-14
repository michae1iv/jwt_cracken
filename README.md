# 🔐 JWT-Cracken

A script for working with JWT tokens: decoding, encoding, and cracking simple secrets. It supports basic automatic brute-force checking of token vulnerability using a wordlist.

## 📆 Features

- 🔍 **Decode JWT** — View the token's header, payload, and signature.
- 🔐 **Encode JWT** — Create new tokens with specified payload, header, and secret.
- 🧠 **Crack JWT** — Brute-force the token's secret using a dictionary.

## 🚀 Usage

```bash
py jwt-crack.py [options]
```
or:
```bash
python3 jwt-crack.py [options]
```

### 🔹 Main Options:

| Flag              | Description                                                  |
| ----------------- | ------------------------------------------------------------ |
| `-d, --decode`    | Decode the token                                             |
| `-e, --encode`    | Encode a payload into a JWT                                  |
| `-c, --crack`     | Crack the token's secret                                     |
| `-p, --payload`   | Provide the payload (in JSON format)                         |
| `--header`        | Provide a custom header (optional)                           |
| `--token`         | The JWT token to analyze                                     |
| `-w, --wordlist`  | Path to wordlist (default: `jwt.secrets.list`)              |
| `-k, --key`       | Secret key for token generation                              |
| `-a, --algorithm` | Algorithm to use for signing (`HS256`, `HS512`, etc.)        |

### ⚠️ Note

- When you passes the token script automatically decodes it and saves payload and headers, after that you can create a new token only changing payload (--payload) or header (--header)
- The `payload` and `header` should be passed as JSON strings. Be sure to escape the quotes properly (in most cases put JSON string in quotes "").
- By default, the script uses the `jwt.secrets.list` file with commonly used weak secrets (Author of list: https://github.com/wallarm/jwt-secrets/tree/master), but you can change it with your own (-w /path/to/your/wordlist).
- When the token is cracked his secret stored in variable, so you can first crack (-c), then create new token at once (-e --payload)

## 📋 Example

Cracking a token, displaying its contents, and providing a new payload:

```powershell
py jwt-crack.py -d -c -e -p "{'sub': '1234567890', 'name': 'Admin', 'iat': 1516239022}" --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.AaFNTGz_5oj27Lvr3w6SrCb1rQ9_kxWIrXlSS_hwKzc
```
```bash
python3 jwt-crack.py -d -c -e -p "{'sub': '1234567890', 'name': 'Admin', 'iat': 1516239022}" --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.AaFNTGz_5oj27Lvr3w6SrCb1rQ9_kxWIrXlSS_hwKzc
```

## 📄 Wordlist

The script uses a default file `jwt.secrets.list` that contains commonly used weak passwords. You can replace it with your own by specifying the path via `-w`.

