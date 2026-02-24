import requests
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad


def decrypt_content(content: str) -> str:
  content = content.strip()
  try:
    # Check if content is already valid M3U
    if (content.startswith("#EXTM3U") or
        content.startswith("#EXTINF") or
            content.startswith("#KODIPROP")):
      return content

    trimmed_content = content.strip()

    # Check length requirement
    if len(trimmed_content) < 79:
      return trimmed_content

    # Extract parts for decryption (String slicing logic remains the same)
    part1 = trimmed_content[0:10]
    part2 = trimmed_content[34:-54]
    part3 = trimmed_content[-10:]
    encrypted_data_str = part1 + part2 + part3

    iv_base64 = trimmed_content[10:34] + "="
    key_base64 = trimmed_content[-54:-10]

    # Decode from Base64
    iv = base64.b64decode(iv_base64)
    key = base64.b64decode(key_base64)
    encrypted_bytes = base64.b64decode(encrypted_data_str)

    # Decrypt using AES/CBC/PKCS5Padding
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_bytes)

    # Unpad and decode to string
    decrypted_data = unpad(decrypted_padded, AES.block_size)

    return decrypted_data.decode('utf-8')

  except Exception as e:
    log_error("crypto_utils", f"Content decryption failed: {e}")
    return content  # Return original content if decryption fails

url = "https://jiotv.byte-vault.workers.dev/"

querystring = { "token": "42e4f5-2d873b-3c37d8-7f3f50" }

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
    "accept": "*/*",
    "Cache-Control": "no-cache, no-store",
    "Host": "jiotv.byte-vault.workers.dev",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip"
}

content = requests.get(url, headers=headers, params=querystring).text
encrypted_base64 = decrypt_content(content)
print(encrypted_base64)
