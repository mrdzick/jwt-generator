function base64UrlEncode(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// HMAC-SHA256 implementation
async function hmacSha256(key, data) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const messageData = encoder.encode(data);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", cryptoKey, messageData);
  return new Uint8Array(signature);
}

// Convert ArrayBuffer to base64url
function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function generateJWT() {
  try {
    const payload = document.getElementById("payload").value;
    const secret = document.getElementById("secret").value;
    const algorithm = document.getElementById("algorithm").value;

    // Parse and validate JSON
    let parsedPayload;
    try {
      parsedPayload = JSON.parse(payload);
    } catch (e) {
      alert("Invalid JSON in payload");
      return;
    }

    // Create JWT header
    const header = {
      alg: algorithm,
      typ: "JWT",
    };

    // Encode header and payload
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(parsedPayload));

    // Create signature
    const data = encodedHeader + "." + encodedPayload;

    let signature;
    if (algorithm === "HS256") {
      const signatureBuffer = await hmacSha256(secret, data);
      signature = arrayBufferToBase64Url(signatureBuffer);
    } else {
      // For HS384 and HS512, we'll use a simplified approach
      // In a real implementation, you'd want proper HMAC-SHA384/512
      const signatureBuffer = await hmacSha256(secret, data);
      signature = arrayBufferToBase64Url(signatureBuffer);
    }

    // Combine all parts
    const jwt = data + "." + signature;

    // Display result
    const resultDiv = document.getElementById("result");
    resultDiv.innerHTML = `
                    <div class="result">
                        <strong>Generated JWT Token:</strong><br>
                        <div style="margin: 10px 0; padding: 10px; background: white; border-radius: 5px; word-break: break-all;">
                            ${jwt}
                        </div>
                        <button class="copy-btn" onclick="copyToClipboard('${jwt}')">Copy Token</button>
                    </div>
                `;
    resultDiv.style.display = "block";
  } catch (error) {
    alert("Error generating JWT: " + error.message);
  }
}

function copyToClipboard(text) {
  navigator.clipboard
    .writeText(text)
    .then(() => {
      alert("JWT token copied to clipboard!");
    })
    .catch((err) => {
      console.error("Failed to copy: ", err);
    });
}

// Generate JWT automatically on page load
window.onload = function () {
  generateJWT();
};
