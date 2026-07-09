const textArea = document.getElementById('plainText');
const encryptPasswordInput = document.getElementById('encryptPassword');
const encryptBtn = document.getElementById('encryptBtn');
const encryptResult = document.getElementById('encryptResult');
const fileInput = document.getElementById('fileInput');

const cipherTextInput = document.getElementById('cipherText');
const ivInput = document.getElementById('ivInput');
const saltInput = document.getElementById('saltInput');
const decryptPasswordInput = document.getElementById('decryptPassword');
const decryptBtn = document.getElementById('decryptBtn');
const decryptResult = document.getElementById('decryptResult');

function showStatus(element, message, isError = false) {
  element.style.color = isError ? '#ff8ba0' : '#9ee7d2';
  element.textContent = message;
}

async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 250000,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function base64Encode(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64Decode(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

encryptBtn.addEventListener('click', async () => {
  const text = textArea.value.trim();
  const password = encryptPasswordInput.value;

  if (!text || !password) {
    showStatus(encryptResult, 'Completa el contenido y la contraseña para cifrar.', true);
    return;
  }

  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt);
    const encoded = new TextEncoder().encode(text);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

    const payload = {
      ciphertext: base64Encode(encrypted),
      iv: base64Encode(iv),
      salt: base64Encode(salt),
    };

    cipherTextInput.value = payload.ciphertext;
    ivInput.value = payload.iv;
    saltInput.value = payload.salt;

    showStatus(
      encryptResult,
      `Documento cifrado correctamente.\n\nIV: ${payload.iv}\n\nSalt: ${payload.salt}`
    );
  } catch (error) {
    showStatus(encryptResult, 'No se pudo cifrar el documento.', true);
    console.error(error);
  }
});

decryptBtn.addEventListener('click', async () => {
  const ciphertext = cipherTextInput.value.trim();
  const iv = ivInput.value.trim();
  const salt = saltInput.value.trim();
  const password = decryptPasswordInput.value;

  if (!ciphertext || !iv || !salt || !password) {
    showStatus(decryptResult, 'Completa todos los campos para descifrar.', true);
    return;
  }

  try {
    const payloadIv = base64Decode(iv);
    const payloadCiphertext = base64Decode(ciphertext);
    const parsedSalt = base64Decode(salt);
    const key = await deriveKey(password, parsedSalt);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: payloadIv }, key, payloadCiphertext);
    const plain = new TextDecoder().decode(decrypted);

    showStatus(decryptResult, `Documento descifrado:\n\n${plain}`);
  } catch (error) {
    showStatus(decryptResult, 'No se pudo descifrar el documento. Verifica la contraseña o los datos.', true);
    console.error(error);
  }
});

fileInput.addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;

  if (!file.type.includes('text') && file.name.split('.').pop()?.toLowerCase() !== 'txt') {
    showStatus(encryptResult, 'Solo se aceptan archivos de texto plano.', true);
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    textArea.value = reader.result;
    showStatus(encryptResult, `Archivo cargado: ${file.name}`);
  };
  reader.readAsText(file);
});
