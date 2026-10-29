//! Utilitários para localizar o campo `XML` em corpos de requisição.

/// Decodifica `application/x-www-form-urlencoded` (`+` vira espaço).
pub fn form_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&text[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 2;
                }
                Err(_) => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Valores do campo `name` num corpo form-urlencoded.
pub fn form_values(body: &str, name: &str) -> Vec<String> {
    body.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (form_decode(k) == name).then(|| form_decode(v))
        })
        .collect()
}
