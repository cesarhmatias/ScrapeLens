//! Codificador Python equivalente a `NaturalAjax::encode` (comprimentos em
//! unidades UTF-16, todos os prefixos recalculados).

/// Nome da função definida em [`PYTHON_ENCODER`].
pub const PYTHON_FUNCTION: &str = "natural_ajax_encode";

/// Nome da função de decodificação definida em [`PYTHON_ENCODER`]:
/// `natural_ajax_decode(texto)` devolve as mesmas partes `(nome, papel, valor)`
/// que o `decode` em Rust, sem offsets.
pub const PYTHON_DECODER: &str = "natural_ajax_decode";

/// Recebe a lista de partes `(nome, papel, valor)` em ordem, com papel
/// `'S'` (estrutura), `'N'` (nome), `'V'` (valor) ou `'D'` (delta).
pub const PYTHON_ENCODER: &str = r#"
def natural_jslen(value):
    return len(value.encode('utf-16-le', 'surrogatepass')) // 2


def natural_fit(number, width, what):
    text = str(number)
    if len(text) > width:
        fail('protocolo Natural: %s excede %d unidades UTF-16' % (what, 10 ** width - 1))
    return text.zfill(width)


def natural_ajax_encode(parts):
    out = []
    i = 0
    while i < len(parts):
        name, role, value = parts[i]
        if role == 'D':
            out.append('x' + natural_fit(natural_jslen(value), 2, 'delta') + value)
            i += 1
            continue
        if name != 'op' or role != 'S' or not value:
            fail('protocolo Natural: estrutura inválida (esperava uma operação)')
        op, rest = value[0], value[1:]
        if op in 'iv':
            head = parts[i + 1:i + 9]
            if len(head) != 8:
                fail('protocolo Natural: cabeçalho curto')
            fields = [p[2] for p in head]
            widths = (2, 2, 2, 2, 2, 3, 5, 1)
            out.append(op + ''.join(natural_fit(natural_jslen(f), w, 'campo do cabeçalho') for f, w in zip(fields, widths)) + ''.join(fields))
            i += 9
        elif op in 'pzqw':
            if i + 1 >= len(parts):
                fail('protocolo Natural: valor ausente')
            data = parts[i + 1][2]
            width = 10 if op in 'zw' else 5
            out.append(op + natural_fit(natural_jslen(rest), 2, 'nome') + natural_fit(natural_jslen(data), width, 'valor') + rest + data)
            i += 2
        elif op == 's':
            if i + 1 >= len(parts):
                fail('protocolo Natural: nome ausente')
            data = parts[i + 1][2]
            out.append('s' + natural_fit(natural_jslen(rest), 1, 'chave do dicionário') + natural_fit(natural_jslen(data), 2, 'nome do dicionário') + rest + data)
            i += 2
        elif op == 'b':
            out.append('b' + natural_fit(natural_jslen(rest), 2, 'escopo') + rest)
            i += 1
        elif op == 'k':
            out.append('k' + natural_fit(natural_jslen(rest), 2, 'nome removido') + rest)
            i += 1
        elif op in 'cl':
            out.append(op)
            i += 1
        else:
            fail('protocolo Natural: operação %r' % op)
    return ''.join(out)


_NATURAL_HEAD = (('sid', 'V'), ('pid', 'V'), ('empty', 'S'), ('model', 'V'), ('dummy', 'S'), ('page', 'V'), ('event', 'V'), ('flag', 'S'))


def natural_ajax_decode(text):
    raw = text.encode('utf-16-le', 'surrogatepass')
    s = ''.join(chr(int.from_bytes(raw[i:i + 2], 'little')) for i in range(0, len(raw), 2))
    state = {'pos': 0}
    parts, stack, names = [], [], {}

    def uni(v):
        return v.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')

    def take(n):
        if n < 0 or state['pos'] + n > len(s):
            fail('protocolo Natural: mensagem truncada')
        value = s[state['pos']:state['pos'] + n]
        state['pos'] += n
        return value

    def number(n):
        v = take(n)
        if not (v.isascii() and v.isdigit()):
            fail('protocolo Natural: comprimento inválido')
        return int(v)

    if s[:1] in ('i', 'v'):
        parts.append(('op', 'S', s[0]))
        state['pos'] = 1
        lens = [number(w) for w in (2, 2, 2, 2, 2, 3, 5, 1)]
        for (name, role), n in zip(_NATURAL_HEAD, lens):
            parts.append((name, role, uni(take(n))))
    while state['pos'] < len(s):
        op = take(1)
        if op == 'l':
            parts.append(('op', 'S', 'l'))
        elif op == 's':
            n, m = number(1), number(2)
            key = uni(take(n))
            name = uni(take(m))
            names[key] = name
            parts.append(('op', 'S', 's' + key))
            parts.append(('s.' + key, 'N', name))
        elif op in 'pqzw':
            n, m = number(2), number(10 if op in 'zw' else 5)
            key = uni(take(n))
            value = uni(take(m))
            resolved = key
            if op in 'qw':
                if key not in names:
                    fail('protocolo Natural: referência de campo desconhecida')
                resolved = names[key]
            parts.append(('op', 'S', op + key))
            parts.append(('p.' + '.'.join(stack + [resolved]), 'V', value))
        elif op == 'b':
            scope = uni(take(number(2)))
            stack.append(scope)
            parts.append(('op', 'S', 'b' + scope))
        elif op == 'c':
            if not stack:
                fail('protocolo Natural: escopo inválido')
            stack.pop()
            parts.append(('op', 'S', 'c'))
        elif op == 'x':
            parts.append(('delta', 'D', uni(take(number(2)))))
        elif op == 'k':
            parts.append(('op', 'S', 'k' + uni(take(number(2)))))
        else:
            fail('protocolo Natural: opcode não suportado: %r' % op)
    return parts
"#;
