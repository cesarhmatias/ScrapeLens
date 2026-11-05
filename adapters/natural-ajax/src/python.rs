//! Python encoder equivalent to `NaturalAjax::encode` (lengths in
//! UTF-16 units, all prefixes recalculated).

/// Name of the function defined in [`PYTHON_ENCODER`].
pub const PYTHON_FUNCTION: &str = "natural_ajax_encode";

/// Name of the decoding function defined in [`PYTHON_ENCODER`]:
/// `natural_ajax_decode(text)` returns the same parts `(name, role, value)`
/// as the `decode` in Rust, without offsets.
pub const PYTHON_DECODER: &str = "natural_ajax_decode";

/// Takes the list of parts `(name, role, value)` in order, with role
/// `'S'` (structure), `'N'` (name), `'V'` (value) or `'D'` (delta).
pub const PYTHON_ENCODER: &str = r#"
def natural_jslen(value):
    return len(value.encode('utf-16-le', 'surrogatepass')) // 2


def natural_fit(number, width, what):
    text = str(number)
    if len(text) > width:
        fail('Natural protocol: %s exceeds %d UTF-16 units' % (what, 10 ** width - 1))
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
            fail('Natural protocol: invalid structure (expected an operation)')
        op, rest = value[0], value[1:]
        if op in 'iv':
            head = parts[i + 1:i + 9]
            if len(head) != 8:
                fail('Natural protocol: header too short')
            fields = [p[2] for p in head]
            widths = (2, 2, 2, 2, 2, 3, 5, 1)
            out.append(op + ''.join(natural_fit(natural_jslen(f), w, 'header field') for f, w in zip(fields, widths)) + ''.join(fields))
            i += 9
        elif op in 'pzqw':
            if i + 1 >= len(parts):
                fail('Natural protocol: missing value')
            data = parts[i + 1][2]
            width = 10 if op in 'zw' else 5
            out.append(op + natural_fit(natural_jslen(rest), 2, 'name') + natural_fit(natural_jslen(data), width, 'value') + rest + data)
            i += 2
        elif op == 's':
            if i + 1 >= len(parts):
                fail('Natural protocol: missing name')
            data = parts[i + 1][2]
            out.append('s' + natural_fit(natural_jslen(rest), 1, 'dictionary key') + natural_fit(natural_jslen(data), 2, 'dictionary name') + rest + data)
            i += 2
        elif op == 'b':
            out.append('b' + natural_fit(natural_jslen(rest), 2, 'scope') + rest)
            i += 1
        elif op == 'k':
            out.append('k' + natural_fit(natural_jslen(rest), 2, 'removed name') + rest)
            i += 1
        elif op in 'cl':
            out.append(op)
            i += 1
        else:
            fail('Natural protocol: operation %r' % op)
    return ''.join(out)


_NATURAL_HEAD = (('sid', 'V'), ('pid', 'V'), ('empty', 'S'), ('model', 'V'), ('dummy', 'S'), ('page', 'V'), ('event', 'V'), ('flag', 'S'))


def natural_ajax_decode(text):
    if len(text.encode('utf-8', 'surrogatepass')) > 8 * 1024 * 1024:
        fail('Natural protocol: limit exceeded: message too large')
    if text.isascii():
        s = text
    else:
        raw = text.encode('utf-16-le', 'surrogatepass')
        s = ''.join(chr(int.from_bytes(raw[i:i + 2], 'little')) for i in range(0, len(raw), 2))
    state = {'pos': 0}
    parts, marks, names = [], [], {}
    ops = 0
    prefix = ''

    def uni(v):
        return v.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')

    def take(n):
        if n < 0 or state['pos'] + n > len(s):
            fail('Natural protocol: message truncated')
        value = s[state['pos']:state['pos'] + n]
        # Cut in the middle of a surrogate pair: error, as in Rust.
        for cut in (state['pos'], state['pos'] + n):
            if 0 < cut < len(s) and '\ud800' <= s[cut - 1] <= '\udbff' and '\udc00' <= s[cut] <= '\udfff':
                fail('Natural protocol: length cuts a UTF-16 surrogate pair')
        state['pos'] += n
        return value

    def number(n):
        v = take(n)
        if not (v.isascii() and v.isdigit()):
            fail('Natural protocol: invalid length')
        return int(v)

    if s[:1] in ('i', 'v'):
        parts.append(('op', 'S', s[0]))
        ops = 1
        state['pos'] = 1
        lens = [number(w) for w in (2, 2, 2, 2, 2, 3, 5, 1)]
        for (name, role), n in zip(_NATURAL_HEAD, lens):
            parts.append((name, role, uni(take(n))))
    while state['pos'] < len(s):
        ops += 1
        if ops > 200000:
            fail('Natural protocol: limit exceeded: too many operations')
        op = take(1)
        if op == 'l':
            parts.append(('op', 'S', 'l'))
        elif op == 's':
            n, m = number(1), number(2)
            key = uni(take(n))
            name = uni(take(m))
            if len(names) >= 10000 and key not in names:
                fail('Natural protocol: limit exceeded: too many dictionary keys')
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
                    fail('Natural protocol: unknown field reference')
                resolved = names[key]
            parts.append(('op', 'S', op + key))
            parts.append(('p.' + prefix + resolved, 'V', value))
        elif op == 'b':
            scope = uni(take(number(2)))
            if len(marks) >= 32:
                fail('Natural protocol: limit exceeded: scopes nested too deeply')
            marks.append(len(prefix))
            prefix += scope + '.'
            if len(prefix) > 512:
                fail('Natural protocol: limit exceeded: scope path too long')
            parts.append(('op', 'S', 'b' + scope))
        elif op == 'c':
            if not marks:
                fail('Natural protocol: invalid scope')
            prefix = prefix[:marks.pop()]
            parts.append(('op', 'S', 'c'))
        elif op == 'x':
            parts.append(('delta', 'D', uni(take(number(2)))))
        elif op == 'k':
            parts.append(('op', 'S', 'k' + uni(take(number(2)))))
        else:
            fail('Natural protocol: unsupported opcode: %r' % op)
    if marks:
        fail('Natural protocol: invalid scope')
    return parts
"#;
