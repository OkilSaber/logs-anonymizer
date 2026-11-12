//! Lexer tolérant pour les termes Elixir : `%{}`, `%Struct{}`, `=>` et `key:`, listes,
//! tuples, strings échappées, `~c"…"`, `<<"…">>`, `#PID<>`, `#Reference<>`, `#Function<>`.
//!
//! Tolérant veut dire : un terme tronqué ou inattendu arrête l'analyse sans perdre les
//! valeurs déjà vues.

use super::{ExtractorId, Pair, Spans, ValueKind};
use memchr::memchr2;

const X: ExtractorId = ExtractorId::ElixirTerm;

/// Cherche les `%{`, les `%Alias{` et les listes keyword (`[clé: valeur, …]`) du texte et
/// les analyse.
pub fn scan(text: &[u8], sp: &mut Spans, max_depth: usize) {
    let mut i = 0;
    while i < text.len() {
        let Some(off) = memchr2(b'%', b'[', &text[i..]) else { break };
        let p = i + off;
        let starts = if text[p] == b'%' { starts_map(text, p) } else { starts_keyword_list(text, p, sp) };
        if !starts || sp.is_claimed(p) || (p > 0 && text[p - 1].is_ascii_alphanumeric()) {
            i = p + 1;
            continue;
        }
        // `State: %{…}` → le libellé devient la racine du chemin.
        let mark = label_before(text, p).map(|(s, e)| sp.push_seg(&text[s..e]));
        let end = parse_at(text, p, sp, max_depth).max(p + 1);
        if let Some(mark) = mark {
            sp.pop_seg(mark);
        }
        sp.claim(p, end);
        i = end;
    }
}

/// Analyse un terme à la position donnée, au chemin courant. Rend la position de fin.
pub fn parse_at(text: &[u8], pos: usize, sp: &mut Spans, max_depth: usize) -> usize {
    let mut p = Parser { t: text, i: pos, sp, max_depth };
    p.term(0);
    p.i
}

fn starts_map(t: &[u8], p: usize) -> bool {
    let mut i = p + 1;
    if t.get(i).is_some_and(|c| c.is_ascii_uppercase()) {
        while i < t.len() && (t[i].is_ascii_alphanumeric() || matches!(t[i], b'.' | b'_')) {
            i += 1;
        }
    }
    t.get(i) == Some(&b'{')
}

/// `[` immédiatement suivi d'une clé keyword : `[user: 'x', …]`. Les crochets de texte
/// (`[info]`, `[gts]: ticking`, `[Offer Config]: …`) n'en sont pas.
fn starts_keyword_list(t: &[u8], p: usize, sp: &mut Spans) -> bool {
    Parser { t, i: p + 1, sp, max_depth: 0 }.keyword_key().is_some()
}

/// `Libellé: ` juste avant la position, sur la même ligne.
fn label_before(t: &[u8], p: usize) -> Option<(usize, usize)> {
    let mut j = p;
    while j > 0 && t[j - 1] == b' ' {
        j -= 1;
    }
    if j == p || j == 0 || t[j - 1] != b':' {
        return None;
    }
    let e = j - 1;
    let mut s = e;
    while s > 0 && (t[s - 1].is_ascii_alphanumeric() || t[s - 1] == b'_') {
        s -= 1;
    }
    (s < e).then_some((s, e))
}

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Scalar,
    Container,
}

struct Parser<'a> {
    t: &'a [u8],
    i: usize,
    sp: &'a mut Spans,
    max_depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.t.len() && self.t[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    /// `self.i` est sur le délimiteur ouvrant. Une string s'arrête à la fin de ligne :
    /// `inspect` échappe les retours à la ligne, un vrai retour signale une troncature.
    fn string(&mut self, quote: u8) -> (usize, usize, bool) {
        let s = self.i + 1;
        let mut j = s;
        while j < self.t.len() {
            let c = self.t[j];
            if c == b'\\' {
                j += 2;
            } else if c == quote {
                self.i = j + 1;
                return (s, j, true);
            } else if c == b'\n' {
                break;
            } else {
                j += 1;
            }
        }
        let e = j.min(self.t.len());
        self.i = e;
        (s, e, false)
    }

    fn string_leaf(&mut self, quote: u8) -> Option<Shape> {
        let (s, e, closed) = self.string(quote);
        self.sp.leaf(s, e, X, ValueKind::Str, false);
        closed.then_some(Shape::Scalar)
    }

    /// Analyse un terme. `None` : tronqué ou non reconnu.
    fn term(&mut self, depth: usize) -> Option<Shape> {
        self.ws();
        if depth > self.max_depth {
            return None;
        }
        let t = self.t;
        let i = self.i;
        let c = *t.get(i)?;
        match c {
            b'"' => self.string_leaf(b'"'),
            b'\'' => self.string_leaf(b'\''),
            b'~' => {
                // Sigil : ~c"…", ~s"…", ~S'…'
                let q = *t.get(i + 2)?;
                if t[i + 1].is_ascii_alphabetic() && (q == b'"' || q == b'\'') {
                    self.i = i + 2;
                    self.string_leaf(q)
                } else {
                    None
                }
            }
            b'%' => {
                self.i += 1;
                while self.i < t.len() && (t[self.i].is_ascii_alphanumeric() || matches!(t[self.i], b'.' | b'_')) {
                    self.i += 1;
                }
                if t.get(self.i) != Some(&b'{') {
                    return None;
                }
                self.i += 1;
                self.sequence(b'}', depth + 1)?;
                Some(Shape::Container)
            }
            b'[' => {
                self.i += 1;
                self.sequence(b']', depth + 1)?;
                Some(Shape::Container)
            }
            b'{' => {
                // Tuple : une seule valeur s'il ne contient que des scalaires
                // (`{203, 0, 113, 10}`), sinon on garde les valeurs de ses conteneurs.
                self.i += 1;
                let mark = self.sp.items.len();
                let has_container = self.sequence(b'}', depth + 1)?;
                if has_container {
                    Some(Shape::Container)
                } else {
                    self.sp.items.truncate(mark);
                    self.sp.leaf(i, self.i, X, ValueKind::Tuple, true);
                    Some(Shape::Scalar)
                }
            }
            b'<' if t.get(i + 1) == Some(&b'<') => {
                let end = memchr::memmem::find(&t[i + 2..], b">>")? + i + 2;
                let inner = &t[i + 2..end];
                if inner.len() >= 2 && inner[0] == b'"' && inner[inner.len() - 1] == b'"' {
                    self.sp.leaf(i + 3, end - 1, X, ValueKind::Str, false);
                } else {
                    self.sp.leaf(i, end + 2, X, ValueKind::Opaque, true);
                }
                self.i = end + 2;
                Some(Shape::Scalar)
            }
            b'#' => {
                // #PID<0.1.2>, #Reference<…>, #Function<1.2/3 in Mod.fun/2>, #MapSet<[…]>
                let mut j = i + 1;
                while j < t.len() && (t[j].is_ascii_alphanumeric() || matches!(t[j], b'.' | b'_')) {
                    j += 1;
                }
                if t.get(j) != Some(&b'<') {
                    return None;
                }
                let mut level = 0usize;
                while j < t.len() {
                    match t[j] {
                        b'<' => level += 1,
                        b'>' => {
                            level -= 1;
                            if level == 0 {
                                break;
                            }
                        }
                        b'\n' => return None,
                        _ => {}
                    }
                    j += 1;
                }
                if j >= t.len() {
                    return None;
                }
                self.i = j + 1;
                self.sp.leaf(i, self.i, X, ValueKind::Opaque, true);
                Some(Shape::Scalar)
            }
            b':' => {
                if t.get(i + 1) == Some(&b'"') {
                    self.i = i + 1;
                    let (s, e, closed) = self.string(b'"');
                    self.sp.leaf(s, e, X, ValueKind::Str, false);
                    return closed.then_some(Shape::Scalar);
                }
                let mut j = i + 1;
                while j < t.len() && (t[j].is_ascii_alphanumeric() || matches!(t[j], b'_' | b'@' | b'.' | b'?' | b'!')) {
                    j += 1;
                }
                if j == i + 1 {
                    return None;
                }
                self.i = j;
                if &t[i + 1..j] != b"..." {
                    self.sp.leaf(i, j, X, ValueKind::Atom, true);
                }
                Some(Shape::Scalar)
            }
            b'&' => {
                let mut j = i + 1;
                while j < t.len() && !t[j].is_ascii_whitespace() && !matches!(t[j], b',' | b'}' | b']' | b')') {
                    j += 1;
                }
                self.i = j;
                self.sp.leaf(i, j, X, ValueKind::Opaque, true);
                Some(Shape::Scalar)
            }
            b'-' | b'0'..=b'9' => {
                let mut j = i + 1;
                if c == b'-' && !t.get(j).is_some_and(u8::is_ascii_digit) {
                    return None;
                }
                while j < t.len() {
                    let next_digit = t.get(j + 1).is_some_and(u8::is_ascii_digit);
                    match t[j] {
                        b'0'..=b'9' | b'_' => j += 1,
                        b'.' if next_digit => j += 1,
                        b'e' | b'E' if next_digit => j += 1,
                        b'e' | b'E' if matches!(t.get(j + 1), Some(b'+' | b'-')) && t.get(j + 2).is_some_and(u8::is_ascii_digit) => j += 2,
                        _ => break,
                    }
                }
                self.i = j;
                self.sp.leaf(i, j, X, ValueKind::Number, true);
                Some(Shape::Scalar)
            }
            b'.' if t[i..].starts_with(b"...") => {
                // Marque de troncature d'inspect : rien à extraire.
                self.i = i + 3;
                Some(Shape::Scalar)
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                // nil, true, false, atome nu, alias de module (Plug.Cowboy.Conn).
                let mut j = i + 1;
                while j < t.len() {
                    let dotted = t[j] == b'.' && t.get(j + 1).is_some_and(|n| n.is_ascii_alphanumeric() || *n == b'_');
                    if t[j].is_ascii_alphanumeric() || matches!(t[j], b'_' | b'?' | b'!' | b'@') || dotted {
                        j += 1;
                    } else {
                        break;
                    }
                }
                self.i = j;
                if !matches!(&t[i..j], b"nil" | b"true" | b"false") {
                    self.sp.leaf(i, j, X, ValueKind::Atom, true);
                }
                Some(Shape::Scalar)
            }
            _ => None,
        }
    }

    /// `clé: ` en syntaxe keyword → (début, fin de la clé, position après le deux-points).
    fn keyword_key(&self) -> Option<(usize, usize, usize)> {
        let t = self.t;
        let i = self.i;
        let (ks, ke, mut j) = if t.get(i) == Some(&b'"') {
            let mut j = i + 1;
            loop {
                match *t.get(j)? {
                    b'\\' => j += 2,
                    b'"' => break,
                    b'\n' => return None,
                    _ => j += 1,
                }
            }
            (i + 1, j, j + 1)
        } else {
            let c = *t.get(i)?;
            if !(c.is_ascii_alphabetic() || c == b'_') {
                return None;
            }
            let mut j = i + 1;
            while j < t.len() && (t[j].is_ascii_alphanumeric() || t[j] == b'_') {
                j += 1;
            }
            if matches!(t.get(j), Some(b'?' | b'!')) {
                j += 1;
            }
            (i, j, j)
        };
        if t.get(j) != Some(&b':') {
            return None;
        }
        j += 1;
        // `clé: valeur` exige un blanc ; `a::b` et `12:30` n'en sont pas.
        t.get(j).is_some_and(|c| c.is_ascii_whitespace()).then_some((ks, ke, j))
    }

    /// Nom de clé d'une paire `clé => valeur`, pour un terme clé occupant `[s, e)`.
    fn key_name(&self, s: usize, e: usize) -> (usize, usize) {
        let t = self.t;
        if e >= s + 2 && t[s] == b'"' && t[e - 1] == b'"' {
            (s + 1, e - 1)
        } else if e >= s + 3 && t[s] == b':' && t[s + 1] == b'"' && t[e - 1] == b'"' {
            (s + 2, e - 1)
        } else if t[s] == b':' {
            (s + 1, e)
        } else {
            (s, e)
        }
    }

    fn keyed_value(&mut self, ks: usize, ke: usize, field_start: usize, depth: usize) -> Option<Shape> {
        let t = self.t;
        let mark = self.sp.push_seg(&t[ks..ke]);
        let idx = self.sp.items.len();
        let r = self.term(depth);
        if self.sp.items.len() == idx + 1 {
            self.sp.items[idx].field = Some((field_start as u32, self.i as u32));
        }
        self.sp.pop_seg(mark);
        r
    }

    /// Contenu d'un map, d'une struct, d'une liste ou d'un tuple, jusqu'à `close`.
    /// Rend `true` si un élément est un conteneur ou une paire clé/valeur.
    fn sequence(&mut self, close: u8, depth: usize) -> Option<bool> {
        let mut has_container = false;
        let mut pair = Pair::default();
        let base = self.sp.cur_len();
        loop {
            self.ws();
            let c = *self.t.get(self.i)?;
            if c == close {
                self.i += 1;
                return Some(has_container);
            }
            if c == b',' || c == b'|' {
                self.i += 1;
                continue;
            }
            if let Some((ks, ke, after)) = self.keyword_key() {
                let field_start = self.i;
                self.i = after;
                has_container = true;
                let before = self.sp.items.len();
                let r = self.keyed_value(ks, ke, field_start, depth);
                pair.note(&self.t[ks..ke], before, self.t, base, self.sp);
                r?;
                continue;
            }
            let idx = self.sp.items.len();
            let start = self.i;
            let shape = self.term(depth)?;
            let end = self.i;
            self.ws();
            if self.t[self.i..].starts_with(b"=>") {
                // C'était une clé : ses spans ne sont pas des valeurs.
                self.sp.items.truncate(idx);
                self.i += 2;
                let (ks, ke) = self.key_name(start, end);
                has_container = true;
                let before = self.sp.items.len();
                let r = self.keyed_value(ks, ke, start, depth);
                pair.note(&self.t[ks..ke], before, self.t, base, self.sp);
                r?;
            } else if shape == Shape::Container {
                has_container = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{dump, run, ExtractorSet, Spans};

    fn extract(text: &[u8]) -> Vec<(String, String)> {
        let mut sp = Spans::default();
        run(text, memchr::memchr(b'\n', text).unwrap_or(text.len()), None, &ExtractorSet::default(), &mut sp);
        dump(text, &sp)
    }

    fn s(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn multiline_header_dump() {
        let text = b"10:00:00.000 [info]  x\n%{\n \"authorization\" => \"Basic dXNlcjpwYXNzd29yZA==\",\n \"host\" => \"gw.priv.kbrw.fr:8080\",\n \"user-agent\" => \"hackney/1.17.4\"\n}";
        assert_eq!(
            extract(text),
            vec![
                s("authorization", "Basic dXNlcjpwYXNzd29yZA=="),
                s("host", "gw.priv.kbrw.fr:8080"),
                s("user-agent", "hackney/1.17.4"),
            ]
        );
    }

    #[test]
    fn keyword_syntax_lists_and_empty_values() {
        let text = br#"03:33:21.132 [debug] [AWSMailer] Sending mail to :%{copy: [], sender: "m@kbrw.fr", reply_to: "", subject: "[Preprod] a, b} c", recipients: ["a@example.com", "b@example.com"]}"#;
        assert_eq!(
            extract(text),
            vec![
                s("sender", "m@kbrw.fr"),
                s("subject", "[Preprod] a, b} c"),
                s("recipients", "a@example.com"),
                s("recipients", "b@example.com"),
            ]
        );
    }

    #[test]
    fn truncated_plug_conn() {
        let text = br#"(jar_admin 0.1.0) lib/app.ex:144: JarAdmin.HTTP.do_match(%Plug.Conn{adapter: {Plug.Cowboy.Conn, :...}, assigns: %{}, cookies: %{"sid" => "abc"}, halted: false, host: "203.0.113.10", method: "POST", owner: #PID<0.30478.27>, remote_ip: {203, 0, 113, 10}, port: 443, ..."#;
        assert_eq!(
            extract(text),
            vec![
                s("adapter", "{Plug.Cowboy.Conn, :...}"),
                s("cookies.sid", "abc"),
                s("host", "203.0.113.10"),
                s("method", "POST"),
                s("owner", "#PID<0.30478.27>"),
                s("remote_ip", "{203, 0, 113, 10}"),
                s("port", "443"),
            ]
        );
    }

    #[test]
    fn nested_paths_labels_and_exotic_terms() {
        let text = br#"State: %{modstate: %{path: ~c"lib/x.ex", line: 1, key: <<"bucket">>, fun: #Function<1.2/3 in Mod.fun/2>}, "user_id" => "M0000001", atom: :ok, t: {:ok, %{"deep" => 'c'}}}"#;
        assert_eq!(
            extract(text),
            vec![
                s("state.modstate.path", "lib/x.ex"),
                s("state.modstate.line", "1"),
                s("state.modstate.key", "bucket"),
                s("state.modstate.fun", "#Function<1.2/3 in Mod.fun/2>"),
                s("state.user_id", "M0000001"),
                s("state.atom", ":ok"),
                s("state.t", ":ok"),
                s("state.t.deep", "c"),
            ]
        );
    }

    #[test]
    fn escaped_quotes_and_delimiters_in_strings() {
        let text = br#"x %{"a" => "v\"1, } => ", "b" => "2"}"#;
        assert_eq!(extract(text), vec![s("a", r#"v\"1, } => "#), s("b", "2")]);
    }

    #[test]
    fn string_cut_by_end_of_line_stops_the_term() {
        let text = b"x %{\"a\" => \"1\", \"b\" => \"cut\n\"c\" => \"never a key\"}";
        assert_eq!(extract(text), vec![s("a", "1"), s("b", "cut")]);
    }

    #[test]
    fn cookie_header_inside_a_term_is_split() {
        let text = br#"x %{"cookie" => "a=1; etam_admin-auth=j@example.com%7C1%7Cz", "set-cookie" => "sid=xyz; Path=/; HttpOnly"}"#;
        assert_eq!(
            extract(text),
            vec![s("cookie.a", "1"), s("cookie.etam_admin-auth", "j@example.com%7C1%7Cz"), s("set-cookie.sid", "xyz")]
        );
    }

    #[test]
    fn top_level_keyword_list_with_charlists() {
        let text = b"03:54:50.548 [info]  host: \"sftp.example.com\", opts.port: 222, connect_opts: [user: 'svc_demo', password: 'Xy*=7&gZ', user_interaction: false, quiet_mode: true]";
        assert_eq!(extract(text), vec![s("connect_opts.user", "svc_demo"), s("connect_opts.password", "Xy*=7&gZ")]);
        // Les crochets de texte ne sont pas des listes keyword.
        assert!(extract(b"10:00:00.000 [info]  [gts]: ticking [Offer Config]: not updating [n_ms] x [a, b] sz[174]").is_empty());
    }

    #[test]
    fn name_value_pairs_take_the_name_as_key() {
        // La forme des propriétés d'emails transactionnels : la clé utile est dans `name`.
        let text = br#"x %{properties: [%{name: :firstName, value: "Jean"}, %{value: "DUPONT", name: "lastName"}, %{name: :orderNumber, value: 900000001}, %{name: :items, value: [%{sku: "123", label: "Robe"}]}, %{name: :cut, value: "tronq"#;
        assert_eq!(
            extract(text),
            vec![
                s("properties.name", ":firstName"),
                s("properties.firstname", "Jean"),
                s("properties.lastname", "DUPONT"),
                s("properties.name", "lastName"),
                s("properties.name", ":orderNumber"),
                s("properties.ordernumber", "900000001"),
                s("properties.name", ":items"),
                s("properties.items.sku", "123"),
                s("properties.items.label", "Robe"),
                s("properties.name", ":cut"),
                s("properties.cut", "tronq"),
            ]
        );
        // `value` sans `name` à côté, ou `name` qui n'est pas un scalaire : rien ne change.
        assert_eq!(extract(br#"x %{value: "v", other: 1} %{name: %{a: 1}, value: "w"}"#), vec![s("value", "v"), s("other", "1"), s("name.a", "1"), s("value", "w")]);
    }

    #[test]
    fn percent_in_text_is_not_a_term() {
        assert!(extract(b"10:00:00.000 [info]  load 50% done, 100%{ nothing").is_empty());
    }
}
