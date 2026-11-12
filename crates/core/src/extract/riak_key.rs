//! Clés Riak dans un message : `<<"bucket">>/<<"clé">>` → `riak.bucket` et `riak.key`
//! (contenu entre guillemets).

use super::{ExtractorId, Spans, ValueKind};
use memchr::{memchr, memmem};

const SEP: &[u8] = b"\">>/<<\"";
const OPEN: &[u8] = b"<<\"";
const CLOSE: &[u8] = b"\">>";

/// Un guillemet précédé d'un nombre impair de `\` est échappé.
fn escaped(text: &[u8], quote: usize) -> bool {
    text[..quote].iter().rev().take_while(|b| **b == b'\\').count() % 2 == 1
}

pub fn scan(text: &[u8], sp: &mut Spans) {
    let root = sp.push_seg(b"riak");
    for sep in memmem::find_iter(text, SEP) {
        if escaped(text, sep) {
            continue;
        }
        // Bucket : du `<<"` qui précède, sur la même ligne et sans guillemet libre entre les deux.
        let line_start = memchr::memrchr(b'\n', &text[..sep]).map_or(0, |p| p + 1);
        let Some(bucket) = memmem::rfind(&text[line_start..sep], OPEN).map(|p| line_start + p + OPEN.len()) else { continue };
        if (bucket..sep).any(|i| text[i] == b'"' && !escaped(text, i)) {
            continue;
        }
        // Clé : jusqu'au `">>` fermant ; si la ligne est coupée avant, jusqu'à sa fin.
        let key = sep + SEP.len();
        let line_end = memchr(b'\n', &text[key..]).map_or(text.len(), |p| key + p);
        let key_end = memmem::find_iter(&text[key..line_end], CLOSE).map(|p| key + p).find(|&q| !escaped(text, q)).unwrap_or(line_end);
        let mark = sp.push_seg(b"bucket");
        sp.leaf(bucket, sep, ExtractorId::RiakKey, ValueKind::Str, false);
        sp.pop_seg(mark);
        let mark = sp.push_seg(b"key");
        sp.leaf(key, key_end, ExtractorId::RiakKey, ValueKind::Str, false);
        sp.pop_seg(mark);
    }
    sp.pop_seg(root);
}

#[cfg(test)]
mod tests {
    use super::super::{dump, run, ExtractorSet, Spans};

    fn extract(text: &str) -> Vec<(String, String)> {
        let mut sp = Spans::default();
        let set = ExtractorSet { riak_key: true, plug_metadata: false, cookie: false, json: false, elixir_term: false, http_request: false, ..ExtractorSet::default() };
        let header = memchr::memchr(b'\n', text.as_bytes()).unwrap_or(text.len());
        run(text.as_bytes(), header, None, &set, &mut sp);
        dump(text.as_bytes(), &sp)
    }

    fn s(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn bucket_and_key() {
        assert_eq!(
            extract("2026-11-09 14:25:54.020 [warning] <0.1166.0>@riak_kv_vnode:do_get_object:1837 Read large object <<\"etam_sb_order_audits\">>/<<\"900424011\">> (5652713 bytes)"),
            vec![s("riak.bucket", "etam_sb_order_audits"), s("riak.key", "900424011")]
        );
        assert_eq!(
            extract("Read large object <<\"etam_sb_etam_admin\">>/<<\"jean.dupont@example.com\">> (12 bytes)"),
            vec![s("riak.bucket", "etam_sb_etam_admin"), s("riak.key", "jean.dupont@example.com")]
        );
    }

    #[test]
    fn several_keys_continuation_lines_and_escapes() {
        assert_eq!(
            extract("2026-11-09 14:25:54.020 [error] <0.1.0> siblings\n    <<\"b1\">>/<<\"k1\">> and <<\"b2\">>/<<\"k \\\" 2\">>\n    <<\"b3\">>/<<\"k3\">>"),
            vec![s("riak.bucket", "b1"), s("riak.key", "k1"), s("riak.bucket", "b2"), s("riak.key", "k \\\" 2"), s("riak.bucket", "b3"), s("riak.key", "k3")]
        );
    }

    #[test]
    fn truncated_and_foreign_forms() {
        // Ligne coupée au milieu de la clé : la clé va jusqu'à la fin de la ligne.
        assert_eq!(extract("Read large object <<\"b\">>/<<\"jean.dupont@exa"), vec![s("riak.bucket", "b"), s("riak.key", "jean.dupont@exa")]);
        assert_eq!(extract("Read <<\"b\">>/<<\"k\nnext line \">> x"), vec![s("riak.bucket", "b"), s("riak.key", "k")]);
        // Clé vide, binaire non imprimable, binaires sans `/`, bucket sans ouverture.
        assert_eq!(extract("<<\"b\">>/<<\"\">>"), vec![s("riak.bucket", "b")]);
        assert_eq!(extract("<<\"b\">>/<<1,2,3>>"), vec![]);
        assert_eq!(extract("{<<\"a\">>,<<\"b\">>}"), vec![]);
        assert_eq!(extract("b\">>/<<\"k\">>"), vec![]);
        assert_eq!(extract("<<\"a\" x \"b\">>/<<\"k\">>"), vec![]);
        assert_eq!(extract(""), vec![]);
    }
}
