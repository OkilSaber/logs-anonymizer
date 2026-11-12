//! Propriétés : aucune valeur sensible injectée ne survit, et la sortie n'est jamais
//! plus « sensible » que l'entrée.

// Ces tests s'appuient sur les templates et le corpus, qui ne font pas partie du dépôt.
#![cfg(logano_templates)]

use logano_core::detect::{detect, DetectorConfig, DetectorId};
use logano_core::pipeline::{run, RunOptions};
use logano_core::template::testing::TEST_KEY;
use logano_core::{Engine, EngineOptions, Library};
use proptest::prelude::*;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn engine(template: &str) -> Engine {
    let lib = Library::builtin();
    Engine::new(Arc::new(lib.compile(template).unwrap()), EngineOptions::with_key(TEST_KEY)).unwrap()
}

fn anonymize(e: &Engine, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    run(input, e, &mut out, &RunOptions::default(), &AtomicBool::new(false), &mut |_| {}).unwrap();
    out
}

fn findings(text: &[u8]) -> usize {
    let mut out = Vec::new();
    for d in DetectorId::ALL {
        detect(d, text, &DetectorConfig::default(), &mut out);
    }
    out.len()
}

fn email() -> impl Strategy<Value = String> {
    ("[a-z]{3,8}", "[a-z]{3,8}", "[a-z]{4,9}", prop::sample::select(vec!["com", "fr", "org", "net"]))
        .prop_map(|(a, b, d, tld)| format!("{a}.{b}@{d}.{tld}"))
}

fn public_ip() -> impl Strategy<Value = String> {
    (prop::sample::select(vec![51u8, 198, 203, 188, 8, 93]), 0u8..=255, 0u8..=255, 1u8..=254).prop_map(|(a, b, c, d)| {
        // Hors des plages privées et réservées.
        let b = if a == 198 { 51 } else { b };
        format!("{a}.{b}.{c}.{d}")
    })
}

fn basic() -> impl Strategy<Value = String> {
    ("[a-z]{4,10}", "[A-Za-z0-9]{8,16}").prop_map(|(u, p)| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
    })
}

/// Les formes observées dans les logs, avec des trous pour les valeurs sensibles.
fn entry() -> impl Strategy<Value = (String, Vec<String>)> {
    (email(), public_ip(), basic(), "[A-Z][a-z]{5,9}", "[1-9][0-9]{1,2} rue [a-z]{4,9}", 0usize..11, "[a-z]{3,8}", "[A-Za-z0-9*=&?!$^+]{10,18}").prop_map(
        |(email, ip, b64, name, street, shape, word, password)| {
            let h = "etam-gateway01.etam-sb.kbrw.fr";
            let (text, secrets) = match shape {
                0 => (format!("{h}  09:39:05.203 [info]  in GET /api/{word}\n{h}  \tcookie : etam_admin-auth={email}%7C1794217138%7CAbCdEfGhIjKlMnOpQrStUvWxYz0=\n"), vec![email, "AbCdEfGhIjKlMnOpQrStUvWxYz0".into()]),
                1 => (format!("{h}  00:00:16.060 [info]  in GET /api/{word}\n{h}  \tauthorization : Basic {b64}\n{h}  %{{\n{h}   \"authorization\" => \"Basic {b64}\",\n{h}   \"host\" => \"{ip}\"\n{h}  }}\n"), vec![b64, ip]),
                2 => (format!("{h}  07:27:23.961 [info]  in GET //api/etam_admin/{email}/{word}\n"), vec![email]),
                3 => (format!("{h}  15:25:21.157 [error] [Iam.Oauth] owner {email} not found from {ip}\n"), vec![email, ip]),
                4 => (format!("{h}  03:33:21.132 [debug] [AWSMailer] Sending mail to :%{{copy: [], subject: \"{word}\", recipients: [\"{email}\"]}}\r\n"), vec![email]),
                5 => (format!("{h}  04:58:03.747 [info]  /api/order\n{h}  {{\n{h}   \"customername\": \"{name}\",\n{h}   \"customeremail\": \"{email}\",\n{h}   \"billingaddress\": {{\n{h}     \"addressline1\": \"{street}\",\n{h}     \"mobilephone\": \"0612345678\"\n{h}   }},\n{h}  ...\n"), vec![name, email, street, "0612345678".into()]),
                6 => (format!("{h}  01:41:09.167 [error] terminated\n{h}  Server: {ip}:443 (http)\n{h}  x(%Plug.Conn{{host: \"{ip}\", remote_ip: {{{}}}, cookies: %{{\"sid\" => \"{b64}\"}}, ...\n", ip.replace('.', ", ")), vec![ip.clone(), ip.replace('.', ", "), b64]),
                7 => (format!("{h}  \x1b[0m\x1b[36m\r\n{h}  10:00:00.000 [info]  {{\"shipping_address\":{{\"address1\":\"{street}\",\"city\":\"{name}\",\"country_code\":\"FR\"}},\"email\":\"{email}\"}}\r\n"), vec![street, name, email]),
                8 => (format!("{h}  03:54:50.548 [info]  host: \"{ip}\", opts.port: 222, connect_opts: [user: '{word}', password: '{password}', user_interaction: false, quiet_mode: true]\n"), vec![password, ip]),
                9 => {
                    // Dans une query string, les caractères spéciaux d'un mot de passe sont encodés :
                    // la valeur nue ne contient que des caractères sûrs.
                    let in_url: String = password.chars().filter(char::is_ascii_alphanumeric).chain("Zz9x".chars()).collect();
                    (format!("{h}  10:00:00.000 [info]  POST /login?user={word}&password={in_url}&next=/ done\n{h}  State: %{{sftp: [host: \"{ip}\", password: \"{password}\"], first_name_query_field: \"{name}\"}}\n"), vec![in_url, password, ip, name])
                }
                _ => (format!("{h}  10:00:00.000 [info]  login as https://{word}:{name}{b64}@partner.example.com/x for {email}\n"), vec![format!("{name}{b64}"), email]),
            };
            (text, secrets)
        },
    )
}

/// Les formes de `haproxy.log`, avec des trous pour les valeurs sensibles.
fn haproxy_line() -> impl Strategy<Value = (String, Vec<String>)> {
    (email(), public_ip(), public_ip(), "[A-Za-z0-9]{10,18}", 0usize..8, "[a-z]{3,8}", 1024u32..65535, any::<bool>(), any::<bool>()).prop_map(
        |(email, client, front, password, shape, word, port, syslog_header, crlf)| {
            let h = "jar-admin-access01.jar-sb-atlas.kbrw.fr";
            let date = "[09/Nov/2026:00:10:02.290]";
            let front_name = format!("node-public_ipv4-{}-443", front.replace('.', "_"));
            let v6 = "2001:41d0:9a:a10:b00:6100:0:1";
            let back = "jar_sb_admin-local_ipv6-8080/jar-admin01";
            let http = |client: &str, frontend: &str, backend: &str, status: u16, hds: &str, req: &str| {
                format!("{client}:{port} {date} {frontend} {backend} tls[TLSv1.3/TLS_AES_256_GCM_SHA384/26] t[0/0/0/4/4] c[{status}] sz[310] - - ---- 1/1/0/0/0 0/0 hds[{hds}] req[\"{req}\"]")
            };
            let front_secret = front_name[17..front_name.len() - 4].to_string();
            let (payload, secrets) = match shape {
                // IP cliente publique, IP publique dans le nom du frontend et du backend.
                0 => (http(&client, &format!("{front_name}~"), &format!("{front_name}/<NOSRV>"), 400, "", "<BADREQ>"), vec![client, front_secret]),
                // Email dans le chemin de l'URL, client interne.
                1 => (http(v6, "node-local_ipv6-2001_41d0_9a_a10_b03_701_0_1-80", back, 200, "{}", &format!("GET //api/etam_admin/{email}/{word} HTTP/1.1")), vec![email]),
                // Mot de passe dans la query string.
                2 => (http(&client, &format!("{front_name}~"), back, 302, "{jar-sb-admin.kbrw.fr|}", &format!("POST /login?user={word}&password={password}&next=/ HTTP/1.1")), vec![client, front_secret, password]),
                // Email en paramètre, IP publique dans un en-tête capturé, requête coupée par syslog.
                3 => {
                    let line = http(&client, "front", back, 200, &format!("{{{front}:80|}}"), &format!("GET /{word}?email={email}&Password={password}"));
                    (line[..line.len() - 2].to_string(), vec![client, front, email, password])
                }
                4 => (format!("{client}:{port} {date} sftp-frontend-ipv4 sftp-backend-ipv6/primary 1/0/60679 6972 sD 1/1/0/0/0 0/0"), vec![client]),
                5 => (format!("{client}:{port} {date} {front_name}/1: SSL handshake failure"), vec![client, front_secret]),
                // Ligne coupée avant la fin des champs fixes.
                6 => (format!("{client}:{port} {date} {front_name}~ {back} tls[-/-/0] t[0/0"), vec![client, front_secret]),
                // Pas un payload HAProxy.
                _ => (format!("Server {back} is DOWN, {word} told {email} from {client}"), vec![email, client]),
            };
            let header = if syslog_header { format!("2026-11-09T00:10:02+00:00 {h} haproxy[1665563]: ") } else { String::new() };
            (format!("{h}  {header}{payload}{}\n", if crlf { "\r" } else { "" }), secrets)
        },
    )
}

/// Trouvailles des détecteurs certains (email, IP, identifiants, JWT, IBAN) dans une sortie,
/// l'infra interne (allowlist) mise à part. Les détecteurs à faux positifs sont laissés de
/// côté : un jeton inséré dans un nom (`node-public_ipv4-IP_d2e9de8b-443`) forme un mot
/// que `high_entropy` prendrait pour un secret, alors que le filet, lui, reconnaît ses jetons.
fn findings_outside_infra(out: &[u8]) -> usize {
    let text = String::from_utf8_lossy(out).replace("2001:41d0:9a:", "infra-");
    let mut found = Vec::new();
    for d in DetectorId::ALL.into_iter().filter(|d| !d.weak()) {
        detect(d, text.as_bytes(), &DetectorConfig::default(), &mut found);
    }
    found.len()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn haproxy_injected_sensitive_values_never_survive(entries in prop::collection::vec(haproxy_line(), 1..12)) {
        let e = engine("kbrw/haproxy");
        let input: String = entries.iter().map(|(t, _)| t.as_str()).collect();
        let out = anonymize(&e, input.as_bytes());
        let text = String::from_utf8_lossy(&out);
        for (_, secrets) in &entries {
            for s in secrets {
                prop_assert!(!text.contains(s.as_str()), "« {} » a survécu dans :\n{}", s, text);
            }
        }
        prop_assert!(!text.contains('\r'), "CR dans la sortie");
        prop_assert_eq!(findings_outside_infra(&out), 0, "sortie :\n{}", text);
    }

    #[test]
    fn haproxy_and_riak_garbage_never_panics(
        tail in "[0-9a-f:._ \\[\\]/~{}|\"<>?&=%+A-Za-z@-]{0,160}",
        cut in 0usize..400,
        raw in prop::collection::vec(any::<u8>(), 0..120),
    ) {
        let valid = "198.51.100.65:40461 [09/Nov/2026:00:00:06.788] node-public_ipv4-51_75_10_28-443~ etam_sb_admin-local_ipv6-8080/etam-admin01 tls[TLSv1.3/TLS_AES_256_GCM_SHA384/28] t[0/0/0/1/1] c[200] sz[174] - - ---- 1/1/0/0/0 0/0 hds[{etam-sb-etam-admin.kbrw.fr|}] req[\"GET /api/orders?a=b HTTP/1.1\"]";
        let cut = cut.min(valid.len());
        let raw: Vec<u8> = raw.into_iter().filter(|b| *b != b'\n').collect();
        let mut input = Vec::new();
        for payload in [format!("{}{tail}", &valid[..cut]).into_bytes(), tail.clone().into_bytes(), raw.clone()] {
            input.extend_from_slice(b"h.kbrw.fr  2026-11-09T00:00:06+00:00 h.kbrw.fr haproxy[227]: ");
            input.extend_from_slice(&payload);
            input.extend_from_slice(b"\nh.kbrw.fr  ");
            input.extend_from_slice(&payload);
            input.push(b'\n');
        }
        let out = anonymize(&engine("kbrw/haproxy"), &input);
        prop_assert_eq!(findings_outside_infra(&out), 0, "sortie : {:?}", String::from_utf8_lossy(&out));

        let mut input = Vec::new();
        for payload in [tail.into_bytes(), raw] {
            input.extend_from_slice(b"r.kbrw.fr  2026-11-09 14:25:54.020 [warning] <0.1166.0>@riak_kv_vnode:do_get_object:1837 Read <<\"b\">>/<<\"");
            input.extend_from_slice(&payload);
            input.extend_from_slice(b"\nr.kbrw.fr  ");
            input.extend_from_slice(&payload);
            input.push(b'\n');
        }
        let out = anonymize(&engine("kbrw/riak-console"), &input);
        prop_assert_eq!(findings_outside_infra(&out), 0, "sortie : {:?}", String::from_utf8_lossy(&out));
    }

    #[test]
    fn injected_sensitive_values_never_survive(entries in prop::collection::vec(entry(), 1..12)) {
        let e = engine("etam/gateway");
        let input: String = entries.iter().map(|(t, _)| t.as_str()).collect();
        let out = anonymize(&e, input.as_bytes());
        let out = String::from_utf8_lossy(&out);
        for (_, secrets) in &entries {
            for s in secrets {
                prop_assert!(!out.contains(s.as_str()), "« {} » a survécu dans :\n{}", s, out);
            }
        }
        let has_control = out.contains(char::from(0x1b)) || out.contains(char::from(b'\r'));
        prop_assert!(!has_control, "ESC ou CR dans la sortie");
    }

    #[test]
    fn output_is_never_more_sensitive_than_input(entries in prop::collection::vec(entry(), 1..8)) {
        let e = engine("kbrw/elixir");
        let input: String = entries.iter().map(|(t, _)| t.as_str()).collect();
        let out = anonymize(&e, input.as_bytes());
        // La sortie anonymisée ne déclenche plus aucun détecteur.
        prop_assert_eq!(findings(&out), 0, "sortie :\n{}", String::from_utf8_lossy(&out));
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_output_triggers_no_detector(lines in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..200), 0..20)) {
        let e = engine("kbrw/elixir");
        let mut input = Vec::new();
        for l in &lines {
            input.extend_from_slice(b"h.kbrw.fr  ");
            input.extend(l.iter().filter(|b| **b != b'\n'));
            input.push(b'\n');
        }
        let out = anonymize(&e, &input);
        prop_assert_eq!(findings(&out), 0, "sortie : {:?}", String::from_utf8_lossy(&out));
    }

    #[test]
    fn structured_garbage_never_panics(s in "[%{}\\[\\]\"',:=> \\\\a-z0-9#<>~\t\n@.-]{0,300}") {
        let e = engine("etam/gateway");
        let input = format!("h.kbrw.fr  10:00:00.000 [info]  {}\n", s.replace('\n', "\nh.kbrw.fr  "));
        let out = anonymize(&e, input.as_bytes());
        prop_assert_eq!(findings(&out), 0);
    }
}
