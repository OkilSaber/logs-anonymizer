//! Import d'une proposition de configuration depuis `~/.ssh/config`, `~/.zshrc`
//! et l'historique du shell.

use serde::{Deserialize, Serialize};

use crate::config::{
    AuthConfig, BastionConfig, HostKeyPolicy, JumpMode, ServerConfig, DEFAULT_IDENTITY_FILE,
    DEFAULT_NC_COMMAND,
};

/// Ce que l'import propose : un bastion global et des serveurs de logs.
/// Rien n'est écrit ; l'application présente la proposition à cocher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportProposal {
    /// Bastion le plus utilisé par les serveurs trouvés.
    pub bastion: Option<BastionConfig>,
    /// Serveurs trouvés. `user`, `auth` et `bastion` ne sont renseignés que
    /// s'ils diffèrent de ceux du bastion global.
    pub servers: Vec<ServerConfig>,
}

/// Construit une proposition à partir du texte de `~/.ssh/config`, de
/// `~/.zshrc` et de l'historique du shell. Fonction pure : ne lit aucun fichier.
///
/// Sont retenus comme serveurs :
/// - les alias zsh dont le nom finit par `logs` et qui lancent `ssh <hôte>`
///   (ex. `alias etamsblogs='ssh syslogserver01.priv.etamadm-sb.kbrw.fr'`) ;
/// - les entrées `Host` littérales de la config SSH dont le nom ou le
///   `HostName` commence par `syslogserver` ;
/// - les commandes `ssh … syslogserver…` de l'historique : un serveur auquel on
///   s'est connecté à la main, sans alias. Rien d'autre n'est lu dans l'historique.
///
/// Pour chaque serveur, les blocs `Host` qui s'appliquent donnent `User`,
/// `IdentityFile`, `Port` et le bastion (`ProxyCommand ssh user@bastion "nc %h %p"`,
/// `ProxyCommand ssh -W %h:%p bastion` ou `ProxyJump`).
pub fn import_ssh_config(
    ssh_config_text: &str,
    zshrc_text: &str,
    history_text: &str,
) -> ImportProposal {
    let blocks = parse_ssh_config(ssh_config_text);

    // (alias zsh éventuel, invocation ssh)
    let mut candidates: Vec<(Option<String>, SshInvocation)> = Vec::new();
    for (alias, argv) in parse_log_aliases(zshrc_text) {
        if let Some(invocation) = parse_ssh_command(&argv) {
            candidates.push((Some(alias), invocation));
        }
    }
    for block in &blocks {
        for pattern in &block.patterns {
            if pattern.contains(['*', '?', '!']) {
                continue;
            }
            let resolved = resolve(&blocks, pattern);
            let hostname = resolved.hostname.as_deref().unwrap_or(pattern);
            if pattern.starts_with("syslogserver") || hostname.starts_with("syslogserver") {
                candidates.push((
                    None,
                    SshInvocation {
                        host: pattern.clone(),
                        ..Default::default()
                    },
                ));
            }
        }
    }
    // Une faute de frappe (`….kbrw.f`) est le début d'un hôte connu : on l'écarte.
    let typed = parse_history(history_text);
    let kept: Vec<SshInvocation> = typed
        .iter()
        .filter(|inv| {
            let longer = |other: &String| {
                other.len() > inv.host.len() && other.starts_with(inv.host.as_str())
            };
            !candidates.iter().any(|(_, c)| longer(&c.host))
                && !typed.iter().any(|t| longer(&t.host))
        })
        .cloned()
        .collect();
    candidates.extend(kept.into_iter().map(|inv| (None, inv)));

    struct Found {
        id: String,
        name: String,
        host: String,
        port: u16,
        user: String,
        identity_file: String,
        bastion: Option<BastionConfig>,
    }

    let mut found: Vec<Found> = Vec::new();
    for (alias, invocation) in candidates {
        let resolved = resolve(&blocks, &invocation.host);
        let host = resolved
            .hostname
            .clone()
            .unwrap_or_else(|| invocation.host.clone());
        if found.iter().any(|f| f.host == host) {
            continue;
        }
        let user = invocation
            .user
            .clone()
            .or_else(|| resolved.user.clone())
            .unwrap_or_default();
        let identity_file = invocation
            .identity
            .clone()
            .or_else(|| resolved.identity_file.clone())
            .unwrap_or_else(|| DEFAULT_IDENTITY_FILE.to_string());
        let bastion = bastion_for(&blocks, &invocation, &resolved, &user, &identity_file);
        let (mut id, name) = derive_id_name(&host, alias.as_deref());
        let base = id.clone();
        let mut n = 2;
        while found.iter().any(|f| f.id == id) {
            id = format!("{base}-{n}");
            n += 1;
        }
        found.push(Found {
            id,
            name,
            host,
            port: invocation.port.or(resolved.port).unwrap_or(22),
            user,
            identity_file,
            bastion,
        });
    }

    // Bastion global : le plus fréquent, le premier rencontré en cas d'égalité.
    let mut tally: Vec<(&BastionConfig, usize)> = Vec::new();
    for bastion in found.iter().filter_map(|f| f.bastion.as_ref()) {
        match tally.iter_mut().find(|(b, _)| *b == bastion) {
            Some((_, count)) => *count += 1,
            None => tally.push((bastion, 1)),
        }
    }
    let mut global: Option<(&BastionConfig, usize)> = None;
    for (bastion, count) in tally {
        if global.is_none_or(|(_, best)| count > best) {
            global = Some((bastion, count));
        }
    }
    let global: Option<BastionConfig> = global.map(|(b, _)| b.clone());

    let servers = found
        .iter()
        .map(|f| {
            let own_bastion = f.bastion.clone().filter(|b| Some(b) != global.as_ref());
            let reference = own_bastion.as_ref().or(global.as_ref());
            let auth = AuthConfig::Key {
                identity_file: f.identity_file.clone(),
            };
            let mut server = ServerConfig::new(f.id.clone(), f.name.clone(), f.host.clone());
            server.port = f.port;
            server.user = (!f.user.is_empty()
                && reference.map(|b| b.user.as_str()) != Some(f.user.as_str()))
            .then(|| f.user.clone());
            server.auth = (reference.map(|b| &b.auth) != Some(&auth)).then_some(auth);
            server.bastion = own_bastion;
            server
        })
        .collect();

    ImportProposal {
        bastion: global,
        servers,
    }
}

// ---------------------------------------------------------------------------
// ~/.ssh/config
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct HostBlock {
    patterns: Vec<String>,
    /// (clé en minuscules, valeur)
    options: Vec<(String, String)>,
}

#[derive(Debug, Default)]
struct Resolved {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    proxy_command: Option<String>,
    proxy_jump: Option<String>,
    server_alive_interval: Option<u64>,
    strict_host_key_checking: Option<String>,
}

fn parse_ssh_config(text: &str) -> Vec<HostBlock> {
    // Les options placées avant le premier `Host` valent pour tous les hôtes.
    let mut blocks = vec![HostBlock {
        patterns: vec!["*".to_string()],
        options: Vec::new(),
    }];
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let split_at = line
            .find(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or(line.len());
        let key = line[..split_at].to_ascii_lowercase();
        let mut value = line[split_at..]
            .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
            .trim();
        if value.len() >= 2
            && value.starts_with('"')
            && value.ends_with('"')
            && value.matches('"').count() == 2
        {
            value = &value[1..value.len() - 1];
        }
        match key.as_str() {
            "host" => blocks.push(HostBlock {
                patterns: value.split_whitespace().map(str::to_string).collect(),
                options: Vec::new(),
            }),
            // Les blocs `Match` ne sont pas interprétés : leurs options sont ignorées.
            "match" => blocks.push(HostBlock::default()),
            _ => {
                if let Some(block) = blocks.last_mut() {
                    block.options.push((key, value.to_string()));
                }
            }
        }
    }
    blocks
}

/// Motif à la `ssh_config` : `*` et `?`.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn go(p: &[u8], t: &[u8]) -> bool {
        match p.split_first() {
            None => t.is_empty(),
            Some((b'*', rest)) => (0..=t.len()).any(|i| go(rest, &t[i..])),
            Some((b'?', rest)) => !t.is_empty() && go(rest, &t[1..]),
            Some((c, rest)) => t.first() == Some(c) && go(rest, &t[1..]),
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

fn block_matches(block: &HostBlock, host: &str) -> bool {
    let mut positive = false;
    for pattern in &block.patterns {
        if let Some(negated) = pattern.strip_prefix('!') {
            if glob_match(negated, host) {
                return false;
            }
        } else if glob_match(pattern, host) {
            positive = true;
        }
    }
    positive
}

/// Comme ssh : pour chaque option, la première valeur rencontrée gagne.
fn resolve(blocks: &[HostBlock], host: &str) -> Resolved {
    let mut r = Resolved::default();
    for block in blocks.iter().filter(|b| block_matches(b, host)) {
        for (key, value) in &block.options {
            match key.as_str() {
                "hostname" if r.hostname.is_none() => r.hostname = Some(value.replace("%h", host)),
                "user" if r.user.is_none() => r.user = Some(value.clone()),
                "port" if r.port.is_none() => r.port = value.parse().ok(),
                "identityfile" if r.identity_file.is_none() => {
                    r.identity_file = Some(value.clone())
                }
                "proxycommand" if r.proxy_command.is_none() => {
                    r.proxy_command = Some(value.clone())
                }
                "proxyjump" if r.proxy_jump.is_none() => r.proxy_jump = Some(value.clone()),
                "serveraliveinterval" if r.server_alive_interval.is_none() => {
                    r.server_alive_interval = value.parse().ok()
                }
                "stricthostkeychecking" if r.strict_host_key_checking.is_none() => {
                    r.strict_host_key_checking = Some(value.to_ascii_lowercase())
                }
                _ => {}
            }
        }
    }
    for opt in [&mut r.proxy_command, &mut r.proxy_jump] {
        if opt
            .as_deref()
            .is_some_and(|v| v.eq_ignore_ascii_case("none"))
        {
            *opt = None;
        }
    }
    r
}

// ---------------------------------------------------------------------------
// Commandes ssh et alias zsh
// ---------------------------------------------------------------------------

/// Découpe une ligne comme un shell : apostrophes, guillemets, antislash.
/// S'arrête à un `#` en début de mot.
fn shell_split(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    current.push(q);
                }
            }
            '"' => {
                in_word = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => match chars.peek() {
                            Some(&n) if matches!(n, '"' | '\\' | '$' | '`') => {
                                current.push(n);
                                chars.next();
                            }
                            _ => current.push('\\'),
                        },
                        _ => current.push(q),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next() {
                    current.push(n);
                }
            }
            '#' if !in_word => break,
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                current.push(c);
            }
        }
    }
    if in_word {
        words.push(current);
    }
    words
}

/// Alias zsh dont le nom finit par `logs` : (nom, commande découpée).
fn parse_log_aliases(zshrc: &str) -> Vec<(String, Vec<String>)> {
    let mut aliases = Vec::new();
    for line in zshrc.lines() {
        let Some(rest) = line.trim().strip_prefix("alias ") else {
            continue;
        };
        let rest = rest.trim_start();
        let rest = rest.strip_prefix("-g ").unwrap_or(rest).trim_start();
        let Some((name, value)) = rest.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !name.ends_with("logs") || name.contains(char::is_whitespace) {
            continue;
        }
        // La valeur est un seul mot shell (souvent entre apostrophes).
        let Some(command) = shell_split(value).into_iter().next() else {
            continue;
        };
        aliases.push((name.to_string(), shell_split(&command)));
    }
    aliases
}

/// Commandes `ssh … syslogserver…` de l'historique du shell, de la plus ancienne
/// à la plus récente. Les autres lignes ne sont pas regardées.
fn parse_history(history: &str) -> Vec<SshInvocation> {
    let mut found = Vec::new();
    for line in history.lines() {
        if !line.contains("syslogserver") {
            continue;
        }
        // Historique étendu de zsh : `: 1700000000:0;commande`.
        let command = line
            .strip_prefix(": ")
            .and_then(|rest| rest.split_once(';'))
            .map_or(line, |(_, command)| command);
        let words = shell_split(command);
        for (i, word) in words.iter().enumerate() {
            if word != "ssh" {
                continue;
            }
            let Some(invocation) = parse_ssh_command(&words[i..]) else {
                continue;
            };
            let host = &invocation.host;
            let plausible = host.starts_with("syslogserver")
                && host.contains('.')
                && !host.ends_with('.')
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
            if plausible {
                found.push(invocation);
            }
        }
    }
    found
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct SshInvocation {
    user: Option<String>,
    host: String,
    port: Option<u16>,
    identity: Option<String>,
    jump: Option<String>,
    /// `-W hôte:port` : transfert stdio, donc `direct-tcpip`.
    stdio_forward: bool,
    remote_command: Vec<String>,
}

/// Options de `ssh` qui prennent un argument.
const SSH_OPTIONS_WITH_ARG: &str = "BbcDEeFIiJLlmOopQRSWw";

fn parse_ssh_command(argv: &[String]) -> Option<SshInvocation> {
    let (program, mut args) = argv.split_first()?;
    if program != "ssh" && !program.ends_with("/ssh") {
        return None;
    }
    let mut inv = SshInvocation::default();
    let mut destination = None;
    while let Some((arg, rest)) = args.split_first() {
        args = rest;
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            destination = Some(arg.clone());
            break;
        };
        // `-p 22`, `-p22`, ou un groupe de drapeaux sans argument (`-tt`, `-A`).
        let letter = flags.chars().next()?;
        if !SSH_OPTIONS_WITH_ARG.contains(letter) {
            continue;
        }
        let attached = &flags[letter.len_utf8()..];
        let value = if attached.is_empty() {
            let (value, rest) = args.split_first()?;
            args = rest;
            value.clone()
        } else {
            attached.to_string()
        };
        match letter {
            'p' => inv.port = value.parse().ok(),
            'i' => inv.identity = Some(value),
            'l' => inv.user = Some(value),
            'J' => inv.jump = Some(value),
            'W' => inv.stdio_forward = true,
            _ => {}
        }
    }
    let destination = destination?;
    let destination = destination.strip_prefix("ssh://").unwrap_or(&destination);
    let (user, hostport) = match destination.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()), host),
        None => (None, destination),
    };
    if user.is_some() {
        inv.user = user;
    }
    inv.host = hostport.to_string();
    inv.remote_command = args.to_vec();
    (!inv.host.is_empty()).then_some(inv)
}

/// `[user@]hôte[:port]` d'un `ProxyJump` (premier saut seulement).
fn parse_jump(spec: &str) -> Option<(Option<String>, String, Option<u16>)> {
    let first = spec.split(',').next()?.trim();
    let first = first.strip_prefix("ssh://").unwrap_or(first);
    let (user, hostport) = match first.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()), host),
        None => (None, first),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => (host, port.parse().ok()),
        _ => (hostport, None),
    };
    (!host.is_empty()).then(|| (user, host.to_string(), port))
}

/// Déduit le bastion d'un serveur à partir de `-J`, `ProxyCommand` ou `ProxyJump`.
fn bastion_for(
    blocks: &[HostBlock],
    invocation: &SshInvocation,
    resolved: &Resolved,
    server_user: &str,
    server_identity: &str,
) -> Option<BastionConfig> {
    // (user, hôte, port, mode, commande nc)
    let (user, host, port, mode, nc_command) = if let Some(jump) = &invocation.jump {
        let (user, host, port) = parse_jump(jump)?;
        (user, host, port, JumpMode::DirectTcpip, None)
    } else if let Some(command) = &resolved.proxy_command {
        let proxy = parse_ssh_command(&shell_split(command))?;
        let remote = proxy.remote_command.join(" ");
        if remote.contains("%h") {
            let nc = remote.replace("%h", "{host}").replace("%p", "{port}");
            (proxy.user, proxy.host, proxy.port, JumpMode::Nc, Some(nc))
        } else if proxy.stdio_forward {
            (
                proxy.user,
                proxy.host,
                proxy.port,
                JumpMode::DirectTcpip,
                None,
            )
        } else {
            return None;
        }
    } else if let Some(jump) = &resolved.proxy_jump {
        let (user, host, port) = parse_jump(jump)?;
        (user, host, port, JumpMode::DirectTcpip, None)
    } else {
        return None;
    };

    // La config SSH s'applique aussi au bastion lui-même.
    let own = resolve(blocks, &host);
    let mut bastion = BastionConfig::new(
        own.hostname.clone().unwrap_or(host),
        user.or(own.user).unwrap_or_else(|| server_user.to_string()),
    );
    bastion.port = port.or(own.port).unwrap_or(22);
    bastion.auth = AuthConfig::Key {
        identity_file: own
            .identity_file
            .unwrap_or_else(|| server_identity.to_string()),
    };
    bastion.mode = mode;
    bastion.nc_command = nc_command.unwrap_or_else(|| DEFAULT_NC_COMMAND.to_string());
    bastion.host_key_policy = match resolved.strict_host_key_checking.as_deref() {
        Some("no") | Some("off") => HostKeyPolicy::Insecure,
        _ => HostKeyPolicy::Tofu,
    };
    bastion.keepalive_secs = resolved.server_alive_interval.unwrap_or(60);
    Some(bastion)
}

/// `syslogserver01.priv.etamadm-sb.kbrw.fr` → (`etam-sb`, `Etam — sandbox`).
fn derive_id_name(host: &str, alias: Option<&str>) -> (String, String) {
    let labels: Vec<&str> = host.split('.').collect();
    let tenant = labels
        .iter()
        .position(|l| *l == "priv")
        .and_then(|i| labels.get(i + 1))
        .filter(|_| labels[0].starts_with("syslogserver"));
    if let Some(tenant) = tenant {
        let (base, sandbox) = match tenant.strip_suffix("-sb") {
            Some(base) => (base, true),
            None => (*tenant, false),
        };
        let client = base
            .strip_suffix("adm")
            .filter(|c| !c.is_empty())
            .unwrap_or(base);
        let number = labels[0].trim_start_matches("syslogserver");
        let mut id = client.to_string();
        if sandbox {
            id.push_str("-sb");
        }
        if !matches!(number, "" | "1" | "01") {
            id.push('-');
            id.push_str(number);
        }
        let mut display = String::new();
        let mut chars = client.chars();
        if let Some(first) = chars.next() {
            display.extend(first.to_uppercase());
            display.push_str(chars.as_str());
        }
        let name = format!("{display} — {}", if sandbox { "sandbox" } else { "prod" });
        return (id, name);
    }
    let id = alias
        .and_then(|a| a.strip_suffix("logs"))
        .filter(|a| !a.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| host.replace('.', "-"));
    (id, host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bloc `Host *.priv.*` typique, avec rebond par `nc`.
    const SSH_CONFIG: &str = r#"
Host *.priv.*
  User jdupont
  IdentityFile ~/.ssh/id_rsa
  StrictHostKeyChecking no
  UserKnownHostsFile=/dev/null
  ProxyCommand ssh jdupont@access01.cloud.kbrwadventure.com "nc %h %p"
  ServerAliveInterval 60
"#;

    const ZSHRC: &str = r#"
export PATH="$HOME/bin:$PATH"
alias ll='ls -la'
alias etamsblogs='ssh syslogserver01.priv.etamadm-sb.kbrw.fr'
alias jarlogs="ssh syslogserver01.priv.jaradm.kbrw.fr"   # prod
alias gitlogs='git log --oneline'
alias psareturnsblogs='ssh syslogserver02.priv.psareturnadm-sb.kbrw.fr'
"#;

    #[test]
    fn bloc_du_prompt_et_alias_logs() {
        let proposal = import_ssh_config(SSH_CONFIG, ZSHRC, "");

        let bastion = proposal.bastion.expect("bastion détecté");
        assert_eq!(bastion.host, "access01.cloud.kbrwadventure.com");
        assert_eq!(bastion.user, "jdupont");
        assert_eq!(bastion.port, 22);
        assert_eq!(bastion.mode, JumpMode::Nc);
        assert_eq!(bastion.nc_command, "nc {host} {port}");
        assert_eq!(bastion.host_key_policy, HostKeyPolicy::Insecure);
        assert_eq!(bastion.keepalive_secs, 60);
        assert_eq!(
            bastion.auth,
            AuthConfig::Key {
                identity_file: "~/.ssh/id_rsa".into()
            }
        );

        let summary: Vec<(&str, &str, &str)> = proposal
            .servers
            .iter()
            .map(|s| (s.id.as_str(), s.name.as_str(), s.host.as_str()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (
                    "etam-sb",
                    "Etam — sandbox",
                    "syslogserver01.priv.etamadm-sb.kbrw.fr"
                ),
                ("jar", "Jar — prod", "syslogserver01.priv.jaradm.kbrw.fr"),
                (
                    "psareturn-sb-02",
                    "Psareturn — sandbox",
                    "syslogserver02.priv.psareturnadm-sb.kbrw.fr"
                ),
            ]
        );
        for server in &proposal.servers {
            assert_eq!(server.port, 22);
            assert_eq!(server.user, None, "même utilisateur que le bastion");
            assert_eq!(server.auth, None, "même clé que le bastion");
            assert_eq!(server.bastion, None, "bastion global");
            assert_eq!(server.path_pattern, crate::config::DEFAULT_PATH_PATTERN);
        }
    }

    #[test]
    fn hosts_syslogserver_de_la_config_ssh() {
        let config = r#"
ServerAliveInterval 30

Host etam-logs
  HostName syslogserver01.priv.etamadm.kbrw.fr
  User autre
  Port 2222
  IdentityFile ~/.ssh/id_ed25519

Host syslogserver01.priv.fpxadm-sb.kbrw.fr

Host web01.priv.etamadm.kbrw.fr
  User web

Host bastion
  HostName access01.cloud.kbrwadventure.com
  User jump
  IdentityFile ~/.ssh/bastion_key

Host *.priv.*
  User jdupont
  ProxyJump bastion
"#;
        let proposal = import_ssh_config(config, "", "");
        let bastion = proposal.bastion.expect("bastion détecté");
        assert_eq!(bastion.host, "access01.cloud.kbrwadventure.com");
        assert_eq!(bastion.user, "jump");
        assert_eq!(bastion.mode, JumpMode::DirectTcpip);
        assert_eq!(bastion.host_key_policy, HostKeyPolicy::Tofu);
        assert_eq!(bastion.keepalive_secs, 30);
        assert_eq!(
            bastion.auth,
            AuthConfig::Key {
                identity_file: "~/.ssh/bastion_key".into()
            }
        );

        assert_eq!(proposal.servers.len(), 2, "{:?}", proposal.servers);
        // `etam-logs` ne correspond pas à `*.priv.*` : pas de bastion pour lui.
        let etam = &proposal.servers[0];
        assert_eq!(etam.id, "etam");
        assert_eq!(etam.host, "syslogserver01.priv.etamadm.kbrw.fr");
        assert_eq!(etam.port, 2222);
        assert_eq!(etam.user.as_deref(), Some("autre"));
        assert_eq!(
            etam.auth,
            Some(AuthConfig::Key {
                identity_file: "~/.ssh/id_ed25519".into()
            })
        );
        let fpx = &proposal.servers[1];
        assert_eq!(fpx.id, "fpx-sb");
        assert_eq!(fpx.user.as_deref(), Some("jdupont"));
        assert_eq!(
            fpx.auth,
            Some(AuthConfig::Key {
                identity_file: DEFAULT_IDENTITY_FILE.into()
            })
        );
        assert_eq!(fpx.bastion, None);
    }

    #[test]
    fn bastion_propre_a_un_serveur() {
        let config = r#"
Host syslogserver01.priv.jaradm.kbrw.fr
  ProxyCommand ssh -p 2200 ops@autre-bastion.example "nc -w 5 %h %p"

Host *.priv.*
  User jdupont
  ProxyCommand ssh -W %h:%p jdupont@access01.cloud.kbrwadventure.com
"#;
        let zshrc = "alias etamlogs='ssh syslogserver01.priv.etamadm.kbrw.fr'\n\
                     alias fpxlogs='ssh -p 2022 moi@syslogserver01.priv.fpxadm.kbrw.fr'\n\
                     alias jarlogs='ssh syslogserver01.priv.jaradm.kbrw.fr'\n";
        let proposal = import_ssh_config(config, zshrc, "");
        let bastion = proposal.bastion.expect("bastion détecté");
        assert_eq!(bastion.host, "access01.cloud.kbrwadventure.com");
        assert_eq!(bastion.mode, JumpMode::DirectTcpip);

        let fpx = proposal.servers.iter().find(|s| s.id == "fpx").unwrap();
        assert_eq!(fpx.port, 2022);
        assert_eq!(fpx.user.as_deref(), Some("moi"));
        assert_eq!(fpx.bastion, None);

        let jar = proposal.servers.iter().find(|s| s.id == "jar").unwrap();
        let own = jar.bastion.as_ref().expect("bastion propre");
        assert_eq!(own.host, "autre-bastion.example");
        assert_eq!(own.port, 2200);
        assert_eq!(own.user, "ops");
        assert_eq!(own.mode, JumpMode::Nc);
        assert_eq!(own.nc_command, "nc -w 5 {host} {port}");
        assert_eq!(jar.user.as_deref(), Some("jdupont"));
    }

    #[test]
    fn serveurs_tapes_a_la_main_dans_l_historique() {
        let history = "\
: 1700000001:0;ssh syslogserver01.priv.bapifadm.kbrw.fr
: 1700000002:5;ssh syslogserver01.priv.bapifadm-sb.kbrw.fr
: 1700000003:0;ssh syslogserver01.priv.crfesadm-sb.kbrw.f
: 1700000004:0;ssh -p 2022 moi@syslogserver01.priv.crfesadm-sb.kbrw.fr
: 1700000005:0;ssh syslogserver01.priv.crfesadm.kbrw.fr 'ls /srv/syslog' && echo ok
: 1700000006:0;ssh syslogserver01.priv.etamadm-sb.kbrw.fr
: 1700000007:0;ssh etam-services01.priv.etam.kbrw.fr
: 1700000008:0;echo syslogserver01.priv.jaradm-sb.kbrw.fr
ssh syslogserver02.priv.totadm-sb.kbrw.fr
: 1700000009:0;ssh syslogserver01.priv.bapifadm.kbrw.fr
";
        let proposal = import_ssh_config(SSH_CONFIG, ZSHRC, history);
        let summary: Vec<(&str, &str)> = proposal
            .servers
            .iter()
            .map(|s| (s.id.as_str(), s.host.as_str()))
            .collect();
        assert_eq!(
            summary,
            vec![
                // Les alias d'abord ; `etam-sb` n'est pas répété.
                ("etam-sb", "syslogserver01.priv.etamadm-sb.kbrw.fr"),
                ("jar", "syslogserver01.priv.jaradm.kbrw.fr"),
                (
                    "psareturn-sb-02",
                    "syslogserver02.priv.psareturnadm-sb.kbrw.fr"
                ),
                ("bapif", "syslogserver01.priv.bapifadm.kbrw.fr"),
                ("bapif-sb", "syslogserver01.priv.bapifadm-sb.kbrw.fr"),
                ("crfes-sb", "syslogserver01.priv.crfesadm-sb.kbrw.fr"),
                ("crfes", "syslogserver01.priv.crfesadm.kbrw.fr"),
                ("tot-sb-02", "syslogserver02.priv.totadm-sb.kbrw.fr"),
            ]
        );
        let bapif = &proposal.servers[3];
        assert_eq!(bapif.name, "Bapif — prod");
        assert_eq!(bapif.bastion, None, "bastion global, par `Host *.priv.*`");
        assert_eq!(bapif.user, None);
        let crfes_sb = &proposal.servers[5];
        assert_eq!(crfes_sb.port, 2022);
        assert_eq!(crfes_sb.user.as_deref(), Some("moi"));
    }

    #[test]
    fn rien_a_importer() {
        let proposal = import_ssh_config("", "alias ll='ls'\n", "ls\n: 1700000000:0;ssh web01.priv.etam.kbrw.fr\n");
        assert_eq!(proposal.bastion, None);
        assert!(proposal.servers.is_empty());
    }

    #[test]
    fn decoupage_shell() {
        assert_eq!(
            shell_split(r#"ssh a@b "nc %h %p" 'x y' z\ w # commentaire"#),
            vec!["ssh", "a@b", "nc %h %p", "x y", "z w"]
        );
    }

    #[test]
    fn motifs_de_host() {
        assert!(glob_match(
            "*.priv.*",
            "syslogserver01.priv.etamadm-sb.kbrw.fr"
        ));
        assert!(!glob_match("*.priv.*", "access01.cloud.kbrwadventure.com"));
        assert!(glob_match("web0?", "web01"));
        let block = HostBlock {
            patterns: vec!["*.priv.*".into(), "!web*".into()],
            options: vec![],
        };
        assert!(block_matches(&block, "syslogserver01.priv.x.fr"));
        assert!(!block_matches(&block, "web01.priv.x.fr"));
    }
}
