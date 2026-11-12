//! Résolution des chevauchements entre candidats au remplacement.
//!
//! Tri par priorité décroissante, puis par longueur décroissante (le plus englobant).
//! Un candidat est accepté s'il ne chevauche rien d'accepté ; contenu dans un accepté,
//! il est écarté, sauf si la règle englobante l'autorise à percer (`keep_inner`) ;
//! un chevauchement partiel fusionne les deux plages, qui seront masquées en bloc.
//!
//! Un candidat qui remplace toute sa plage absorbe ceux qu'il contient, même plus
//! prioritaires : sinon ce qui entoure le contenu resterait en clair alors qu'une règle
//! demandait de masquer la valeur entière.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cand {
    pub start: u32,
    pub end: u32,
    pub prio: i32,
    pub rule: u32,
    pub order: u32,
    /// Le remplacement doit être mis entre guillemets.
    pub quote: bool,
    pub field: Option<(u32, u32)>,
}

#[derive(Clone, Debug)]
pub struct Accepted {
    pub cand: Cand,
    /// Candidats autorisés à percer ce remplacement, triés par position.
    pub holes: Vec<Cand>,
    /// Issu d'une fusion de chevauchements partiels : à masquer en bloc.
    pub merged: bool,
}

fn overlaps(a: &Cand, b: &Cand) -> bool {
    a.start < b.end && b.start < a.end
}

fn contains(outer: &Cand, inner: &Cand) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

/// `keep_inner(règle englobante, règle contenue)` dit si la seconde peut percer la première.
/// `replaces(règle)` dit si la règle remplace sa plage (tout sauf `keep`).
/// `shadowed(règle)` est appelé pour chaque candidat écarté.
pub fn resolve(
    cands: &mut [Cand],
    keep_inner: impl Fn(u32, u32) -> bool,
    replaces: impl Fn(u32) -> bool,
    mut shadowed: impl FnMut(u32),
) -> Vec<Accepted> {
    cands.sort_by(|a, b| {
        b.prio
            .cmp(&a.prio)
            .then((b.end - b.start).cmp(&(a.end - a.start)))
            .then(a.start.cmp(&b.start))
            .then(a.order.cmp(&b.order))
    });
    let mut acc: Vec<Accepted> = Vec::with_capacity(cands.len());
    for c in cands.iter() {
        let hits: Vec<usize> = acc.iter().enumerate().filter(|(_, a)| overlaps(&a.cand, c)).map(|(i, _)| i).collect();
        if hits.is_empty() {
            acc.push(Accepted { cand: *c, holes: Vec::new(), merged: false });
            continue;
        }
        if hits.len() == 1 && contains(&acc[hits[0]].cand, c) {
            let a = &mut acc[hits[0]];
            let identical = a.cand.start == c.start && a.cand.end == c.end;
            if !a.merged && !identical && keep_inner(a.cand.rule, c.rule) && !a.holes.iter().any(|h| overlaps(h, c)) {
                a.holes.push(*c);
            } else {
                shadowed(c.rule);
            }
            continue;
        }
        if hits.iter().all(|&i| contains(c, &acc[i].cand)) {
            // Englobant de priorité inférieure. S'il remplace sa plage, il absorbe ce qu'il
            // contient ; une valeur gardée (`keep`) à l'intérieur, elle, l'emporte.
            let absorbs = replaces(c.rule) && hits.iter().all(|&i| acc[i].merged || replaces(acc[i].cand.rule));
            if !absorbs {
                shadowed(c.rule);
                continue;
            }
            let mut outer = Accepted { cand: *c, holes: Vec::new(), merged: false };
            for &i in hits.iter().rev() {
                let inner = acc.remove(i);
                if !inner.merged && keep_inner(c.rule, inner.cand.rule) {
                    outer.holes.push(inner.cand);
                } else if !inner.merged {
                    shadowed(inner.cand.rule);
                }
            }
            acc.push(outer);
            continue;
        }
        // Chevauchement partiel : on fusionne tout ce qui se touche.
        let mut merged = *c;
        loop {
            let before = acc.len();
            acc.retain(|a| {
                if overlaps(&a.cand, &merged) {
                    merged.start = merged.start.min(a.cand.start);
                    merged.end = merged.end.max(a.cand.end);
                    false
                } else {
                    true
                }
            });
            if acc.len() == before {
                break;
            }
        }
        merged.quote = false;
        merged.field = None;
        acc.push(Accepted { cand: merged, holes: Vec::new(), merged: true });
    }
    acc.sort_by_key(|a| a.cand.start);
    for a in &mut acc {
        a.holes.sort_by_key(|h| h.start);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(start: u32, end: u32, prio: i32, rule: u32) -> Cand {
        Cand { start, end, prio, rule, order: rule, quote: false, field: None }
    }

    /// (début, fin, règle, règles des trous, fusionné)
    type Row = (u32, u32, u32, Vec<u32>, bool);

    /// Règle 9 : `keep`. Les autres remplacent leur plage.
    const KEEP: u32 = 9;

    fn run(mut cands: Vec<Cand>, inner_ok: &[(u32, u32)]) -> (Vec<Row>, Vec<u32>) {
        let mut shadowed = Vec::new();
        let acc = resolve(&mut cands, |o, i| inner_ok.contains(&(o, i)), |r| r != KEEP, |r| shadowed.push(r));
        (
            acc.iter().map(|a| (a.cand.start, a.cand.end, a.cand.rule, a.holes.iter().map(|h| h.rule).collect(), a.merged)).collect(),
            shadowed,
        )
    }

    #[test]
    fn disjoint_candidates_are_all_accepted_in_order() {
        let (acc, sh) = run(vec![c(20, 30, 100, 1), c(0, 10, 200, 2)], &[]);
        assert_eq!(acc, vec![(0, 10, 2, vec![], false), (20, 30, 1, vec![], false)]);
        assert!(sh.is_empty());
    }

    #[test]
    fn priority_then_most_enclosing() {
        // Même priorité : l'englobant gagne, le contenu est écarté.
        let (acc, sh) = run(vec![c(5, 10, 100, 1), c(0, 20, 100, 2)], &[]);
        assert_eq!(acc, vec![(0, 20, 2, vec![], false)]);
        assert_eq!(sh, vec![1]);
        // Le contenu a une priorité supérieure, mais l'englobant remplace toute la valeur :
        // il l'absorbe, pour ne rien laisser en clair autour.
        let (acc, sh) = run(vec![c(5, 10, 300, 1), c(0, 20, 100, 2)], &[]);
        assert_eq!(acc, vec![(0, 20, 2, vec![], false)]);
        assert_eq!(sh, vec![1]);
        // Sauf si la règle englobante l'autorise à percer : il devient un trou.
        let (acc, sh) = run(vec![c(5, 10, 300, 1), c(0, 20, 100, 2)], &[(2, 1)]);
        assert_eq!(acc, vec![(0, 20, 2, vec![1], false)]);
        assert!(sh.is_empty());
        // Une valeur gardée à l'intérieur l'emporte sur un englobant moins prioritaire…
        let (acc, sh) = run(vec![c(5, 10, 300, KEEP), c(0, 20, 100, 2)], &[]);
        assert_eq!(acc, vec![(5, 10, KEEP, vec![], false)]);
        assert_eq!(sh, vec![2]);
        // …et un `keep` englobant ne fait pas disparaître un remplacement plus prioritaire.
        let (acc, sh) = run(vec![c(5, 10, 300, 1), c(0, 20, 100, KEEP)], &[]);
        assert_eq!(acc, vec![(5, 10, 1, vec![], false)]);
        assert_eq!(sh, vec![KEEP]);
        // Même plage : la priorité la plus haute gagne.
        let (acc, sh) = run(vec![c(0, 10, 150, 1), c(0, 10, 210, 2)], &[]);
        assert_eq!(acc, vec![(0, 10, 2, vec![], false)]);
        assert_eq!(sh, vec![1]);
    }

    #[test]
    fn keep_inner_punches_a_hole() {
        let (acc, sh) = run(vec![c(0, 40, 240, 1), c(0, 23, 100, 2), c(30, 35, 50, 3)], &[(1, 2)]);
        assert_eq!(acc, vec![(0, 40, 1, vec![2], false)]);
        assert_eq!(sh, vec![3]);
    }

    #[test]
    fn partial_overlap_is_merged() {
        let (acc, _) = run(vec![c(0, 10, 200, 1), c(5, 15, 100, 2), c(14, 20, 50, 3), c(40, 50, 10, 4)], &[]);
        assert_eq!(acc, vec![(0, 20, 3, vec![], true), (40, 50, 4, vec![], false)]);
    }
}
