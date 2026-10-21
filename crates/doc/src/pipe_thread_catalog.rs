//! Finite internal pipe-thread data and checked nominal Rc profiles, in millimetres.
//! Data: Yamawa YEU23, printed pp.668 and707:
//! https://www.yamawa.eu/files/Yamawa_European_Catalogue_YEU23.pdf
//! G and Rp process recommendations are separate from basic thread dimensions.
//! Rc uses ISO7-1:1994 clause3.3/Figure5: its gauge plane is P/2 inside the face.
//! This module is not yet connected to Hole parsing or UI; Rc must never become a cylinder alias.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipeFamily {
    G,
    Rp,
    Rc,
}
impl PipeFamily {
    pub const ALL: [Self; 3] = [Self::G, Self::Rp, Self::Rc];
    pub fn label(self) -> &'static str {
        match self {
            Self::G => "G",
            Self::Rp => "Rp",
            Self::Rc => "Rc",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PipeSize {
    pub nominal: &'static str,
    pub tpi: u16,
    pub major: f64,
    pub pitch_diameter: f64,
    /// Basic minor diameter, at the gauge plane for Rc.
    pub minor: f64,
    pub g_drill: f64,
    pub g_bore: f64,
    pub rp_drill: f64,
    pub rp_bore: f64,
}

const SIZES: &[PipeSize] = &[
    PipeSize {
        nominal: "1/8",
        tpi: 28,
        major: 9.728,
        pitch_diameter: 9.147,
        minor: 8.566,
        g_drill: 8.75,
        g_bore: 8.78,
        rp_drill: 8.5,
        rp_bore: 8.55,
    },
    PipeSize {
        nominal: "1/4",
        tpi: 19,
        major: 13.157,
        pitch_diameter: 12.301,
        minor: 11.445,
        g_drill: 11.75,
        g_bore: 11.78,
        rp_drill: 11.4,
        rp_bore: 11.5,
    },
    PipeSize {
        nominal: "3/8",
        tpi: 19,
        major: 16.662,
        pitch_diameter: 15.806,
        minor: 14.95,
        g_drill: 15.25,
        g_bore: 15.28,
        rp_drill: 14.8,
        rp_bore: 14.9,
    },
    PipeSize {
        nominal: "1/2",
        tpi: 14,
        major: 20.955,
        pitch_diameter: 19.793,
        minor: 18.631,
        g_drill: 19.0,
        g_bore: 19.04,
        rp_drill: 18.5,
        rp_bore: 18.55,
    },
    PipeSize {
        nominal: "3/4",
        tpi: 14,
        major: 26.441,
        pitch_diameter: 25.279,
        minor: 24.117,
        g_drill: 24.5,
        g_bore: 24.52,
        rp_drill: 24.0,
        rp_bore: 24.1,
    },
    PipeSize {
        nominal: "1",
        tpi: 11,
        major: 33.249,
        pitch_diameter: 31.77,
        minor: 30.291,
        g_drill: 30.75,
        g_bore: 30.77,
        rp_drill: 30.2,
        rp_bore: 30.25,
    },
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PipeThread {
    family: PipeFamily,
    size: &'static PipeSize,
}
impl PipeThread {
    pub fn family(self) -> PipeFamily {
        self.family
    }
    pub fn size(self) -> &'static PipeSize {
        self.size
    }
    pub fn designation(self) -> String {
        format!("{} {}", self.family.label(), self.size.nominal)
    }
    pub fn pitch(self) -> f64 {
        25.4 / f64::from(self.size.tpi)
    }
    pub fn profile_degrees(self) -> f64 {
        55.0
    }
    /// Pilot drill and recommended process bore. Neither is an Rc finished-cone diameter.
    pub fn process_bore(self) -> Option<(f64, f64)> {
        match self.family {
            PipeFamily::G => Some((self.size.g_drill, self.size.g_bore)),
            PipeFamily::Rp => Some((self.size.rp_drill, self.size.rp_bore)),
            PipeFamily::Rc => None,
        }
    }
    pub fn rc_cone(self, depth: f64) -> Option<RcCone> {
        if self.family != PipeFamily::Rc || !depth.is_finite() {
            return None;
        }
        let gauge_depth = self.pitch() / 2.0;
        let face = self.size.minor + self.pitch() / 32.0;
        let end = face - depth / 16.0;
        if depth <= gauge_depth || !end.is_finite() || end <= 0.0 {
            return None;
        }
        Some(RcCone { face, gauge_depth, depth, end })
    }
}

pub fn pipe_thread_sizes() -> impl Iterator<Item = PipeThread> {
    PipeFamily::ALL.into_iter().flat_map(|family| SIZES.iter().map(move |size| PipeThread { family, size }))
}

pub fn parse_pipe_thread(text: &str) -> Option<PipeThread> {
    if text.len() > 80 {
        return None;
    }
    let mut words = text.split_whitespace();
    let family = match words.next()? {
        "G" | "BSPP" => PipeFamily::G,
        "Rp" => PipeFamily::Rp,
        "Rc" => PipeFamily::Rc,
        _ => return None,
    };
    let nominal = words.next()?;
    if words.next().is_some() {
        return None;
    }
    let size = SIZES.iter().find(|s| s.nominal == nominal)?;
    Some(PipeThread { family, size })
}

/// Nominal minor envelope; the inward depth coordinate starts at the workpiece face.
/// Diameter decreases by1/16 per millimetre, radius by1/32. No helical profile or tolerance claim.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RcCone {
    face: f64,
    gauge_depth: f64,
    depth: f64,
    end: f64,
}
impl RcCone {
    pub fn face_diameter(self) -> f64 {
        self.face
    }
    pub fn gauge_depth(self) -> f64 {
        self.gauge_depth
    }
    pub fn depth(self) -> f64 {
        self.depth
    }
    pub fn end_diameter(self) -> f64 {
        self.end
    }
    pub fn half_angle(self) -> f64 {
        (1.0_f64 / 32.0).atan()
    }
    pub fn diameter_at(self, z: f64) -> Option<f64> {
        (z.is_finite() && z >= 0.0 && z <= self.depth).then(|| self.face - z / 16.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    #[test]
    fn dimensions_and_process_references_match_the_source_tables() {
        for (nominal, tpi, major, pitch, minor, gd, gb, rd, rb) in [
            ("1/8", 28, 9.728, 9.147, 8.566, 8.75, 8.78, 8.5, 8.55),
            ("1/4", 19, 13.157, 12.301, 11.445, 11.75, 11.78, 11.4, 11.5),
            ("3/8", 19, 16.662, 15.806, 14.950, 15.25, 15.28, 14.8, 14.9),
            ("1/2", 14, 20.955, 19.793, 18.631, 19.0, 19.04, 18.5, 18.55),
            ("3/4", 14, 26.441, 25.279, 24.117, 24.5, 24.52, 24.0, 24.1),
            ("1", 11, 33.249, 31.770, 30.291, 30.75, 30.77, 30.2, 30.25),
        ] {
            for family in PipeFamily::ALL {
                let thread = parse_pipe_thread(&format!("{} {nominal}", family.label())).unwrap();
                let s = thread.size();
                assert_eq!((s.tpi, s.major, s.pitch_diameter, s.minor), (tpi, major, pitch, minor));
                assert_eq!(
                    thread.process_bore(),
                    match family {
                        PipeFamily::G => Some((gd, gb)),
                        PipeFamily::Rp => Some((rd, rb)),
                        PipeFamily::Rc => None,
                    }
                );
            }
        }
    }
    #[test]
    fn recognizes_internal_pipe_designations() {
        assert_eq!(pipe_thread_sizes().count(), 18);
        for family in ["G", "Rp", "Rc"] {
            for nominal in ["1/8", "1/4", "3/8", "1/2", "3/4", "1"] {
                let s = parse_pipe_thread(&format!("{family} {nominal}")).unwrap();
                assert_eq!(parse_pipe_thread(&s.designation()), Some(s));
                assert_eq!(s.profile_degrees(), 55.0);
            }
        }
        assert_eq!(parse_pipe_thread("BSPP 1/4").unwrap().designation(), "G 1/4");
        assert!(parse_pipe_thread(&" ".repeat(81)).is_none());
        for bad in ["NPT 1/4", "R 1/4", "Rc 6.35", "Rc 2/8", "G 1/4 junk", "Rc NaN", "Rp", "M6", "1/4-20 UNC"] {
            assert!(parse_pipe_thread(bad).is_none(), "{bad}");
        }
    }
    #[test]
    fn nominal_labels_and_process_bores_are_distinct() {
        let g = parse_pipe_thread("G 1/4").unwrap();
        let rp = parse_pipe_thread("Rp 1/4").unwrap();
        assert_eq!(g.size().major, 13.157);
        assert_ne!(g.size().major, 25.4 / 4.0);
        assert_eq!(g.process_bore(), Some((11.75, 11.78)));
        assert_eq!(rp.process_bore(), Some((11.4, 11.5)));
        assert!((g.pitch() - 25.4 / 19.0).abs() < 1e-12);
        assert!(parse_pipe_thread("Rc 1/4").unwrap().process_bore().is_none());
        assert!(g.rc_cone(10.0).is_none() && rp.rc_cone(10.0).is_none());
    }
    #[test]
    fn all_rc_sizes_follow_the_inside_gauge_plane_and_diameter_taper() {
        // Independent frozen arithmetic from the verified gauge-plane research, not face-based tap preparation.
        let expected = [
            ("1/8", 8.566, 8.594348214285715),
            ("1/4", 11.445, 11.486776315789474),
            ("3/8", 14.950, 14.991776315789473),
            ("1/2", 18.631, 18.687696428571428),
            ("3/4", 24.117, 24.17369642857143),
            ("1", 30.291, 30.36315909090909),
        ];
        for (nominal, minor, face) in expected {
            let s = parse_pipe_thread(&format!("Rc {nominal}")).unwrap();
            let c = s.rc_cone(10.0).unwrap();
            assert!((c.face_diameter() - face).abs() < 1e-12);
            assert!((c.diameter_at(c.gauge_depth()).unwrap() - minor).abs() < 1e-12);
            assert!((c.end_diameter() - (face - 0.625)).abs() < 1e-12);
            assert!((c.half_angle().tan() - 1.0 / 32.0).abs() < 1e-12);
            assert!(c.diameter_at(-1.0).is_none() && c.diameter_at(10.1).is_none());
            assert!(c.diameter_at(f64::NAN).is_none());
            for bad in [0.0, -1.0, s.pitch() / 2.0, 1e6, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
                assert!(s.rc_cone(bad).is_none());
            }
        }
    }
}
