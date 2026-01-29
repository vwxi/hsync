use crate::diff;

pub(crate) struct DiffBox {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

pub(crate) struct Snake {
    sx: i32,
    sy: i32,
    fx: i32,
    fy: i32,
}

impl DiffBox {
    fn width(&self) -> i32 {
        self.right - self.left
    }

    fn height(&self) -> i32 {
        self.bottom - self.top
    }

    fn size(&self) -> i32 {
        self.width() + self.height()
    }

    fn delta(&self) -> i32 {
        self.width() - self.height()
    }
}

pub struct Diff {}

impl Diff {
    fn forwards(diff_box: &DiffBox, vf: &mut [i32], vb: &mut [i32], d: i32) -> Option<Snake> {
        for k in (-d..d).step_by(2) {
            let c = k - diff_box.delta();
        }

        None
    }

    fn backwards(diff_box: &DiffBox, vf: &mut [i32], vb: &mut [i32], d: i32) -> Option<Snake> {
        None
    }

    fn midpoint(diff_box: DiffBox) -> Option<Snake> {
        if diff_box.size() == 0 {
            return None;
        }

        let max = diff_box.size() / 2;
        let mut vf = vec![2 * max + 1, 0];
        vf[1] = diff_box.left;
        let mut vb = vec![2 * max + 1, 0];
        vb[1] = diff_box.bottom;

        for d in 0..max {
            if let Some(snake) = Diff::forwards(&diff_box, &mut vf, &mut vb, d)
                .or_else(|| Diff::backwards(&diff_box, &mut vf, &mut vb, d))
            {
                return Some(snake);
            }
        }

        None
    }
}
