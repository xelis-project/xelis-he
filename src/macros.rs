
macro_rules! make_add_variants {
    ($lhs:ty, $rhs:ty, Output = $out:ty) => {
        impl<'b> Add<&'b $rhs> for $lhs {
            type Output = $out;
            fn add(self, rhs: &'b $rhs) -> $out {
                &self + rhs
            }
        }

        impl<'a> Add<$rhs> for &'a $lhs {
            type Output = $out;
            fn add(self, rhs: $rhs) -> $out {
                self + &rhs
            }
        }

        impl Add<$rhs> for $lhs {
            type Output = $out;
            fn add(self, rhs: $rhs) -> $out {
                &self + &rhs
            }
        }

        impl AddAssign<$rhs> for $lhs {
            fn add_assign(&mut self, rhs: $rhs) {
                *self = &*self + &rhs;
            }
        }
    };
}

macro_rules! make_sub_variants {
    ($lhs:ty, $rhs:ty, Output = $out:ty) => {
        impl<'b> Sub<&'b $rhs> for $lhs {
            type Output = $out;
            fn sub(self, rhs: &'b $rhs) -> $out {
                &self - rhs
            }
        }

        impl<'a> Sub<$rhs> for &'a $lhs {
            type Output = $out;
            fn sub(self, rhs: $rhs) -> $out {
                self - &rhs
            }
        }

        impl Sub<$rhs> for $lhs {
            type Output = $out;
            fn sub(self, rhs: $rhs) -> $out {
                &self - &rhs
            }
        }

        impl SubAssign<$rhs> for $lhs {
            fn sub_assign(&mut self, rhs: $rhs) {
                *self = &*self - &rhs;
            }
        }
    };
}
