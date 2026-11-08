//! Reading the app's output: byte search and a small screen replayer.

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    rfind(haystack, needle).is_some()
}

pub fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

/// Replay `output`, drawn on a terminal of `size` (width, height), using the
/// cursor/erase sequences Ratatui's backend emits.
///
/// The fixture uses single-column text. This is a small screen reader for
/// these checks, not a general ANSI or Unicode terminal emulator.
pub fn render(output: &[u8], size: (u16, u16)) -> String {
    let (width, height) = (i64::from(size.0), i64::from(size.1));
    let blank = || vec![vec![' '; width as usize]; height as usize];
    let mut grid = blank();
    let (mut y, mut x) = (0_i64, 0_i64);
    let text: Vec<char> = String::from_utf8_lossy(output).chars().collect();
    let mut i = 0;
    while i < text.len() {
        let token = text[i];
        i += 1;
        if token == '\x1b' {
            if let Some((final_byte, parameters, end)) = csi(&text, i) {
                i = end;
                if parameters.starts_with('?') {
                    continue; // Private terminal modes, including cursor visibility.
                }
                let numbers: Vec<i64> = parameters
                    .split(';')
                    .map(|n| n.parse().unwrap_or(0))
                    .collect();
                let count = if numbers[0] == 0 { 1 } else { numbers[0] };
                let or_one = |n: i64| if n == 0 { 1 } else { n };
                match final_byte {
                    'H' | 'f' => {
                        y = or_one(numbers[0]) - 1;
                        x = numbers.get(1).map_or(1, |&n| or_one(n)) - 1;
                    }
                    'G' => x = count - 1,
                    'A' => y -= count,
                    'B' => y += count,
                    'C' => x += count,
                    'D' => x -= count,
                    'J' if matches!(numbers[0], 2 | 3) => grid = blank(),
                    'K' if (0..height).contains(&y) => {
                        let start = if matches!(numbers[0], 1 | 2) {
                            0
                        } else {
                            x.max(0)
                        };
                        let end = if matches!(numbers[0], 0 | 2) {
                            width
                        } else {
                            width.min(x + 1)
                        };
                        for cell in start.max(0)..end.min(width) {
                            grid[y as usize][cell as usize] = ' ';
                        }
                    }
                    _ => {}
                }
            } else if text.get(i).is_some_and(|&next| next != '\n') {
                i += 1; // Another two-character escape sequence.
            }
            continue;
        }
        match token {
            '\r' => x = 0,
            '\n' => y += 1,
            token if token >= ' ' => {
                if (0..height).contains(&y) && (0..width).contains(&x) {
                    grid[y as usize][x as usize] = token;
                }
                x += 1;
            }
            _ => {}
        }
    }
    grid.iter()
        .map(|row| row.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Parse a CSI sequence whose `[` starts at `start`, returning its final
/// character, its parameters, and the index after it.
fn csi(text: &[char], start: usize) -> Option<(char, String, usize)> {
    if text.get(start) != Some(&'[') {
        return None;
    }
    let mut end = start + 1;
    while text.get(end).is_some_and(|c| ('0'..='?').contains(c)) {
        end += 1;
    }
    let parameters_end = end;
    while text.get(end).is_some_and(|c| (' '..='/').contains(c)) {
        end += 1;
    }
    let final_byte = *text.get(end).filter(|c| ('@'..='~').contains(*c))?;
    let parameters = text[start + 1..parameters_end].iter().collect();
    Some((final_byte, parameters, end + 1))
}
