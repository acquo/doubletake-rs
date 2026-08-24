//! Probe: does WASAPI loopback capture produce frames in this session?
//! Prints the first few frame sizes and sample stats.

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match lumen_audio::start() {
        Err(e) => {
            println!("WASAPI capture FAILED: {e}");
            std::process::exit(1);
        }
        Ok(cap) => {
            println!("WASAPI capture started");
            let mut nonzero = 0usize;
            let mut total = 0usize;
            for i in 0..20 {
                match cap.recv_frame() {
                    Ok(frame) => {
                        let nz = frame.iter().filter(|v| **v != 0).count();
                        nonzero += nz;
                        total += frame.len();
                        if i < 3 {
                            println!(
                                "frame {i}: {} samples, nonzero={} first=[{:?}]",
                                frame.len(),
                                nz,
                                &frame[..frame.len().min(8)]
                            );
                        }
                    }
                    Err(e) => {
                        println!("frame {i}: recv error: {e}");
                        break;
                    }
                }
            }
            println!(
                "done: {} frames captured, {} samples, {} nonzero (silence={})",
                total / (352 * 2),
                total,
                nonzero,
                nonzero == 0
            );
        }
    }
}
