use base64::{engine::general_purpose::STANDARD, Engine};
use proxylane_protocol::cache::{CacheConfig, PayloadCache};
use proxylane_protocol::{Analyzer, Connection, Direction, Limits, Output, Protocol};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
};

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Input {
    CacheStats,
    CacheStatus {
        cache_id: u64,
    },
    CacheRead {
        cache_id: u64,
        direction: Direction,
        offset: u64,
        length: usize,
    },
    CacheDecode {
        cache_id: u64,
        direction: Direction,
    },
    Open {
        connection: Connection,
        protocol: Protocol,
    },
    Data {
        connection_id: String,
        direction: Direction,
        offset: u64,
        data_base64: String,
    },
    Eof {
        connection_id: String,
        direction: Direction,
        clean: bool,
    },
    Close {
        connection_id: String,
    },
}
fn write(outputs: Vec<Output>, writer: &mut impl Write) -> Result<(), String> {
    let has_output = !outputs.is_empty();
    for output in outputs {
        serde_json::to_writer(&mut *writer, &output).map_err(|e| e.to_string())?;
        writeln!(writer).map_err(|e| e.to_string())?;
    }
    if has_output {
        writer.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn run(
    reader: &mut dyn BufRead,
    writer: &mut impl Write,
    cache: Option<&PayloadCache>,
) -> Result<(), String> {
    let mut connections = BTreeMap::<String, Analyzer>::new();
    let mut number = 0;
    loop {
        let mut line = Vec::new();
        // Read until newline without ever allocating an unbounded JSON line.
        loop {
            let buffer = reader.fill_buf().map_err(|e| e.to_string())?;
            if buffer.is_empty() {
                break;
            }
            let count = buffer
                .iter()
                .position(|&b| b == b'\n')
                .map_or(buffer.len(), |i| i + 1);
            if line.len() + count > 2 * 1024 * 1024 {
                return Err(format!("line {} exceeds 2 MiB", number + 1));
            }
            line.extend_from_slice(&buffer[..count]);
            reader.consume(count);
            if line.last() == Some(&b'\n') {
                break;
            }
        }
        if line.is_empty() {
            break;
        }
        number += 1;
        let input: Input =
            serde_json::from_slice(&line).map_err(|e| format!("line {number}: {e}"))?;
        let outputs = match input {
            Input::CacheStats
            | Input::CacheStatus { .. }
            | Input::CacheRead { .. }
            | Input::CacheDecode { .. } => {
                let result = (|| -> Result<serde_json::Value, String> {
                    let cache = cache.ok_or("payload cache disabled")?;
                    Ok(match input {
                        Input::CacheStats => {
                            serde_json::json!({ "type": "cache_stats", "stats": cache.stats()? })
                        }
                        Input::CacheStatus { cache_id } => {
                            serde_json::json!({ "type": "cache_status", "cache_id": cache_id, "cache": cache.status(cache_id)? })
                        }
                        Input::CacheRead {
                            cache_id,
                            direction,
                            offset,
                            length,
                        } => {
                            serde_json::json!({ "type": "cache_payload", "payload": cache.read(cache_id, direction, offset, length)? })
                        }
                        Input::CacheDecode {
                            cache_id,
                            direction,
                        } => {
                            serde_json::json!({ "type": "cache_payload", "payload": cache.decode(cache_id, direction, 4 * 1024 * 1024)? })
                        }
                        _ => unreachable!(),
                    })
                })();
                let value = result.unwrap_or_else(
                    |error| serde_json::json!({ "type": "cache_error", "error": error }),
                );
                serde_json::to_writer(&mut *writer, &value).map_err(|e| e.to_string())?;
                writeln!(writer)
                    .and_then(|_| writer.flush())
                    .map_err(|e| e.to_string())?;
                Vec::new()
            }
            Input::Open {
                connection,
                protocol,
            } => {
                if connections.contains_key(&connection.id) {
                    return Err(format!("line {number}: duplicate connection"));
                }
                if connections.len() >= 8 {
                    return Err("active connection limit (8)".into());
                }
                if connection.id.len() > 256 || connection.destination.len() > 2048 {
                    return Err("connection metadata limit".into());
                }
                let id = connection.id.clone();
                let analyzer = match cache {
                    Some(cache) => Analyzer::with_cache(
                        connection,
                        protocol,
                        Limits::default(),
                        cache.clone(),
                    )?,
                    None => Analyzer::new(connection, protocol, Limits::default())?,
                };
                connections.insert(id, analyzer);
                Vec::new()
            }
            Input::Data {
                connection_id,
                direction,
                offset,
                data_base64,
            } => {
                let bytes = STANDARD
                    .decode(data_base64)
                    .map_err(|e| format!("line {number}: {e}"))?;
                connections
                    .get_mut(&connection_id)
                    .ok_or("unknown connection")?
                    .push(direction, offset, &bytes)
            }
            Input::Eof {
                connection_id,
                direction,
                clean,
            } => connections
                .get_mut(&connection_id)
                .ok_or("unknown connection")?
                .eof(direction, clean),
            Input::Close { connection_id } => connections
                .remove(&connection_id)
                .ok_or("unknown connection")?
                .close(),
        };
        write(outputs, writer)?;
    }
    for analyzer in connections.values_mut() {
        write(analyzer.close(), writer)?;
    }
    writer.flush().map_err(|e| e.to_string())
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!("ProxyLane protocol reconstruction proof of concept\nUsage: proxylane-protocol [OPTIONS] [events.jsonl]\nReads JSONL from file or stdin, writes JSONL to stdout.\nTemporary payload cache enabled by default; removed on exit.\nOptions: --no-cache, --cache-root PATH, --cache-entry-bytes N,\n         --cache-total-bytes N, --cache-queue-chunks N, --cache-max-entries N\nSee src/ProxyLaneProtocol/README.md for the event schema.");
        return;
    }
    let result = (|| {
        let mut config = CacheConfig::default();
        let mut enabled = true;
        let mut input = None;
        let mut arguments = args.iter();
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--no-cache" => enabled = false,
                "--cache-root" => {
                    config.root = arguments.next().ok_or("missing cache root")?.into()
                }
                "--cache-entry-bytes"
                | "--cache-total-bytes"
                | "--cache-queue-chunks"
                | "--cache-max-entries" => {
                    let value = arguments
                        .next()
                        .ok_or("missing cache limit")?
                        .parse::<u64>()
                        .map_err(|_| "invalid cache limit")?;
                    match argument.as_str() {
                        "--cache-entry-bytes" => config.entry_bytes = value,
                        "--cache-total-bytes" => config.total_bytes = value,
                        "--cache-queue-chunks" => {
                            config.queue_chunks =
                                value.try_into().map_err(|_| "queue limit overflow")?
                        }
                        _ => {
                            config.max_entries =
                                value.try_into().map_err(|_| "entry count limit overflow")?
                        }
                    }
                }
                _ if argument.starts_with('-') => {
                    return Err(format!("unknown option: {argument}"))
                }
                _ if input.is_none() => input = Some(argument),
                _ => return Err("expected at most one input path".into()),
            }
        }
        let mut reader: Box<dyn BufRead> = if let Some(path) = input {
            Box::new(io::BufReader::new(
                std::fs::File::open(path).map_err(|e| e.to_string())?,
            ))
        } else {
            Box::new(io::BufReader::new(io::stdin()))
        };
        let cache = if enabled {
            Some(PayloadCache::new(config)?)
        } else {
            None
        };
        if let Some(cache) = &cache {
            eprintln!("Temporary payload cache: {}", cache.directory().display());
            let startup = cache.stats()?;
            if startup.recovered_runs != 0 {
                eprintln!("Removed {} abandoned cache run(s)", startup.recovered_runs);
            }
            for warning in startup.warnings {
                eprintln!("Cache cleanup warning: {warning}");
            }
        }
        let result = run(
            &mut *reader,
            &mut io::BufWriter::new(io::stdout().lock()),
            cache.as_ref(),
        );
        let cleanup = cache.as_ref().map_or(Ok(()), PayloadCache::shutdown);
        if let Err(error) = &cleanup {
            eprintln!("{error}");
        }
        result.and(cleanup)
    })();
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
