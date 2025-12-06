//! Admin command handlers for yggdrasil control interface.

use anyhow::Result;
use comfy_table::{Table, presets::UTF8_FULL_CONDENSED};
use yggdrasil::admin::{AdminClient, responses};

use crate::utils::{format_bytes, format_duration};

pub fn ctl_list(endpoint: &str, json: bool) -> Result<()> {
    let client = AdminClient::new(endpoint);
    let response = client.request("list", None)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response.response)?);
        return Ok(());
    }

    if let Some(data) = response.response {
        let list: responses::ListResponse = serde_json::from_value(data)?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL_CONDENSED);
        table.set_header(vec!["Command", "Arguments", "Description"]);

        for entry in list.list {
            let args = entry
                .fields
                .iter()
                .map(|f| format!("{}=...", f))
                .collect::<Vec<_>>()
                .join(", ");
            table.add_row(vec![entry.command, args, entry.description]);
        }

        println!("{}", table);
    }

    Ok(())
}

pub fn ctl_get_self(endpoint: &str, json: bool) -> Result<()> {
    let client = AdminClient::new(endpoint);
    let response = client.request("getSelf", None)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response.response)?);
        return Ok(());
    }

    if let Some(data) = response.response {
        let info: responses::GetSelfResponse = serde_json::from_value(data)?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL_CONDENSED);
        table.add_row(vec!["Build name:", &info.build_name]);
        table.add_row(vec!["Build version:", &info.build_version]);
        table.add_row(vec!["IPv6 address:", &info.ip_address]);
        table.add_row(vec!["IPv6 subnet:", &info.subnet]);
        table.add_row(vec!["Routing entries:", &info.routing_entries.to_string()]);
        table.add_row(vec!["Public key:", &info.public_key]);

        println!("{}", table);
    }

    Ok(())
}

pub fn ctl_get_peers(endpoint: &str, json: bool) -> Result<()> {
    let client = AdminClient::new(endpoint);
    let response = client.request("getPeers", None)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response.response)?);
        return Ok(());
    }

    if let Some(data) = response.response {
        let peers: responses::GetPeersResponse = serde_json::from_value(data)?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL_CONDENSED);
        table.set_header(vec!["URI", "State", "Dir", "IP Address", "Uptime", "RTT"]);

        for peer in peers.peers {
            let state = if peer.up { "Up" } else { "Down" };
            let dir = if peer.inbound { "In" } else { "Out" };
            let rtt = if peer.latency > 0 {
                format!("{:.2}ms", peer.latency as f64 / 1000.0)
            } else {
                "-".to_string()
            };
            let uptime = format_duration(peer.uptime as u64);

            table.add_row(vec![
                peer.uri,
                state.to_string(),
                dir.to_string(),
                peer.ip_address,
                uptime,
                rtt,
            ]);
        }

        println!("{}", table);
    }

    Ok(())
}

pub fn ctl_get_tree(endpoint: &str, json: bool) -> Result<()> {
    let client = AdminClient::new(endpoint);
    let response = client.request("getTree", None)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response.response)?);
        return Ok(());
    }

    if let Some(data) = response.response {
        let tree: responses::GetTreeResponse = serde_json::from_value(data)?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL_CONDENSED);
        table.set_header(vec!["Public Key", "IP Address", "Parent", "Sequence"]);

        for entry in tree.tree {
            table.add_row(vec![
                entry.public_key,
                entry.ip_address,
                entry.parent,
                entry.sequence.to_string(),
            ]);
        }

        println!("{}", table);
    }

    Ok(())
}

pub fn ctl_get_paths(endpoint: &str, json: bool) -> Result<()> {
    let client = AdminClient::new(endpoint);
    let response = client.request("getPaths", None)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response.response)?);
        return Ok(());
    }

    if let Some(data) = response.response {
        let paths: responses::GetPathsResponse = serde_json::from_value(data)?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL_CONDENSED);
        table.set_header(vec!["Public Key", "IP Address", "Path", "Sequence"]);

        for entry in paths.paths {
            let path_str = format!("{:?}", entry.path);
            table.add_row(vec![
                entry.public_key,
                entry.ip_address,
                path_str,
                entry.sequence.to_string(),
            ]);
        }

        println!("{}", table);
    }

    Ok(())
}

pub fn ctl_get_sessions(endpoint: &str, json: bool) -> Result<()> {
    let client = AdminClient::new(endpoint);
    let response = client.request("getSessions", None)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response.response)?);
        return Ok(());
    }

    if let Some(data) = response.response {
        let sessions: responses::GetSessionsResponse = serde_json::from_value(data)?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL_CONDENSED);
        table.set_header(vec!["Public Key", "IP Address", "Uptime", "RX", "TX"]);

        for entry in sessions.sessions {
            table.add_row(vec![
                entry.public_key,
                entry.ip_address,
                format_duration(entry.uptime as u64),
                format_bytes(entry.rx_bytes),
                format_bytes(entry.tx_bytes),
            ]);
        }

        println!("{}", table);
    }

    Ok(())
}

pub fn ctl_get_tun(endpoint: &str, json: bool) -> Result<()> {
    let client = AdminClient::new(endpoint);
    let response = client.request("getTUN", None)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response.response)?);
        return Ok(());
    }

    if let Some(data) = response.response {
        let tun: responses::GetTUNResponse = serde_json::from_value(data)?;

        let mut table = Table::new();
        table.load_preset(UTF8_FULL_CONDENSED);
        table.add_row(vec!["TUN enabled:", &tun.enabled.to_string()]);
        if tun.enabled {
            table.add_row(vec!["Interface name:", &tun.name]);
            table.add_row(vec!["MTU:", &tun.mtu.to_string()]);
        }

        println!("{}", table);
    }

    Ok(())
}

pub fn ctl_add_peer(endpoint: &str, uri: &str, interface: Option<&str>) -> Result<()> {
    let client = AdminClient::new(endpoint);
    let mut args = serde_json::json!({ "uri": uri });
    if let Some(intf) = interface {
        args["interface"] = serde_json::Value::String(intf.to_string());
    }
    let _response = client.request("addPeer", Some(args))?;
    println!("Peer added successfully");
    Ok(())
}

pub fn ctl_remove_peer(endpoint: &str, uri: &str, interface: Option<&str>) -> Result<()> {
    let client = AdminClient::new(endpoint);
    let mut args = serde_json::json!({ "uri": uri });
    if let Some(intf) = interface {
        args["interface"] = serde_json::Value::String(intf.to_string());
    }
    let _response = client.request("removePeer", Some(args))?;
    println!("Peer removed successfully");
    Ok(())
}

pub fn ctl_raw(endpoint: &str, command: &str, args: &[String]) -> Result<()> {
    let client = AdminClient::new(endpoint);

    let mut arg_map = serde_json::Map::new();
    for arg in args {
        if let Some((key, value)) = arg.split_once('=') {
            arg_map.insert(
                key.to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }

    let args = if arg_map.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(arg_map))
    };

    let response = client.request(command, args)?;
    println!("{}", serde_json::to_string_pretty(&response.response)?);
    Ok(())
}
