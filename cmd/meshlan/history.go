package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type HistoryLocalPoint struct {
	At             time.Time `json:"at"`
	BytesReceived  uint64    `json:"bytesReceived"`
	BytesSent      uint64    `json:"bytesSent"`
	ServiceRunning bool      `json:"serviceRunning"`
	DirectCount    int       `json:"directCount"`
	RelayCount     int       `json:"relayCount"`
}

type HistoryPeerPoint struct {
	At              time.Time `json:"at"`
	Name            string    `json:"name"`
	Address         string    `json:"address"`
	Online          bool      `json:"online"`
	Reachable       bool      `json:"reachable"`
	PathMode        string    `json:"pathMode"`
	LatencyMs       int64     `json:"latencyMs"`
	Underlay        string    `json:"underlay,omitempty"`
	ServiceCount    int       `json:"serviceCount"`
	HealthyServices int       `json:"healthyServices"`
}

type HistoryEvent struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Peer   string    `json:"peer,omitempty"`
	Detail string    `json:"detail"`
}

type ClientHistoryResponse struct {
	From        time.Time                 `json:"from"`
	To          time.Time                 `json:"to"`
	Local       []HistoryLocalPoint       `json:"local"`
	Peers       []HistoryPeerPoint        `json:"peers"`
	Connections []ServiceConnectionRecord `json:"connections"`
	Events      []HistoryEvent            `json:"events"`
}

type ServerHistoryPoint struct {
	At             time.Time `json:"at"`
	Name           string    `json:"name"`
	Address        string    `json:"address"`
	Online         bool      `json:"online"`
	ServiceRunning bool      `json:"serviceRunning"`
	BytesReceived  uint64    `json:"bytesReceived"`
	BytesSent      uint64    `json:"bytesSent"`
	ClientVersion  string    `json:"clientVersion,omitempty"`
}

type ServerHistoryResponse struct {
	From   time.Time            `json:"from"`
	To     time.Time            `json:"to"`
	Peers  []ServerHistoryPoint `json:"peers"`
	Events []HistoryEvent       `json:"events"`
}

type historyStore struct {
	db *sql.DB
}

func openHistoryStore(path string) (*historyStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &historyStore{db: db}
	statements := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA synchronous=NORMAL`,
		`PRAGMA busy_timeout=5000`,
		`CREATE TABLE IF NOT EXISTS client_local_samples (
			id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ms INTEGER NOT NULL,
			rx INTEGER NOT NULL, tx INTEGER NOT NULL, service_running INTEGER NOT NULL,
			direct_count INTEGER NOT NULL, relay_count INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_client_local_ts ON client_local_samples(ts_ms)`,
		`CREATE TABLE IF NOT EXISTS client_peer_samples (
			id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ms INTEGER NOT NULL,
			name TEXT NOT NULL, address TEXT NOT NULL, online INTEGER NOT NULL, reachable INTEGER NOT NULL,
			path_mode TEXT NOT NULL, latency_ms INTEGER NOT NULL, underlay TEXT NOT NULL,
			service_count INTEGER NOT NULL, healthy_services INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_client_peer_ts_name ON client_peer_samples(ts_ms,name)`,
		`CREATE TABLE IF NOT EXISTS server_peer_samples (
			id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ms INTEGER NOT NULL,
			name TEXT NOT NULL, address TEXT NOT NULL, online INTEGER NOT NULL, service_running INTEGER NOT NULL,
			rx INTEGER NOT NULL, tx INTEGER NOT NULL, client_version TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_server_peer_ts_name ON server_peer_samples(ts_ms,name)`,
		`CREATE TABLE IF NOT EXISTS connection_summary (
			mapping_id TEXT NOT NULL, service_name TEXT NOT NULL, user_name TEXT NOT NULL,
			address TEXT NOT NULL, protocol TEXT NOT NULL, allowed INTEGER NOT NULL, active INTEGER NOT NULL,
			first_seen_ms INTEGER NOT NULL, last_seen_ms INTEGER NOT NULL,
			bytes_to_local INTEGER NOT NULL, bytes_to_peer INTEGER NOT NULL,
			PRIMARY KEY(mapping_id,address,allowed)
		)`,
		`CREATE TABLE IF NOT EXISTS history_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ms INTEGER NOT NULL,
			scope TEXT NOT NULL, kind TEXT NOT NULL, peer TEXT NOT NULL, detail TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_history_events_scope_ts ON history_events(scope,ts_ms)`,
		`CREATE TABLE IF NOT EXISTS ai_conversations (
			id TEXT PRIMARY KEY, title TEXT NOT NULL, created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ai_conversations_updated ON ai_conversations(updated_ms DESC)`,
		`CREATE TABLE IF NOT EXISTS ai_messages (
			id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES ai_conversations(id) ON DELETE CASCADE,
			role TEXT NOT NULL, content TEXT NOT NULL, plan_json TEXT NOT NULL, created_ms INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ai_messages_conversation ON ai_messages(conversation_id,created_ms)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, fmt.Errorf("初始化历史数据库失败: %w", err)
		}
	}
	// Active connections are process-local and cannot survive a client restart.
	// Reset stale values left by an interrupted reverse-proxy request or shutdown.
	if _, err := db.Exec(`UPDATE connection_summary SET active=0 WHERE active<>0`); err != nil {
		db.Close()
		return nil, fmt.Errorf("重置历史连接状态失败: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	return store, nil
}

func (s *historyStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func unixMillis(value time.Time) int64     { return value.UTC().UnixMilli() }
func fromUnixMillis(value int64) time.Time { return time.UnixMilli(value).UTC() }

func historySampleStride(count, maximum int) int {
	if count <= maximum || maximum < 1 {
		return 1
	}
	return (count + maximum - 1) / maximum
}

func (s *historyStore) RecordLocal(point HistoryLocalPoint) error {
	if s == nil {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO client_local_samples(ts_ms,rx,tx,service_running,direct_count,relay_count) VALUES(?,?,?,?,?,?)`,
		unixMillis(point.At), point.BytesReceived, point.BytesSent, point.ServiceRunning, point.DirectCount, point.RelayCount)
	return err
}

func (s *historyStore) RecordTopology(snapshot TopologySnapshot) error {
	if s == nil {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	statement, err := tx.Prepare(`INSERT INTO client_peer_samples(ts_ms,name,address,online,reachable,path_mode,latency_ms,underlay,service_count,healthy_services) VALUES(?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer statement.Close()
	for _, peer := range snapshot.Peers {
		if _, err := statement.Exec(unixMillis(snapshot.RefreshedAt), peer.Name, peer.Address, peer.Online, peer.Reachable, peer.PathMode, peer.LatencyMs, peer.Underlay, peer.ServiceCount, peer.HealthyServiceCount); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *historyStore) RecordServerPeer(peer PeerRecord, at time.Time, online bool) error {
	if s == nil {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO server_peer_samples(ts_ms,name,address,online,service_running,rx,tx,client_version) VALUES(?,?,?,?,?,?,?,?)`,
		unixMillis(at), peer.Name, peer.Address, online, peer.ServiceRunning, peer.BytesReceived, peer.BytesSent, peer.ClientVersion)
	return err
}

func (s *historyStore) RecordConnection(record ServiceConnectionRecord) error {
	if s == nil {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO connection_summary(mapping_id,service_name,user_name,address,protocol,allowed,active,first_seen_ms,last_seen_ms,bytes_to_local,bytes_to_peer)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(mapping_id,address,allowed) DO UPDATE SET service_name=excluded.service_name,user_name=excluded.user_name,protocol=excluded.protocol,active=excluded.active,last_seen_ms=excluded.last_seen_ms,bytes_to_local=excluded.bytes_to_local,bytes_to_peer=excluded.bytes_to_peer`,
		record.MappingID, record.ServiceName, record.UserName, record.Address, record.Protocol, record.Allowed, record.Active,
		unixMillis(record.FirstSeen), unixMillis(record.LastSeen), record.BytesToLocal, record.BytesToPeer)
	return err
}

func (s *historyStore) RecordEvent(scope, kind, peer, detail string, at time.Time) error {
	if s == nil {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO history_events(ts_ms,scope,kind,peer,detail) VALUES(?,?,?,?,?)`, unixMillis(at), scope, kind, peer, detail)
	return err
}

func historyWindow(hours int) (time.Time, time.Time, error) {
	if hours < 1 || hours > 24*30 {
		return time.Time{}, time.Time{}, errors.New("历史时间范围必须为 1 到 720 小时")
	}
	to := time.Now().UTC()
	return to.Add(-time.Duration(hours) * time.Hour), to, nil
}

func (s *historyStore) ClientHistory(hours int) (ClientHistoryResponse, error) {
	from, to, err := historyWindow(hours)
	result := ClientHistoryResponse{From: from, To: to, Local: []HistoryLocalPoint{}, Peers: []HistoryPeerPoint{}, Connections: []ServiceConnectionRecord{}, Events: []HistoryEvent{}}
	if err != nil || s == nil {
		return result, err
	}
	fromMs := unixMillis(from)
	var localCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM client_local_samples WHERE ts_ms>=?`, fromMs).Scan(&localCount); err != nil {
		return result, err
	}
	localStride := historySampleStride(localCount, 3998)
	rows, err := s.db.Query(`SELECT ts_ms,rx,tx,service_running,direct_count,relay_count FROM client_local_samples
		WHERE ts_ms>=? AND (id % ? = 0 OR id=(SELECT MIN(id) FROM client_local_samples WHERE ts_ms>=?) OR id=(SELECT MAX(id) FROM client_local_samples WHERE ts_ms>=?))
		ORDER BY ts_ms ASC LIMIT 4000`, fromMs, localStride, fromMs, fromMs)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var ts int64
		var point HistoryLocalPoint
		if err := rows.Scan(&ts, &point.BytesReceived, &point.BytesSent, &point.ServiceRunning, &point.DirectCount, &point.RelayCount); err != nil {
			rows.Close()
			return result, err
		}
		point.At = fromUnixMillis(ts)
		result.Local = append(result.Local, point)
	}
	rows.Close()
	var peerMomentCount int
	if err := s.db.QueryRow(`SELECT COUNT(DISTINCT ts_ms) FROM client_peer_samples WHERE ts_ms>=?`, fromMs).Scan(&peerMomentCount); err != nil {
		return result, err
	}
	peerStride := historySampleStride(peerMomentCount, 2998)
	rows, err = s.db.Query(`WITH ordered_moments AS (
		SELECT ts_ms, ROW_NUMBER() OVER (ORDER BY ts_ms ASC) AS rn FROM (SELECT DISTINCT ts_ms FROM client_peer_samples WHERE ts_ms>=?)
	), selected_moments AS (
		SELECT ts_ms FROM ordered_moments WHERE rn % ? = 0 OR rn=1 OR rn=(SELECT MAX(rn) FROM ordered_moments)
	)
	SELECT p.ts_ms,p.name,p.address,p.online,p.reachable,p.path_mode,p.latency_ms,p.underlay,p.service_count,p.healthy_services
	FROM client_peer_samples p JOIN selected_moments m ON m.ts_ms=p.ts_ms ORDER BY p.ts_ms ASC LIMIT 12000`, fromMs, peerStride)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var ts int64
		var point HistoryPeerPoint
		if err := rows.Scan(&ts, &point.Name, &point.Address, &point.Online, &point.Reachable, &point.PathMode, &point.LatencyMs, &point.Underlay, &point.ServiceCount, &point.HealthyServices); err != nil {
			rows.Close()
			return result, err
		}
		point.At = fromUnixMillis(ts)
		result.Peers = append(result.Peers, point)
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT mapping_id,service_name,user_name,address,protocol,allowed,active,first_seen_ms,last_seen_ms,bytes_to_local,bytes_to_peer FROM connection_summary ORDER BY last_seen_ms DESC LIMIT 1000`)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var first, last int64
		var record ServiceConnectionRecord
		if err := rows.Scan(&record.MappingID, &record.ServiceName, &record.UserName, &record.Address, &record.Protocol, &record.Allowed, &record.Active, &first, &last, &record.BytesToLocal, &record.BytesToPeer); err != nil {
			rows.Close()
			return result, err
		}
		record.FirstSeen, record.LastSeen = fromUnixMillis(first), fromUnixMillis(last)
		result.Connections = append(result.Connections, record)
	}
	rows.Close()
	result.Events, err = s.events("client", from, 1000)
	return result, err
}

func (s *historyStore) ServerHistory(hours int) (ServerHistoryResponse, error) {
	from, to, err := historyWindow(hours)
	result := ServerHistoryResponse{From: from, To: to, Peers: []ServerHistoryPoint{}, Events: []HistoryEvent{}}
	if err != nil || s == nil {
		return result, err
	}
	rows, err := s.db.Query(`SELECT ts_ms,name,address,online,service_running,rx,tx,client_version FROM server_peer_samples WHERE ts_ms>=? ORDER BY ts_ms ASC LIMIT 12000`, unixMillis(from))
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var ts int64
		var point ServerHistoryPoint
		if err := rows.Scan(&ts, &point.Name, &point.Address, &point.Online, &point.ServiceRunning, &point.BytesReceived, &point.BytesSent, &point.ClientVersion); err != nil {
			rows.Close()
			return result, err
		}
		point.At = fromUnixMillis(ts)
		result.Peers = append(result.Peers, point)
	}
	rows.Close()
	result.Events, err = s.events("server", from, 1000)
	return result, err
}

func (s *historyStore) events(scope string, from time.Time, limit int) ([]HistoryEvent, error) {
	rows, err := s.db.Query(`SELECT ts_ms,kind,peer,detail FROM history_events WHERE scope=? AND ts_ms>=? ORDER BY ts_ms DESC LIMIT ?`, scope, unixMillis(from), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []HistoryEvent{}
	for rows.Next() {
		var ts int64
		var event HistoryEvent
		if err := rows.Scan(&ts, &event.Kind, &event.Peer, &event.Detail); err != nil {
			return nil, err
		}
		event.At = fromUnixMillis(ts)
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *historyStore) Cleanup(retention time.Duration) error {
	if s == nil {
		return nil
	}
	cutoff := unixMillis(time.Now().UTC().Add(-retention))
	for _, statement := range []string{
		`DELETE FROM client_local_samples WHERE ts_ms < ?`,
		`DELETE FROM client_peer_samples WHERE ts_ms < ?`,
		`DELETE FROM server_peer_samples WHERE ts_ms < ?`,
		`DELETE FROM history_events WHERE ts_ms < ?`,
	} {
		if _, err := s.db.Exec(statement, cutoff); err != nil {
			return err
		}
	}
	return nil
}
