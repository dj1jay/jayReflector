/**
@file    TrunkLink.cpp
@brief   Server-to-server trunk link — jayReflector edition
@date    2026-04-06

Based on GeuReflector by IW1GEU.
Extended by DJ1JAY for FM-Funknetz / jayReflector.
Wire protocol fully compatible with GeuReflector.
*/

#include <iostream>
#include <sstream>
#include <cassert>
#include <random>
#include <cerrno>
#include <cstring>
#include <ctime>

#include <AsyncConfig.h>
#include <AsyncTcpConnection.h>

#include "TrunkLink.h"
#include "TgFilter.h"
#include "ReflectorMsg.h"
#include "Reflector.h"
#include "TGHandler.h"
#include "ReflectorClient.h"
#include <json/json.h>

using namespace std;
using namespace Async;
using namespace sigc;


static std::vector<std::string> splitPrefixes(const std::string& s)
{
  std::vector<std::string> result;
  std::istringstream ss(s);
  std::string token;
  while (std::getline(ss, token, ','))
  {
    token.erase(0, token.find_first_not_of(" \t"));
    token.erase(token.find_last_not_of(" \t") + 1);
    if (!token.empty()) result.push_back(token);
  }
  return result;
}

static std::string joinPrefixes(const std::vector<std::string>& v)
{
  std::string result;
  for (const auto& p : v) { if (!result.empty()) result += ','; result += p; }
  return result;
}


/****************************************************************************
 * TrunkLink public methods
 ****************************************************************************/

TrunkLink::TrunkLink(Reflector* reflector, Async::Config& cfg,
                     const std::string& section)
  : m_reflector(reflector), m_cfg(cfg), m_section(section),
    m_peer_id(section),   // default: peer_id = section name (GeuReflector compat)
    m_mqtt_name(section), // default: mqtt_name = section name
    m_peer_port(5302), m_priority(0), m_peer_priority(0),
    m_heartbeat_timer(1000, Timer::TYPE_PERIODIC, false)
{
  std::random_device rd;
  std::mt19937 rng(rd());
  std::uniform_int_distribution<uint32_t> dist;
  m_priority = dist(rng);

  m_con.connected.connect(mem_fun(*this, &TrunkLink::onConnected));
  m_con.disconnected.connect(mem_fun(*this, &TrunkLink::onDisconnected));
  m_con.frameReceived.connect(mem_fun(*this, &TrunkLink::onFrameReceived));
  m_con.setMaxFrameSize(ReflectorMsg::MAX_POSTAUTH_FRAME_SIZE);

  m_heartbeat_timer.expired.connect(
      mem_fun(*this, &TrunkLink::heartbeatTick));
}


TrunkLink::~TrunkLink(void)
{
  for (uint32_t tg : m_peer_active_tgs)
    TGHandler::instance()->clearTrunkTalkerForTG(tg);
  m_peer_active_tgs.clear();
}


bool TrunkLink::initialize(void)
{
  if (!m_cfg.getValue(m_section, "HOST", m_peer_host) || m_peer_host.empty())
  {
    cerr << "*** ERROR[" << m_section << "]: Missing HOST" << endl;
    return false;
  }

  m_cfg.getValue(m_section, "PORT", m_peer_port);

  if (!m_cfg.getValue(m_section, "SECRET", m_secret) || m_secret.empty())
  {
    cerr << "*** ERROR[" << m_section << "]: Missing SECRET" << endl;
    return false;
  }

  // PEER_ID — explicit identifier sent in MsgTrunkHello.
  // If not set, defaults to section name (backward compatible with GeuReflector).
  std::string peer_id_str;
  if (m_cfg.getValue(m_section, "PEER_ID", peer_id_str) && !peer_id_str.empty())
  {
    m_peer_id = peer_id_str;
  }

  // MQTT_NAME — subtopic name used in MQTT publishing.
  // e.g. MQTT_NAME=nc1 → topic: svxreflector/trunk/nc1/TRUNK_NC2NC1
  // If not set, defaults to section name.
  std::string mqtt_name_str;
  if (m_cfg.getValue(m_section, "MQTT_NAME", mqtt_name_str) && !mqtt_name_str.empty())
  {
    m_mqtt_name = mqtt_name_str;
  }

  std::string local_prefix_str;
  m_cfg.getValue("GLOBAL", "LOCAL_PREFIX", local_prefix_str);
  m_local_prefix = splitPrefixes(local_prefix_str);
  if (m_local_prefix.empty())
  {
    cerr << "*** ERROR: Missing or empty LOCAL_PREFIX in [GLOBAL]" << endl;
    return false;
  }

  std::string remote_prefix_str;
  if (!m_cfg.getValue(m_section, "REMOTE_PREFIX", remote_prefix_str) ||
      remote_prefix_str.empty())
  {
    cerr << "*** ERROR[" << m_section << "]: Missing REMOTE_PREFIX" << endl;
    return false;
  }
  m_remote_prefix = splitPrefixes(remote_prefix_str);

  // BLACKLIST_TGS — flexible filter: exact, prefix (24*), range (2427-2438)
  std::string blacklist_str;
  if (m_cfg.getValue(m_section, "BLACKLIST_TGS", blacklist_str) && !blacklist_str.empty())
  {
    m_blacklist_filter = TgFilter::parse(blacklist_str);
    if (!m_blacklist_filter.empty())
      std::cout << m_section << ": Blacklisted TGs: "
                << m_blacklist_filter.toString() << std::endl;
  }

  // ALLOW_TGS — flexible whitelist: exact, prefix (24*), range (2427-2438)
  std::string allow_str;
  if (m_cfg.getValue(m_section, "ALLOW_TGS", allow_str) && !allow_str.empty())
  {
    m_allow_filter = TgFilter::parse(allow_str);
    if (!m_allow_filter.empty())
      std::cout << m_section << ": Allowed TGs (whitelist): "
                << m_allow_filter.toString() << std::endl;
  }

  // TG_MAP — bidirectional TG mapping: peer_tg:local_tg,peer_tg2:local_tg2
  // Example: TG_MAP=1:2624123,2:2624124
  std::string tgmap_str;
  if (m_cfg.getValue(m_section, "TG_MAP", tgmap_str))
  {
    std::istringstream ss(tgmap_str);
    std::string pair;
    while (std::getline(ss, pair, ','))
    {
      auto colon = pair.find(':');
      if (colon == std::string::npos) continue;
      try
      {
        uint32_t peer_tg  = std::stoul(pair.substr(0, colon));
        uint32_t local_tg = std::stoul(pair.substr(colon + 1));
        m_tg_map_in[peer_tg]   = local_tg;   // incoming: peer→local
        m_tg_map_out[local_tg] = peer_tg;    // outgoing: local→peer
      }
      catch (...) {}
    }
    if (!m_tg_map_in.empty())
    {
      std::cout << m_section << ": TG mapping:";
      for (const auto& kv : m_tg_map_in)
        std::cout << " " << kv.first << "↔" << kv.second;
      std::cout << std::endl;
    }
  }

  // TRUNK_DEBUG
  std::string debug_str;
  if (m_cfg.getValue("GLOBAL", "TRUNK_DEBUG", debug_str))
    m_debug = (debug_str == "1" || debug_str == "true" || debug_str == "yes");

  cout << m_section << ": Trunk to " << m_peer_host << ":" << m_peer_port
       << " peer_id=" << m_peer_id
       << " local=" << joinPrefixes(m_local_prefix)
       << " remote=" << joinPrefixes(m_remote_prefix)
       << (m_blacklist_filter.empty() ? "" : " [blacklist active]")
       << (m_allow_filter.empty() ? "" : " [whitelist active]")
       << (m_debug ? " [debug]" : "") << endl;

  m_con.addStaticSRVRecord(0, 0, 0, m_peer_port, m_peer_host);
  m_con.setReconnectMinTime(2000);
  m_con.setReconnectMaxTime(30000);
  m_con.connect();

  return true;
}


bool TrunkLink::isBlacklisted(uint32_t tg) const
{
  return m_blacklist_filter.matches(tg) && !m_blacklist_filter.empty();
}


bool TrunkLink::isAllowed(uint32_t tg) const
{
  if (m_allow_filter.empty()) return true;
  return m_allow_filter.matches(tg);
}


bool TrunkLink::isSharedTG(uint32_t tg) const
{
  if (isBlacklisted(tg)) return false;
  if (!isAllowed(tg)) return false;

  const std::string s = std::to_string(tg);
  size_t best_remote_len = 0;
  for (const auto& prefix : m_remote_prefix)
  {
    if (s.size() >= prefix.size() &&
        s.compare(0, prefix.size(), prefix) == 0 &&
        prefix.size() > best_remote_len)
    {
      best_remote_len = prefix.size();
    }
  }
  if (best_remote_len == 0) return false;

  for (const auto& prefix : m_all_prefixes)
  {
    if (prefix.size() > best_remote_len &&
        s.size() >= prefix.size() &&
        s.compare(0, prefix.size(), prefix) == 0)
    {
      return false;
    }
  }
  return true;
}


bool TrunkLink::isOwnedTG(uint32_t tg) const
{
  if (isBlacklisted(tg)) return false;
  if (!isAllowed(tg)) return false;
  const std::string s = std::to_string(tg);
  for (const auto& prefix : m_local_prefix)
  {
    if (s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0)
      return true;
  }
  for (const auto& prefix : m_remote_prefix)
  {
    if (s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0)
      return true;
  }
  return false;
}


bool TrunkLink::isPeerInterestedTG(uint32_t tg) const
{
  if (isBlacklisted(tg)) return false;
  auto it = m_peer_interested_tgs.find(tg);
  if (it == m_peer_interested_tgs.end()) return false;
  return (std::time(nullptr) - it->second) < PEER_INTEREST_TIMEOUT_S;
}


bool TrunkLink::isActive(void) const
{
  return isOutboundReady() || isInboundReady();
}

bool TrunkLink::isOutboundReady(void) const
{
  return m_con.isConnected() && m_ob_hello_received;
}

bool TrunkLink::isInboundReady(void) const
{
  return m_inbound_con != nullptr && m_ib_hello_received;
}


void TrunkLink::muteCallsign(const std::string& callsign)
{
  m_muted_callsigns.insert(callsign);
  cout << m_section << ": Muted callsign '" << callsign << "'" << endl;
}

void TrunkLink::unmuteCallsign(const std::string& callsign)
{
  m_muted_callsigns.erase(callsign);
  cout << m_section << ": Unmuted callsign '" << callsign << "'" << endl;
}

bool TrunkLink::isCallsignMuted(const std::string& callsign) const
{
  return m_muted_callsigns.count(callsign) > 0;
}


Json::Value TrunkLink::statusJson(void) const
{
  Json::Value obj(Json::objectValue);
  obj["host"]               = m_peer_host;
  obj["port"]               = m_peer_port;
  obj["peer_id"]            = m_peer_id;
  obj["connected"]          = isActive();
  obj["outbound_connected"] = m_con.isConnected();
  obj["outbound_hello"]     = m_ob_hello_received;
  obj["inbound_connected"]  = (m_inbound_con != nullptr);
  obj["inbound_hello"]      = m_ib_hello_received;

  Json::Value local_arr(Json::arrayValue);
  for (const auto& p : m_local_prefix) local_arr.append(p);
  obj["local_prefix"] = local_arr;

  Json::Value remote_arr(Json::arrayValue);
  for (const auto& p : m_remote_prefix) remote_arr.append(p);
  obj["remote_prefix"] = remote_arr;

  if (!m_blacklist_filter.empty())
  {
    Json::Value bl(Json::arrayValue);
    // blacklist stored as TgFilter - show as string
    bl.append(m_blacklist_filter.toString());
    obj["blacklist_tgs"] = bl;
  }

  // Statistics
  Json::Value stats(Json::objectValue);
  stats["bytes_rx"]    = (Json::UInt64)m_stat_bytes_rx;
  stats["bytes_tx"]    = (Json::UInt64)m_stat_bytes_tx;
  stats["frames_rx"]   = (Json::UInt64)m_stat_frames_rx;
  stats["frames_tx"]   = (Json::UInt64)m_stat_frames_tx;
  stats["reconnects"]  = m_stat_reconnects;
  obj["stats"] = stats;

  // Muted callsigns
  if (!m_muted_callsigns.empty())
  {
    Json::Value muted(Json::arrayValue);
    for (const auto& cs : m_muted_callsigns) muted.append(cs);
    obj["muted"] = muted;
  }

  // Active trunk talkers
  Json::Value talkers(Json::objectValue);
  const auto& trunk_map = TGHandler::instance()->trunkTalkersSnapshot();
  for (const auto& kv : trunk_map)
  {
    if (isSharedTG(kv.first) || m_reflector->isClusterTG(kv.first))
      talkers[std::to_string(kv.first)] = kv.second;
  }
  obj["active_talkers"] = talkers;

  return obj;
}


void TrunkLink::acceptInboundConnection(Async::FramedTcpConnection* con,
                                         const MsgTrunkHello& hello)
{
  if (m_inbound_con != nullptr)
  {
    cerr << "*** WARNING[" << m_section
         << "]: Already have inbound — rejecting new one from "
         << con->remoteHost() << endl;
    con->disconnect();
    return;
  }

  m_inbound_con     = con;
  m_peer_priority   = hello.priority();
  m_ib_hello_received = true;
  m_ib_hb_tx_cnt    = HEARTBEAT_TX_CNT_RESET;
  m_ib_hb_rx_cnt    = HEARTBEAT_RX_CNT_RESET;
  m_heartbeat_timer.setEnable(true);
  m_yielded_tgs.clear();
  m_debug_frame_cnt = 0;

  con->frameReceived.connect(mem_fun(*this, &TrunkLink::onFrameReceived));

  cout << m_section << ": Accepted inbound from " << con->remoteHost()
       << ":" << con->remotePort()
       << " peer='" << hello.id() << "' priority=" << m_peer_priority << endl;

  if (m_debug)
    cout << m_section << " [DEBUG]: ob_connected=" << m_con.isConnected()
         << " ob_hello=" << m_ob_hello_received << endl;

  // Reply on inbound with section name for matching
  sendMsgOnInbound(MsgTrunkHello(m_section, joinPrefixes(m_local_prefix),
                                  m_priority, m_secret));
}


void TrunkLink::onInboundDisconnected(Async::FramedTcpConnection* con,
    Async::FramedTcpConnection::DisconnectReason reason)
{
  if (con != m_inbound_con) return;

  cout << m_section << ": Inbound trunk connection lost" << endl;

  m_inbound_con       = nullptr;
  m_ib_hello_received = false;
  m_ib_hb_tx_cnt      = 0;
  m_ib_hb_rx_cnt      = 0;

  clearPeerTalkerState();

  if (!m_con.isConnected())
    m_heartbeat_timer.setEnable(false);
}


void TrunkLink::onLocalTalkerStart(uint32_t tg, const std::string& callsign)
{
  if (!isActive() || isBlacklisted(tg)) return;
  if (!isSharedTG(tg) && !m_reflector->isClusterTG(tg) &&
      !isPeerInterestedTG(tg)) return;
  uint32_t peer_tg = mapTgOut(tg);
  if (peer_tg != tg && m_debug)
    cout << m_section << " [DEBUG]: TG map out " << tg << " -> " << peer_tg << endl;
  sendMsg(MsgTrunkTalkerStart(peer_tg, callsign));
}

void TrunkLink::onLocalTalkerStop(uint32_t tg)
{
  if (!isActive() || isBlacklisted(tg)) return;
  if (!isSharedTG(tg) && !m_reflector->isClusterTG(tg) &&
      !isPeerInterestedTG(tg)) return;
  if (m_yielded_tgs.count(tg)) return;
  sendMsg(MsgTrunkTalkerStop(mapTgOut(tg)));
}

void TrunkLink::onLocalAudio(uint32_t tg, const std::vector<uint8_t>& audio)
{
  if (!isActive() || isBlacklisted(tg)) return;
  if (!isSharedTG(tg) && !m_reflector->isClusterTG(tg) &&
      !isPeerInterestedTG(tg)) return;
  if (m_yielded_tgs.count(tg)) return;
  sendMsg(MsgTrunkAudio(mapTgOut(tg), audio));
}

void TrunkLink::onLocalFlush(uint32_t tg)
{
  if (!isActive() || isBlacklisted(tg)) return;
  if (!isSharedTG(tg) && !m_reflector->isClusterTG(tg) &&
      !isPeerInterestedTG(tg)) return;
  sendMsg(MsgTrunkFlush(mapTgOut(tg)));
}


/****************************************************************************
 * TrunkLink private methods
 ****************************************************************************/

void TrunkLink::onConnected(void)
{
  cout << m_section << ": Outbound connected to "
       << m_con.remoteHost() << ":" << m_con.remotePort() << endl;

  m_stat_reconnects++;
  m_ob_hello_received = false;
  m_ob_hb_tx_cnt      = HEARTBEAT_TX_CNT_RESET;
  m_ob_hb_rx_cnt      = HEARTBEAT_RX_CNT_RESET;
  m_heartbeat_timer.setEnable(true);
  m_debug_frame_cnt   = 0;

  if (m_debug)
    cout << m_section << " [DEBUG]: sending hello peer_id=" << m_peer_id
         << " priority=" << m_priority << endl;

  // Always send section name for matching on remote side,
  // PEER_ID is only used locally for MQTT/logging
  sendMsgOnOutbound(MsgTrunkHello(m_section, joinPrefixes(m_local_prefix),
                                   m_priority, m_secret));
}


void TrunkLink::onDisconnected(TcpConnection* con,
                               TcpConnection::DisconnectReason reason)
{
  cout << m_section << ": Outbound disconnected: "
       << TcpConnection::disconnectReasonStr(reason) << endl;

  m_ob_hello_received = false;
  m_ob_hb_tx_cnt      = 0;
  m_ob_hb_rx_cnt      = 0;

  if (m_inbound_con == nullptr)
    m_heartbeat_timer.setEnable(false);
}


void TrunkLink::onFrameReceived(FramedTcpConnection* con,
                                std::vector<uint8_t>& data)
{
  m_stat_bytes_rx  += data.size();
  m_stat_frames_rx += 1;

  const char* buf = reinterpret_cast<const char*>(data.data());
  stringstream ss;
  ss.write(buf, data.size());

  ReflectorMsg header;
  if (!header.unpack(ss))
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to unpack trunk message header" << endl;
    return;
  }

  bool is_inbound = (con == m_inbound_con);
  bool hello_done = is_inbound ? m_ib_hello_received : m_ob_hello_received;

  if (!hello_done &&
      header.type() != MsgTrunkHello::TYPE &&
      header.type() != MsgTrunkHeartbeat::TYPE)
  {
    cerr << "*** WARNING[" << m_section << "]: Ignoring type="
         << header.type() << " before hello" << endl;
    return;
  }

  if (is_inbound) m_ib_hb_rx_cnt = HEARTBEAT_RX_CNT_RESET;
  else            m_ob_hb_rx_cnt = HEARTBEAT_RX_CNT_RESET;

  if (m_debug && header.type() != MsgTrunkHeartbeat::TYPE)
  {
    if ((header.type() == MsgTrunkAudio::TYPE ||
         header.type() == MsgTrunkFlush::TYPE) && m_debug_frame_cnt < 500)
    {
      cout << m_section << " [DEBUG]: rx " << (is_inbound ? "IB" : "OB")
           << " type=" << header.type() << " len=" << data.size() << endl;
      if (++m_debug_frame_cnt == 500)
        cout << m_section << " [DEBUG]: audio log limit reached (500)" << endl;
    }
    else if (header.type() != MsgTrunkAudio::TYPE &&
             header.type() != MsgTrunkFlush::TYPE)
    {
      cout << m_section << " [DEBUG]: rx " << (is_inbound ? "IB" : "OB")
           << " type=" << header.type() << " len=" << data.size() << endl;
    }
  }

  switch (header.type())
  {
    case MsgTrunkHeartbeat::TYPE:   handleMsgTrunkHeartbeat();        break;
    case MsgTrunkHello::TYPE:       handleMsgTrunkHello(ss);          break;
    case MsgTrunkTalkerStart::TYPE: handleMsgTrunkTalkerStart(ss);    break;
    case MsgTrunkTalkerStop::TYPE:  handleMsgTrunkTalkerStop(ss);     break;
    case MsgTrunkAudio::TYPE:       handleMsgTrunkAudio(ss);          break;
    case MsgTrunkFlush::TYPE:       handleMsgTrunkFlush(ss);          break;
    case MsgTrunkNodeList::TYPE:    handleMsgTrunkNodeList(ss);       break;
    default:
      cerr << "*** WARNING[" << m_section << "]: Unknown trunk type="
           << header.type() << endl;
      break;
  }
}


void TrunkLink::handleMsgTrunkHeartbeat(void) { /* rx counter reset in onFrameReceived */ }


void TrunkLink::handleMsgTrunkHello(std::istream& is)
{
  MsgTrunkHello msg;
  if (!msg.unpack(is))
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to unpack MsgTrunkHello" << endl;
    return;
  }
  if (msg.id().empty())
  {
    cerr << "*** ERROR[" << m_section << "]: Peer sent empty trunk ID" << endl;
    m_con.disconnect();
    return;
  }
  if (!msg.verify(m_secret))
  {
    cerr << "*** ERROR[" << m_section << "]: Auth failed for peer '"
         << msg.id() << "' (HMAC mismatch)" << endl;
    m_con.disconnect();
    return;
  }
  m_peer_priority     = msg.priority();
  m_ob_hello_received = true;

  cout << m_section << ": Hello from peer '" << msg.id()
       << "' prefix=" << msg.localPrefix()
       << " priority=" << m_peer_priority << " (OK)" << endl;
}


void TrunkLink::handleMsgTrunkTalkerStart(std::istream& is)
{
  MsgTrunkTalkerStart msg;
  if (!msg.unpack(is))
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to unpack MsgTrunkTalkerStart" << endl;
    return;
  }

  uint32_t tg = msg.tg();
  if (isBlacklisted(tg)) return;
  if (!isOwnedTG(tg) && !m_reflector->isClusterTG(tg)) return;

  // Map incoming peer TG to local TG
  uint32_t local_tg = mapTgIn(tg);
  if (local_tg != tg && m_debug)
    cout << m_section << " [DEBUG]: TG map in " << tg << " -> " << local_tg << endl;

  // Mute check
  if (isCallsignMuted(msg.callsign()))
  {
    if (m_debug)
      cout << m_section << " [DEBUG]: TalkerStart from muted cs=" << msg.callsign() << endl;
    return;
  }

  // Tie-break using local_tg
  ReflectorClient* local_talker = TGHandler::instance()->talkerForTG(local_tg);
  if (local_talker != nullptr)
  {
    if (m_priority <= m_peer_priority)
    {
      cout << m_section << ": TG #" << local_tg << " conflict — local wins" << endl;
      return;
    }
    cout << m_section << ": TG #" << local_tg << " conflict — deferring to peer" << endl;
    m_yielded_tgs.insert(local_tg);
    TGHandler::instance()->setTalkerForTG(local_tg, nullptr);
  }

  m_peer_active_tgs.insert(local_tg);
  m_peer_interested_tgs[local_tg] = std::time(nullptr);
  TGHandler::instance()->setTrunkTalkerForTG(local_tg, msg.callsign());
}


void TrunkLink::handleMsgTrunkTalkerStop(std::istream& is)
{
  MsgTrunkTalkerStop msg;
  if (!msg.unpack(is))
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to unpack MsgTrunkTalkerStop" << endl;
    return;
  }
  uint32_t tg = msg.tg();
  uint32_t local_tg = mapTgIn(tg);
  if (!isOwnedTG(tg) && !m_reflector->isClusterTG(local_tg)) return;

  m_yielded_tgs.erase(local_tg);
  m_peer_active_tgs.erase(local_tg);
  TGHandler::instance()->clearTrunkTalkerForTG(local_tg);
}


void TrunkLink::handleMsgTrunkAudio(std::istream& is)
{
  MsgTrunkAudio msg;
  if (!msg.unpack(is))
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to unpack MsgTrunkAudio" << endl;
    return;
  }
  uint32_t tg = msg.tg();
  uint32_t local_tg = mapTgIn(tg);
  if (isBlacklisted(tg)) return;
  if ((!isOwnedTG(tg) && !m_reflector->isClusterTG(local_tg)) || msg.audio().empty()) return;
  if (m_peer_active_tgs.find(local_tg) == m_peer_active_tgs.end()) return;

  // Check if the talker on this TG is muted
  const std::string& cs = TGHandler::instance()->trunkTalkerForTG(local_tg);
  if (!cs.empty() && isCallsignMuted(cs)) return;

  m_peer_interested_tgs[local_tg] = std::time(nullptr);

  MsgUdpAudio udp_msg(msg.audio());
  m_reflector->broadcastUdpMsg(udp_msg, ReflectorClient::TgFilter(local_tg));
  m_reflector->forwardAudioToSatellitesExcept(nullptr, local_tg, msg.audio());
}


void TrunkLink::handleMsgTrunkFlush(std::istream& is)
{
  MsgTrunkFlush msg;
  if (!msg.unpack(is))
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to unpack MsgTrunkFlush" << endl;
    return;
  }
  uint32_t tg = msg.tg();
  uint32_t local_tg = mapTgIn(tg);
  if (isBlacklisted(tg)) return;
  if (!isOwnedTG(tg) && !m_reflector->isClusterTG(local_tg)) return;

  // Check if muted
  const std::string& cs = TGHandler::instance()->trunkTalkerForTG(local_tg);
  if (!cs.empty() && isCallsignMuted(cs)) return;

  m_reflector->broadcastUdpMsg(MsgUdpFlushSamples(), ReflectorClient::TgFilter(local_tg));
  m_reflector->forwardFlushToSatellitesExcept(nullptr, tg);
}


void TrunkLink::sendMsg(const ReflectorMsg& msg)
{
  if (isOutboundReady())       sendMsgOnOutbound(msg);
  else if (isInboundReady())   sendMsgOnInbound(msg);
  else if (m_debug)
    cerr << m_section << " [DEBUG]: tx dropped type=" << msg.type()
         << " (no active connection)" << endl;
}


void TrunkLink::sendMsgOnOutbound(const ReflectorMsg& msg)
{
  if (!m_con.isConnected()) return;

  ostringstream ss;
  if (!ReflectorMsg(msg.type()).pack(ss) || !msg.pack(ss))
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to pack trunk message "
         "type=" << msg.type() << endl;
    return;
  }

  const std::string buf = ss.str();
  if (buf.empty()) return;

  int written = m_con.write(buf.data(), buf.size());
  if (written < 0)
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to write trunk message "
         "type=" << msg.type() << " written=" << written << endl;
    return;
  }
  if (static_cast<size_t>(written) != buf.size())
  {
    cerr << "*** WARNING[" << m_section << "]: Partial write trunk message "
         "type=" << msg.type() << " written=" << written
         << " expected=" << buf.size() << endl;
  }

  m_stat_bytes_tx += buf.size();
  m_stat_frames_tx++;
  m_ob_hb_tx_cnt = HEARTBEAT_TX_CNT_RESET;
} /* TrunkLink::sendMsgOnOutbound */


void TrunkLink::sendMsgOnInbound(const ReflectorMsg& msg)
{
  if (m_inbound_con == nullptr) return;

  if (!m_inbound_con->isConnected())
  {
    cerr << "*** WARNING[" << m_section << "]: Attempted to send message "
         "type=" << msg.type() << " on disconnected inbound connection" << endl;
    m_inbound_con = nullptr;
    return;
  }

  ostringstream ss;
  if (!ReflectorMsg(msg.type()).pack(ss) || !msg.pack(ss))
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to pack trunk message "
         "type=" << msg.type() << endl;
    return;
  }

  const std::string buf = ss.str();
  if (buf.empty()) return;

  int written = m_inbound_con->write(buf.data(), buf.size());
  if (written < 0)
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to write trunk message "
         "type=" << msg.type() << " written=" << written << endl;
    m_inbound_con = nullptr;
    return;
  }
  if (static_cast<size_t>(written) != buf.size())
  {
    cerr << "*** WARNING[" << m_section << "]: Partial write trunk message "
         "type=" << msg.type() << " written=" << written
         << " expected=" << buf.size() << endl;
  }

  m_stat_bytes_tx += buf.size();
  m_stat_frames_tx++;
  m_ib_hb_tx_cnt = HEARTBEAT_TX_CNT_RESET;
} /* TrunkLink::sendMsgOnInbound */


void TrunkLink::heartbeatTick(Async::Timer* t)
{
  // Outbound
  if (m_con.isConnected() && m_ob_hb_rx_cnt > 0)
  {
    if (--m_ob_hb_tx_cnt == 0) sendMsgOnOutbound(MsgTrunkHeartbeat());
    if (--m_ob_hb_rx_cnt == 0)
    {
      cerr << "*** ERROR[" << m_section << "]: Outbound heartbeat timeout" << endl;
      m_con.disconnect();
    }
    else if (m_debug && m_ob_hb_rx_cnt <= 5)
      cerr << m_section << " [DEBUG]: OB hb countdown: " << m_ob_hb_rx_cnt << endl;
  }

  // Inbound
  if (m_inbound_con != nullptr && m_ib_hb_rx_cnt > 0)
  {
    if (--m_ib_hb_tx_cnt == 0) sendMsgOnInbound(MsgTrunkHeartbeat());
    if (--m_ib_hb_rx_cnt == 0)
    {
      cerr << "*** ERROR[" << m_section << "]: Inbound heartbeat timeout" << endl;
      m_inbound_con->disconnect();
    }
    else if (m_debug && m_ib_hb_rx_cnt <= 5)
      cerr << m_section << " [DEBUG]: IB hb countdown: " << m_ib_hb_rx_cnt << endl;
  }

  // Prune expired peer interest entries
  time_t now = std::time(nullptr);
  for (auto it = m_peer_interested_tgs.begin(); it != m_peer_interested_tgs.end(); )
  {
    if ((now - it->second) >= PEER_INTEREST_TIMEOUT_S)
      it = m_peer_interested_tgs.erase(it);
    else
      ++it;
  }

  if (!m_con.isConnected() && m_inbound_con == nullptr)
    m_heartbeat_timer.setEnable(false);
}


void TrunkLink::clearPeerTalkerState(void)
{
  for (uint32_t tg : m_peer_active_tgs)
    TGHandler::instance()->clearTrunkTalkerForTG(tg);
  m_peer_active_tgs.clear();
  m_yielded_tgs.clear();
  m_peer_interested_tgs.clear();
}


/*
 * This file has not been truncated
 */


void TrunkLink::sendNodeList(const std::vector<MsgTrunkNodeList::NodeEntry>& nodes)
{
  if (!m_ib_hello_received || !m_ob_hello_received) return;
  cout << m_section << ": sending MsgTrunkNodeList ("
       << nodes.size() << " nodes) to peer" << endl;
  sendMsg(MsgTrunkNodeList(nodes));
} /* TrunkLink::sendNodeList */


void TrunkLink::handleMsgTrunkNodeList(std::istream& is)
{
  MsgTrunkNodeList msg;
  if (!msg.unpack(is))
  {
    cerr << "*** ERROR[" << m_section << "]: Failed to unpack MsgTrunkNodeList" << endl;
    return;
  }
  m_peer_nodes = msg.nodes();

  // Write full node list to JSON file — keeps log clean
  std::string jsonfile = "/var/run/svxreflector/nodes_" + m_section + ".json";
  Json::Value root;
  root["section"]   = m_section;
  root["peer_id"]   = m_peer_id;
  root["count"]     = (Json::UInt)m_peer_nodes.size();
  root["timestamp"] = (Json::Int64)time(nullptr);
  Json::Value arr(Json::arrayValue);
  for (const auto& n : m_peer_nodes)
  {
    Json::Value e;
    e["callsign"] = n.callsign;
    e["tg"]       = n.tg;
    if (n.lat != 0.0f || n.lon != 0.0f)
    {
      e["lat"] = n.lat;
      e["lon"] = n.lon;
    }
    if (!n.qth_name.empty())
      e["qth_name"] = n.qth_name;
    arr.append(e);
  }
  root["nodes"] = arr;
  Json::StreamWriterBuilder builder;
  builder["commentStyle"] = "None";
  builder["indentation"]  = "  ";
  std::string payload = Json::writeString(builder, root);
  FILE* f = fopen(jsonfile.c_str(), "w");
  if (f)
  {
    fwrite(payload.c_str(), 1, payload.size(), f);
    fclose(f);
    cout << "NODELIST[" << m_section << "]: received " << m_peer_nodes.size()
         << " nodes from peer '" << m_peer_id << "' -> " << jsonfile << endl;
  }
  else
  {
    // Fallback: dir may not exist yet
    cout << "NODELIST[" << m_section << "]: received " << m_peer_nodes.size()
         << " nodes from peer '" << m_peer_id << "'" << endl;
  }

  m_reflector->onPeerNodeList(this, m_peer_nodes);
} /* TrunkLink::handleMsgTrunkNodeList */


void TrunkLink::reloadConfig(void)
{
  // Hot-reload: BLACKLIST_TGS, ALLOW_TGS, TG_MAP
  // These can be changed without restarting the reflector.
  // Network/auth parameters require a full restart.

  cout << m_section << ": Reloading config..." << endl;

  // Clear existing
  m_blacklist_filter = TgFilter{};
  m_allow_filter = TgFilter{};
  m_tg_map_in.clear();
  m_tg_map_out.clear();

  // BLACKLIST_TGS
  std::string blacklist_str;
  if (m_cfg.getValue(m_section, "BLACKLIST_TGS", blacklist_str) && !blacklist_str.empty())
  {
    m_blacklist_filter = TgFilter::parse(blacklist_str);
    if (!m_blacklist_filter.empty())
      cout << m_section << ": Blacklisted TGs: " << m_blacklist_filter.toString() << endl;
  }

  // ALLOW_TGS
  std::string allow_str;
  if (m_cfg.getValue(m_section, "ALLOW_TGS", allow_str) && !allow_str.empty())
  {
    m_allow_filter = TgFilter::parse(allow_str);
    if (!m_allow_filter.empty())
      cout << m_section << ": Allowed TGs: " << m_allow_filter.toString() << endl;
  }

  // TG_MAP
  std::string tgmap_str;
  if (m_cfg.getValue(m_section, "TG_MAP", tgmap_str))
  {
    std::istringstream ss(tgmap_str);
    std::string pair;
    while (std::getline(ss, pair, ','))
    {
      auto colon = pair.find(':');
      if (colon == std::string::npos) continue;
      try
      {
        uint32_t peer_tg  = std::stoul(pair.substr(0, colon));
        uint32_t local_tg = std::stoul(pair.substr(colon + 1));
        m_tg_map_in[peer_tg]   = local_tg;
        m_tg_map_out[local_tg] = peer_tg;
      }
      catch (...) {}
    }
  }
  if (!m_tg_map_in.empty())
  {
    cout << m_section << ": TG mapping:";
    for (const auto& kv : m_tg_map_in)
      cout << " " << kv.first << "<->" << kv.second;
    cout << endl;
  }

  cout << m_section << ": Config reloaded"
       << (m_blacklist_filter.empty() ? "" : " [blacklist]")
       << (m_allow_filter.empty()     ? "" : " [whitelist]")
       << (m_tg_map_in.empty()     ? "" : " [tg_map]")
       << endl;
} /* TrunkLink::reloadConfig */

