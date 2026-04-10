/**
@file    TrunkLink.h
@brief   Server-to-server trunk link — jayReflector edition
@date    2026-04-06

Based on GeuReflector by IW1GEU.
Extended by DJ1JAY for FM-Funknetz / jayReflector:
  - PEER_ID: explicit peer identifier, independent of section name
  - BLACKLIST_TGS: per-section TG blacklist
  - Mute support via PTY command
  - MQTT trunk status publishing
  - Audio frame statistics
*/

#ifndef TRUNK_LINK_INCLUDED
#define TRUNK_LINK_INCLUDED

#include <set>
#include <map>
#include "TgFilter.h"
#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include <sigc++/sigc++.h>
#include <json/json.h>

#include <AsyncConfig.h>
#include <AsyncTcpPrioClient.h>
#include <AsyncFramedTcpConnection.h>
#include <AsyncTimer.h>

#include "ReflectorMsg.h"

class Reflector;
class MsgUdpAudio;

/**
@brief  Manages a persistent TCP trunk link to a peer SvxReflector

One TrunkLink instance is created per [TRUNK_x] config section.
It maintains two independent TCP connections to the peer:
  - An outbound connection (TcpPrioClient) that we initiate and auto-reconnects
  - An inbound connection accepted from the peer via the trunk server

jayReflector extensions over GeuReflector:
  PEER_ID      = optional explicit peer identifier (default = section name)
  BLACKLIST_TGS = comma-separated TGs never forwarded on this link
  Mute support: mute/unmute a peer callsign via PTY command

Wire protocol is fully compatible with GeuReflector.
*/
class TrunkLink : public sigc::trackable
{
  public:
    TrunkLink(Reflector* reflector, Async::Config& cfg,
              const std::string& section);
    ~TrunkLink(void);

    bool initialize(void);

    bool isSharedTG(uint32_t tg) const;
    bool isBlacklisted(uint32_t tg) const;
    bool isAllowed(uint32_t tg) const;
    // Also expose filters for satellite to read
    const TgFilter& allowFilter(void) const { return m_allow_filter; }
    const TgFilter& blacklistFilter(void) const { return m_blacklist_filter; }

    void setAllPrefixes(const std::vector<std::string>& all_prefixes)
    {
      m_all_prefixes = all_prefixes;
    }

    const std::string& section(void)   const { return m_section; }
    const std::string& peerId(void)    const { return m_peer_id; }
    const std::string& mqttName(void)  const { return m_mqtt_name; }

    // Send our local node list to the peer (called on login/logout/TG change)
    void sendNodeList(const std::vector<MsgTrunkNodeList::NodeEntry>& nodes);

    // Peer node list received from remote reflector
    const std::vector<MsgTrunkNodeList::NodeEntry>& peerNodes(void) const
      { return m_peer_nodes; }

    Json::Value statusJson(void) const;

    const std::string& secret(void) const { return m_secret; }
    const std::vector<std::string>& remotePrefix(void) const
    {
      return m_remote_prefix;
    }

    void acceptInboundConnection(Async::FramedTcpConnection* con,
                                  const MsgTrunkHello& hello);
    void onInboundDisconnected(Async::FramedTcpConnection* con,
        Async::FramedTcpConnection::DisconnectReason reason);

    void onLocalTalkerStart(uint32_t tg, const std::string& callsign);
    void onLocalTalkerStop(uint32_t tg);
    void onLocalAudio(uint32_t tg, const std::vector<uint8_t>& audio);
    void onLocalFlush(uint32_t tg);

    // Mute/unmute a callsign received from this trunk peer
    void muteCallsign(const std::string& callsign);
    void unmuteCallsign(const std::string& callsign);
    void reloadConfig(void);  // hot-reload BLACKLIST_TGS, ALLOW_TGS, TG_MAP
    bool isCallsignMuted(const std::string& callsign) const;

    bool isActive(void) const;

  private:
    static const unsigned HEARTBEAT_TX_CNT_RESET   = 10;
    static const unsigned HEARTBEAT_RX_CNT_RESET   = 15;
    static const time_t   PEER_INTEREST_TIMEOUT_S  = 60; // 1 min (was 10 min)

    using FramedTcpClient =
        Async::TcpPrioClient<Async::FramedTcpConnection>;

    Reflector*          m_reflector;
    Async::Config&      m_cfg;
    std::string         m_section;        // config section name [TRUNK_x]
    std::string         m_peer_id;        // explicit peer ID (PEER_ID= or section)
    std::string         m_mqtt_name;      // MQTT subtopic name (MQTT_NAME= or section)
    std::vector<MsgTrunkNodeList::NodeEntry> m_peer_nodes; // node list from peer
    bool                m_debug = false;
    unsigned            m_debug_frame_cnt = 0;

    std::string              m_peer_host;
    uint16_t                 m_peer_port;
    std::string              m_secret;
    std::vector<std::string> m_local_prefix;
    std::vector<std::string> m_remote_prefix;
    TgFilter                 m_blacklist_filter;  // never forward these TGs
    TgFilter                 m_allow_filter;      // if non-empty: only forward these TGs
    std::map<uint32_t,uint32_t> m_tg_map_in;   // peer TG → local TG
    std::map<uint32_t,uint32_t> m_tg_map_out;  // local TG → peer TG

    uint32_t mapTgIn(uint32_t tg) const   // map incoming peer TG to local TG
    {
      auto it = m_tg_map_in.find(tg);
      return (it != m_tg_map_in.end()) ? it->second : tg;
    }
    uint32_t mapTgOut(uint32_t tg) const  // map outgoing local TG to peer TG
    {
      auto it = m_tg_map_out.find(tg);
      return (it != m_tg_map_out.end()) ? it->second : tg;
    }

    uint32_t            m_priority;
    uint32_t            m_peer_priority = 0;

    FramedTcpClient             m_con;
    Async::FramedTcpConnection* m_inbound_con = nullptr;
    Async::Timer                m_heartbeat_timer;

    std::vector<std::string> m_all_prefixes;
    std::set<uint32_t>       m_yielded_tgs;
    std::set<uint32_t>       m_peer_active_tgs;
    std::map<uint32_t, time_t> m_peer_interested_tgs;

    // Muted callsigns (PTY mute command)
    std::set<std::string>    m_muted_callsigns;

    // Statistics
    uint64_t  m_stat_bytes_rx   = 0;
    uint64_t  m_stat_bytes_tx   = 0;
    uint64_t  m_stat_frames_rx  = 0;
    uint64_t  m_stat_frames_tx  = 0;
    unsigned  m_stat_reconnects = 0;

    // Per-connection state
    bool                m_ob_hello_received = false;
    unsigned            m_ob_hb_tx_cnt = 0;
    unsigned            m_ob_hb_rx_cnt = 0;
    bool                m_ib_hello_received = false;
    unsigned            m_ib_hb_tx_cnt = 0;
    unsigned            m_ib_hb_rx_cnt = 0;

    TrunkLink(const TrunkLink&);
    TrunkLink& operator=(const TrunkLink&);

    bool isOutboundReady(void) const;
    bool isInboundReady(void) const;
    bool isOwnedTG(uint32_t tg) const;
    bool isPeerInterestedTG(uint32_t tg) const;

    void onConnected(void);
    void onDisconnected(Async::TcpConnection* con,
                        Async::TcpConnection::DisconnectReason reason);
    void onFrameReceived(Async::FramedTcpConnection* con,
                         std::vector<uint8_t>& data);

    void handleMsgTrunkHello(std::istream& is);
    void handleMsgTrunkTalkerStart(std::istream& is);
    void handleMsgTrunkTalkerStop(std::istream& is);
    void handleMsgTrunkAudio(std::istream& is);
    void handleMsgTrunkFlush(std::istream& is);
    void handleMsgTrunkHeartbeat(void);
    void handleMsgTrunkNodeList(std::istream& is);

    void sendMsg(const ReflectorMsg& msg);
    void sendMsgOnOutbound(const ReflectorMsg& msg);
    void sendMsgOnInbound(const ReflectorMsg& msg);
    void heartbeatTick(Async::Timer* t);
    void clearPeerTalkerState(void);

}; /* class TrunkLink */


#endif /* TRUNK_LINK_INCLUDED */
