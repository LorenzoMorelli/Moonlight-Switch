//
//  TailscaleManager.cpp
//  Moonlight-Switch
//
#include "TailscaleManager.hpp"

#include <borealis.hpp>
#include <jansson.h>

#include <cstdio>
#include <sys/stat.h>

#include "Settings.hpp"
#include "tsnet/tsnet.h"

#ifdef __SWITCH__
extern "C" int tsnet_shim_nx_init(void);
#endif

static const char* stateNames[] = {
    "tailscale/state_stopped",  "tailscale/state_starting",
    "tailscale/state_login",    "tailscale/state_auth",
    "tailscale/state_running",  "tailscale/state_error",
};

void TailscaleManager::init() {
    m_state_dir = Settings::instance().working_dir() + "/tailscale";
    mkdir(m_state_dir.c_str(), 0700);
    m_settings_path = m_state_dir + "/settings.json";
    // write defaults on first run so the file is there to inspect/edit
    if (FILE* f = fopen(m_settings_path.c_str(), "rb"))
        fclose(f);
    else
        save();
    load();

#ifdef __SWITCH__
    // must be installed before any tailnet-bound socket is created; while
    // the engine is off every socket simply goes to the real stack
    tsnet_shim_nx_init();
#endif

    tsnet_log_set_file((m_state_dir + "/tsnet.log").c_str(), 2 * 1024 * 1024);
    tsnet_log_set_level(TSNET_LOG_INFO);

    m_crash_flag = m_state_dir + "/.starting";
    if (m_enabled && !isLoggedIn()) {
        // no node keys (e.g. after logout): stay off rather than start an
        // interactive registration nobody asked for
        m_enabled = false;
        save();
        brls::Logger::info("Tailscale: enabled but not logged in; staying "
                           "off until the user authenticates.");
    } else if (m_enabled) {
        // Crash-loop guard: the previous start died before reaching RUNNING,
        // so open with Tailscale disabled and let the user retry.
        FILE* f = fopen(m_crash_flag.c_str(), "rb");
        if (f) {
            fclose(f);
            remove(m_crash_flag.c_str());
            m_enabled = false;
            save();
            brls::Logger::error("Tailscale: previous start crashed before "
                                "connecting; auto-start disabled. Re-enable "
                                "from the Tailscale tab to retry.");
        } else {
            start();
        }
    }
}

static bool fileExists(const std::string& path) {
    if (FILE* f = fopen(path.c_str(), "rb")) {
        fclose(f);
        return true;
    }
    return false;
}

bool TailscaleManager::willAutoStart(const std::string& workingDir) {
    std::string dir = workingDir + "/tailscale";
    json_error_t err;
    json_t* root = json_load_file((dir + "/settings.json").c_str(), 0, &err);
    if (!root) return false;
    bool enabled = json_is_true(json_object_get(root, "enabled"));
    json_decref(root);
    return enabled && fileExists(dir + "/node.key") &&
           !fileExists(dir + "/.starting");
}

bool TailscaleManager::isLoggedIn() const {
    std::string p = m_state_dir + "/node.key";
    if (FILE* f = fopen(p.c_str(), "rb")) {
        fclose(f);
        return true;
    }
    return false;
}

void TailscaleManager::load() {
    json_error_t err;
    json_t* root = json_load_file(m_settings_path.c_str(), 0, &err);
    if (!root) return;
    json_t* v = json_object_get(root, "enabled");
    if (json_is_boolean(v)) m_enabled = json_boolean_value(v);
    v = json_object_get(root, "server_url");
    if (json_is_string(v)) m_server_url = json_string_value(v);
    v = json_object_get(root, "hostname");
    if (json_is_string(v)) m_hostname = json_string_value(v);
    json_decref(root);
}

void TailscaleManager::save() {
    json_t* root = json_object();
    json_object_set_new(root, "enabled", json_boolean(m_enabled));
    json_object_set_new(root, "server_url", json_string(m_server_url.c_str()));
    json_object_set_new(root, "hostname", json_string(m_hostname.c_str()));
    json_dump_file(root, m_settings_path.c_str(), JSON_INDENT(2));
    json_decref(root);
}

void TailscaleManager::setEnabled(bool enabled) {
    m_enabled = enabled;
    save();
    if (enabled && !m_running)
        start();
    else if (!enabled && m_running)
        stop();
}

void TailscaleManager::setServerUrl(const std::string& url) {
    m_server_url = url.empty() ? "https://controlplane.tailscale.com" : url;
    save();
}

void TailscaleManager::start(const std::string& authKey) {
    if (m_running) return;

    static std::string authKeyKeep; // must outlive tsnet_start's config read
    authKeyKeep = authKey;

    tsnet_config cfg = {};
    cfg.server_url = m_server_url.c_str();
    cfg.state_dir = m_state_dir.c_str();
    cfg.hostname = m_hostname.c_str();
    cfg.auth_key = authKeyKeep.empty() ? nullptr : authKeyKeep.c_str();
    cfg.log_level = TSNET_LOG_INFO;

    // marshal to the UI thread; skip once shutting down (see shuttingDown())
    tsnet_events ev = {};
    ev.on_state = [](tsnet_state st, const char* detail, void*) {
        (void)st;
        if (TailscaleManager::instance().shuttingDown()) return;
        std::string d = detail ? detail : "";
        brls::sync([d] { TailscaleManager::instance()._stateEvent(d); });
    };
    ev.on_authurl = [](const char* url, void*) {
        if (TailscaleManager::instance().shuttingDown()) return;
        std::string u = url;
        brls::sync([u] {
            auto& self = TailscaleManager::instance();
            if (self.onAuthUrl) self.onAuthUrl(u);
        });
    };
    ev.on_peers = [](void*) {
        if (TailscaleManager::instance().shuttingDown()) return;
        brls::sync([] { TailscaleManager::instance()._peersEvent(); });
    };

    // crash-loop guard, removed in _stateEvent() once RUNNING
    if (!m_crash_flag.empty()) {
        FILE* f = fopen(m_crash_flag.c_str(), "wb");
        if (f) fclose(f);
    }

    int rc = tsnet_start(&cfg, &ev);
    if (rc == TSNET_OK) {
        m_running = true;
        brls::Logger::info("Tailscale: started (server {})", m_server_url);
    } else {
        brls::Logger::error("Tailscale: start failed: {}", tsnet_err_str((tsnet_err)rc));
    }
    authKeyKeep.clear();
}

void TailscaleManager::stop() {
    if (!m_running) return;
    tsnet_stop();
    m_running = false;
    m_tunnelUp = false;
    if (!m_shuttingDown && onStateChanged) onStateChanged();
}

void TailscaleManager::shutdown() {
    m_shuttingDown = true;
    stop();
}

void TailscaleManager::logout() {
    stop();
    for (const char* f : {"machine.key", "node.key", "disco.key",
                          "state.json"}) {
        std::string p = m_state_dir + "/" + f;
        // best-effort scrub before removing
        FILE* fp = fopen(p.c_str(), "r+b");
        if (fp) {
            char zeros[64] = {};
            fwrite(zeros, 1, sizeof(zeros), fp);
            fclose(fp);
        }
        remove(p.c_str());
    }
    // a logout must not silently re-register on the next launch
    m_enabled = false;
    save();
    brls::Logger::info("Tailscale: logged out (keys removed)");
}

std::string TailscaleManager::stateString() {
    using namespace brls::literals;
    tsnet_state st = m_running ? tsnet_get_state() : TSNET_ST_STOPPED;
    std::string s = brls::getStr(stateNames[st]);
    if (!m_state_detail.empty() && st != TSNET_ST_RUNNING)
        s += " (" + m_state_detail + ")";
    if (st == TSNET_ST_RUNNING) {
        char ip[20];
        tsnet_get_self_ip4(ip, sizeof(ip));
        if (ip[0]) s += std::string(" — ") + ip;
    }
    return s;
}

std::string TailscaleManager::selfIp() {
    char ip[20] = "";
    if (m_running) tsnet_get_self_ip4(ip, sizeof(ip));
    return ip;
}

std::vector<TailscalePeer> TailscaleManager::peers() {
    std::vector<TailscalePeer> out;
    if (!m_running) return out;
    tsnet_peer_info raw[32];
    int n = tsnet_get_peers(raw, 32);
    for (int i = 0; i < n; i++) {
        TailscalePeer p;
        p.name = raw[i].name;
        p.ip4 = raw[i].ip4;
        p.online = raw[i].online;
        p.sessionUp = raw[i].session_up;
        p.path = raw[i].path;
        out.push_back(p);
    }
    return out;
}

void TailscaleManager::_stateEvent(const std::string& detail) {
    m_state_detail = detail;
    // registered: disarm the crash guard
    if (m_running && tsnet_get_state() == TSNET_ST_RUNNING) {
        if (!m_crash_flag.empty()) remove(m_crash_flag.c_str());
        // a successful login (e.g. via browser) leaves Tailscale enabled
        if (!m_enabled) {
            m_enabled = true;
            save();
        }
    } else {
        m_tunnelUp = false;
    }
    if (onStateChanged) onStateChanged();
}

void TailscaleManager::_peersEvent() {
    // Peers are reported once the data plane is up, unlike the RUNNING state
    if (m_running && !m_tunnelUp) {
        m_tunnelUp = true;
        m_tunnelUpEvent.fire();
    }
    if (onStateChanged) onStateChanged();
}
